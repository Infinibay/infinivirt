/**
 * NftablesService manages VM firewall rules using nftables.
 * Uses the bridge family for Layer 2 filtering on TAP devices.
 *
 * @example
 * import { NftablesService } from '@network/NftablesService'
 *
 * const nftables = new NftablesService()
 *
 * // Initialize nftables infrastructure
 * await nftables.initialize()
 *
 * // Create firewall chain for VM
 * const chainName = await nftables.createVMChain('vm-abc123', 'vnet-abc12345')
 *
 * // Apply firewall rules
 * const result = await nftables.applyRules(
 *   'vm-abc123',
 *   'vnet-abc12345',
 *   departmentRules,
 *   vmRules
 * )
 *
 * // Later, remove VM firewall
 * await nftables.removeVMChain('vm-abc123')
 */

import { createHash } from 'crypto'
import { CommandExecutor } from '@utils/commandExecutor'
import { Debugger } from '@utils/debug'
import { retryOnBusy, sleep } from '@utils/retry'
import { KeyedMutex } from '@utils/KeyedMutex'
import { FirewallRuleTranslator } from './FirewallRuleTranslator'
import { NftablesPersistence } from './NftablesPersistence'
import {
  FirewallRuleInput,
  FirewallApplyResult,
  FirewallDefaultAction,
  NftablesErrorCode,
  NftablesError,
  NftablesRuleTokens,
  INFINIZATION_TABLE_NAME,
  INFINIZATION_TABLE_FAMILY,
  DEFAULT_CHAIN_PRIORITY,
  generateVMChainName
} from '../types/firewall.types'
import { TAP_NAME_PREFIX } from '../types/network.types'

/** Delay after removing jump rules before flushing chain (ms) */
const POST_JUMP_REMOVAL_DELAY_MS = 500
/** Delay after flushing chain before deletion (ms) */
const POST_FLUSH_DELAY_MS = 500

/** Base chain name for forwarding VM traffic */
const BASE_FORWARD_CHAIN = 'forward'

export interface NftablesServiceConfig {
  /** Whether to persist rules to disk after changes (default: true) */
  enablePersistence?: boolean
  /**
   * Bridge-family conntrack policy (audit L94). The default established/related rule
   * and any user ct-state rule require nf_conntrack_bridge / br_netfilter on the host.
   *   - 'fail' (default): initialize() probes for bridge-conntrack support and THROWS
   *     a single, actionable error naming the missing modules if unsupported, instead
   *     of letting every per-VM applyRules() fail opaquely at start time.
   *   - 'degrade': if the probe fails, log ONE warning and run stateless — the auto
   *     established/related rule is omitted so VMs can still start (best-effort,
   *     less precise filtering). Set this only when you accept stateless filtering.
   */
  bridgeConntrackMode?: 'fail' | 'degrade'
}

export class NftablesService {
  private executor: CommandExecutor
  private debug: Debugger
  /** Cache of rule hashes per VM to detect changes */
  private ruleHashCache: Map<string, string> = new Map()
  /** Persistence handler for disk export/import */
  private persistence: NftablesPersistence
  /** Whether to persist rules to disk after changes */
  private enablePersistence: boolean
  /**
   * Bridge-family conntrack policy (see NftablesServiceConfig.bridgeConntrackMode).
   *
   * STATIC / process-wide (audit MF-5): the host's conntrack capability is a property
   * of the KERNEL, not of any one NftablesService instance. The backend constructs
   * several instances (Infinization-owned, VMLifecycle, HealthMonitor, EventHandler,
   * ...) and only the Infinization-owned one calls initialize(); the instances that
   * actually apply rules on the VM-start path never do. A per-instance mode/support
   * field meant the probe result never reached those instances and the established
   * rule was ALWAYS injected — so on a host without bridge conntrack, even in
   * 'degrade' mode, the VM-start apply still threw and the VM failed to start. Making
   * the mode + support SHARED (mirroring the static chainLock) lets the single
   * memoized probe govern every instance's apply path.
   *
   * Default resolved from INFINIZATION_BRIDGE_CONNTRACK_MODE at class-load time; an
   * explicit `new NftablesService({ bridgeConntrackMode })` overwrites the shared
   * static (so the existing Infinization.ts construction keeps working).
   */
  private static bridgeConntrackMode: 'fail' | 'degrade' =
    process.env.INFINIZATION_BRIDGE_CONNTRACK_MODE === 'degrade' ? 'degrade' : 'fail'
  /**
   * Tri-state result of the one-time bridge-conntrack probe (audit L94 / MF-5).
   * STATIC / process-wide so the result is visible to every instance's apply path,
   * not only the instance that ran the probe:
   *   - null  → not yet probed — treat conntrack as available so a stale read before
   *             the (awaited) probe completes never wrongly omits the ct-state rule.
   *   - true  → probe confirmed nf_conntrack_bridge/br_netfilter support.
   *   - false → probe failed AND mode='degrade' → run stateless (omit ct-state rules).
   */
  private static bridgeConntrackSupported: boolean | null = null
  /**
   * Memoized one-shot probe (audit MF-5). The probe runs at most ONCE per process: the
   * first apply on ANY instance (or initialize()) starts it and stores the promise here;
   * every subsequent call awaits the same promise instead of re-probing the kernel.
   * In 'fail' mode a rejected probe rejects this promise too, so the first apply of any
   * instance surfaces the actionable error (and a later apply re-awaits/re-throws).
   */
  private static conntrackProbe?: Promise<void>
  /**
   * Serializes mutations to a given VM chain, keyed by chain name, so apply/
   * remove/jump-rule operations on the same chain (and the shared forward chain)
   * never interleave. STATIC (process-wide): the backend constructs several
   * NftablesService instances (VMLifecycle, HealthMonitor, EventHandler, ...), and
   * a per-instance lock would not serialize across them — they all mutate the
   * SAME kernel nft table. A module-level lock makes the serialization global.
   */
  private static readonly chainLock = new KeyedMutex()
  private get chainLock (): KeyedMutex {
    return NftablesService.chainLock
  }

  constructor (config: NftablesServiceConfig = {}) {
    this.executor = new CommandExecutor()
    this.debug = new Debugger('nftables')
    this.persistence = new NftablesPersistence()
    this.enablePersistence = config.enablePersistence ?? true
    // An explicit constructor option overwrites the SHARED static mode (audit MF-5):
    // the policy is process-wide, so the last explicit choice wins for every instance.
    // Absent an explicit option, keep the static default resolved from
    // INFINIZATION_BRIDGE_CONNTRACK_MODE at class load.
    if (config.bridgeConntrackMode !== undefined) {
      NftablesService.bridgeConntrackMode = config.bridgeConntrackMode
    }
  }

  // ============================================================================
  // Public Methods
  // ============================================================================

  /**
   * Initializes the nftables infrastructure for VM firewall management.
   * Creates the infinization table and base forward chain if they don't exist.
   *
   * @throws Error if initialization fails (except for already-exists errors)
   */
  async initialize (): Promise<void> {
    this.debug.log('Initializing nftables infrastructure')

    // Create table (bridge family for Layer 2 filtering)
    await this.createTableIfNotExists()

    // One-time host-capability preflight (audit L94): the bridge-family chains we
    // build inject `ct state established,related`, which needs nf_conntrack_bridge /
    // br_netfilter. Probe ONCE here so a missing module surfaces as a single,
    // actionable init-time error (or a degraded-mode warning) — not as an opaque
    // failure on every single VM start. Runs BEFORE the base chain / any VM apply.
    await this.ensureBridgeConntrackSupport()

    // Create base forward chain with hook
    await this.createBaseChainIfNotExists()

    this.debug.log('nftables infrastructure initialized successfully')
  }

  /**
   * Ensures the one-time bridge-conntrack probe has run, memoized PROCESS-WIDE
   * (audit MF-5). The first caller — initialize() OR the first apply on ANY instance —
   * kicks off the probe and stores the promise on the static `conntrackProbe`; every
   * later caller awaits that same promise instead of re-probing the kernel. In 'fail'
   * mode a rejected probe leaves the rejected promise memoized, so a subsequent apply
   * re-awaits and re-throws the same actionable error rather than silently proceeding.
   */
  private async ensureBridgeConntrackSupport (): Promise<void> {
    if (NftablesService.conntrackProbe === undefined) {
      NftablesService.conntrackProbe = this.runBridgeConntrackProbe()
    }
    try {
      await NftablesService.conntrackProbe
    } catch (error) {
      // Do NOT permanently memoize a rejected probe: a transient failure (e.g. a
      // 'Device or resource busy' collision with other host nft tooling at startup)
      // would otherwise poison the process-wide static and brick every later
      // init/apply/cron until a full restart. Clear it so the next caller re-probes
      // the kernel. SUCCESS and degrade-mode resolutions stay memoized (run once).
      NftablesService.conntrackProbe = undefined
      throw error
    }
  }

  /**
   * Probes whether the host supports stateful (conntrack) matching in the BRIDGE
   * family, which the auto established/related rule and any user ct-state rule rely on
   * (audit L94). Best-effort `modprobe br_netfilter nf_conntrack_bridge`, then applies
   * and deletes a throwaway `ct state established` rule in a temporary bridge chain via
   * a single `nft -f -` transaction.
   *
   *   - On success: records support and returns.
   *   - On failure with mode='fail' (default): throws ONE clear NftablesError naming the
   *     missing modules, so the operator fixes the host instead of debugging per-VM
   *     start failures.
   *   - On failure with mode='degrade': logs one warning and records that ct-state rules
   *     must be omitted (stateless degraded mode) so VMs can still start.
   *
   * Runs at most once per process — callers go through the memoizing
   * ensureBridgeConntrackSupport() wrapper above.
   */
  private async runBridgeConntrackProbe (): Promise<void> {
    // Best-effort module load. modprobe may be absent (e.g. modules built-in) — that
    // is fine; the probe below is the real source of truth.
    try {
      await this.executor.execute('modprobe', ['br_netfilter', 'nf_conntrack_bridge'])
      this.debug.log('Loaded bridge conntrack modules (br_netfilter, nf_conntrack_bridge)')
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.debug.log('warn', `modprobe br_netfilter nf_conntrack_bridge failed/unavailable (continuing to probe): ${message}`)
    }

    // Probe: create a throwaway bridge chain, add a `ct state established` rule, then
    // tear it down — all in ONE atomic `nft -f -` transaction. If conntrack-in-bridge
    // is unsupported, the kernel rejects the ct-state rule and the whole transaction
    // rolls back (so the probe leaves no residue).
    const probeChain = 'infz_ctprobe'
    const probeRuleset = [
      `add table ${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME}`,
      `add chain ${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME} ${probeChain}`,
      `add rule ${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME} ${probeChain} ct state established accept`,
      `delete chain ${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME} ${probeChain}`
    ].join('\n') + '\n'

    try {
      // Retry a transient 'Device or resource busy' (a real, codebase-acknowledged
      // condition for nft — see utils/retry) before concluding conntrack is unsupported.
      await retryOnBusy(async () => await this.execFile(probeRuleset))
      NftablesService.bridgeConntrackSupported = true
      this.debug.log('Bridge conntrack probe succeeded — stateful (established/related) filtering available')
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      // Best-effort cleanup of the probe chain in case it survived a partial apply.
      try {
        await this.exec(['delete', 'chain', INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME, probeChain])
      } catch { /* chain already gone (transaction rolled back) — ignore */ }

      const diagnostic =
        'Bridge-family conntrack is unavailable: the kernel rejected a `ct state established` rule in the ' +
        `${INFINIZATION_TABLE_FAMILY} family. This blocks stateful per-VM firewalling. ` +
        'Load the required modules on the host: `modprobe br_netfilter nf_conntrack_bridge` ' +
        '(and ensure they persist across reboots). ' +
        `Underlying nft error: ${message}`

      if (NftablesService.bridgeConntrackMode === 'degrade') {
        NftablesService.bridgeConntrackSupported = false
        this.debug.log('warn', `${diagnostic} — continuing in STATELESS degraded mode (established/related rule omitted; filtering is less precise).`)
        return
      }

      NftablesService.bridgeConntrackSupported = false
      this.debug.log('error', diagnostic)
      throw this.wrapError(new Error(diagnostic), NftablesErrorCode.COMMAND_FAILED, {
        command: 'ct-state preflight',
        args: ['br_netfilter', 'nf_conntrack_bridge']
      })
    }
  }

  /**
   * Creates a firewall chain for a specific VM.
   * The chain will be named using the VM ID and attached to the base forward chain.
   *
   * @param vmId - The VM identifier
   * @param tapDeviceName - The TAP device name for this VM
   * @returns The created chain name
   * @throws Error if chain creation fails
   */
  async createVMChain (vmId: string, tapDeviceName: string): Promise<string> {
    // Serialize chain + forward-jump mutations process-wide (same lock as applyRules)
    // so a concurrent attach/detach/cleanup on the same VM chain cannot interleave
    // with this create's list-then-add jump-rule sequence.
    return this.chainLock.runExclusive(generateVMChainName(vmId), () =>
      this.createVMChainUnlocked(vmId, tapDeviceName))
  }

  private async createVMChainUnlocked (vmId: string, tapDeviceName: string): Promise<string> {
    const chainName = generateVMChainName(vmId)
    this.debug.log(`Creating VM chain: ${chainName} for VM: ${vmId} (TAP: ${tapDeviceName})`)

    try {
      // Check if chain already exists
      const exists = await this.chainExists(chainName)
      if (exists) {
        this.debug.log(`Chain ${chainName} already exists, skipping creation`)
      } else {
        // Create the VM chain (regular chain, no hook)
        await this.exec([
          'add', 'chain',
          INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
          chainName
        ])
        this.debug.log(`VM chain created: ${chainName}`)
      }

      // Add jump rules from base forward chain to VM chain for this TAP device
      // We need rules for both directions (traffic to and from the VM)
      await this.addJumpRules(chainName, tapDeviceName)

      return chainName
    } catch (error) {
      const message = `Failed to create VM chain ${chainName}: ${error instanceof Error ? error.message : String(error)}`
      this.debug.log('error', message)
      throw this.wrapError(error, NftablesErrorCode.COMMAND_FAILED, {
        command: 'add chain',
        args: [chainName]
      })
    }
  }

  /**
   * Applies firewall rules to a VM **atomically and fail-closed**.
   *
   * Merges department rules with VM-specific rules (respecting overridesDept),
   * injects the established/related allow rule, and appends a terminal rule that
   * enforces the department's default posture:
   *   - defaultAction 'drop'   (BLOCK_ALL): traffic not explicitly accepted is dropped.
   *   - defaultAction 'accept' (ALLOW_ALL): traffic not explicitly dropped is accepted.
   *
   * The whole ruleset (flush + every rule + terminal) is applied in a SINGLE
   * `nft -f -` transaction. This guarantees:
   *   - **Atomicity**: there is never a window where the chain is flushed/half-populated
   *     while jump rules are live — the kernel swaps the chain contents in one step.
   *   - **Fail-closed**: if any rule is rejected by nft, the ENTIRE transaction is
   *     rolled back and the chain keeps its PREVIOUS ruleset (we throw). We never
   *     degrade to a flushed/partial chain that falls through to accept.
   *
   * A rule that fails to *translate* in JS is skipped and counted in `failedRules`
   * (not silently dropped). Because the chain ends in a terminal drop under BLOCK_ALL,
   * skipping a rule denies rather than exposes that traffic.
   *
   * @param vmId - The VM identifier
   * @param tapDeviceName - The TAP device name for this VM
   * @param departmentRules - Rules inherited from the department
   * @param vmRules - Rules specific to this VM
   * @param defaultAction - Terminal posture (default 'drop' = fail-closed)
   * @returns Result containing count of applied/failed rules
   */
  async applyRules (
    vmId: string,
    tapDeviceName: string,
    departmentRules: FirewallRuleInput[],
    vmRules: FirewallRuleInput[],
    defaultAction: FirewallDefaultAction = 'drop'
  ): Promise<FirewallApplyResult> {
    // Serialize all mutations to this VM's chain so a department-wide reapply cannot
    // interleave with a per-VM resync (or a concurrent removeVMChain), which would
    // otherwise yield duplicate/missing rules or a half-applied chain.
    return this.chainLock.runExclusive(generateVMChainName(vmId), () =>
      this.applyRulesUnlocked(vmId, tapDeviceName, departmentRules, vmRules, defaultAction))
  }

  private async applyRulesUnlocked (
    vmId: string,
    tapDeviceName: string,
    departmentRules: FirewallRuleInput[],
    vmRules: FirewallRuleInput[],
    defaultAction: FirewallDefaultAction = 'drop'
  ): Promise<FirewallApplyResult> {
    const chainName = generateVMChainName(vmId)
    this.debug.log(`Applying firewall rules to chain ${chainName} for VM ${vmId} (defaultAction=${defaultAction})`)

    const result: FirewallApplyResult = {
      totalRules: 0,
      appliedRules: 0,
      failedRules: 0,
      chainName,
      failures: []
    }

    try {
      // Establish host bridge-conntrack capability BEFORE building/applying any ruleset
      // (audit MF-5). This memoized, process-wide probe runs at most once and is what
      // makes the VM-start path (instances that never call initialize()) honor the
      // operator's mode: in 'fail' mode a missing module throws the actionable error
      // HERE (so the VM fails fast with a clear cause); in 'degrade' mode it sets the
      // shared bridgeConntrackSupported=false so the established rule is omitted below
      // and the atomic apply does not throw on a host without nf_conntrack_bridge.
      await this.ensureBridgeConntrackSupport()

      // Ensure chain + jump rules exist (idempotent). The atomic ruleset below also
      // re-asserts the chain via `add chain`, but createVMChain wires the jump rules
      // from the base forward chain on first creation.
      const exists = await this.chainExists(chainName)
      if (!exists) {
        this.debug.log(`Chain ${chainName} does not exist, creating it`)
        // Call the UNLOCKED body: applyRulesUnlocked already holds this VM's chainLock
        // (KeyedMutex is not re-entrant, so re-locking via createVMChain would deadlock).
        await this.createVMChainUnlocked(vmId, tapDeviceName)
      }

      // Merge rules (VM rules can override department rules)
      const mergedRules = this.mergeRules(departmentRules, vmRules)

      // Inject default rule for established/related traffic so connections initiated
      // by the VM (or accepted via explicit rules) keep working under a terminal drop.
      // Omitted in stateless degraded mode (audit L94) where the host lacks bridge
      // conntrack — injecting a ct-state rule there would make the whole apply throw.
      // Reads the SHARED static support flag (audit MF-5) just resolved by the probe
      // above, so this holds on every instance — not only one that called initialize().
      if (NftablesService.bridgeConntrackSupported !== false) {
        mergedRules.push(this.getDefaultEstablishedRule())
      }

      // Sort by priority (lower number = evaluated first)
      mergedRules.sort((a, b) => a.priority - b.priority)

      result.totalRules = mergedRules.length

      // Translate every rule to an nft rule line. Translation failures are recorded
      // but do not abort the apply (the terminal drop keeps the result fail-closed).
      const { lines, applied, failures } = this.buildRuleLines(mergedRules, tapDeviceName)
      result.failures = failures
      result.failedRules = failures.length

      // Build a single atomic transaction: re-assert chain, flush it, re-add every
      // rule, and append the terminal posture rule last (after the established rule).
      const ruleset = this.buildAtomicRuleset(chainName, lines, defaultAction)

      // Apply atomically. On ANY error the kernel rolls back the whole transaction,
      // so the chain retains its previous rules — fail-closed.
      await this.execFile(ruleset)

      result.appliedRules = applied
      this.debug.log(`Atomically applied ${result.appliedRules}/${result.totalRules} rules to chain ${chainName} (terminal: ${defaultAction})`)

      // Persist rules to disk after successful apply
      await this.persistToDiskIfEnabled()

      return result
    } catch (error) {
      const message = `Failed to apply rules to chain ${chainName} (chain retains previous ruleset): ${error instanceof Error ? error.message : String(error)}`
      this.debug.log('error', message)
      throw this.wrapError(error, NftablesErrorCode.COMMAND_FAILED)
    }
  }

  /**
   * Translates a list of merged rules into nft rule-body strings (one per rule;
   * INOUT expands to two). Records translation failures instead of throwing so a
   * single bad rule cannot abort the whole apply.
   */
  private buildRuleLines (
    mergedRules: FirewallRuleInput[],
    tapDeviceName: string
  ): { lines: string[]; applied: number; failures: Array<{ ruleName: string; error: string }> } {
    const lines: string[] = []
    let applied = 0
    const failures: Array<{ ruleName: string; error: string }> = []

    for (const rule of mergedRules) {
      try {
        if (rule.direction === 'INOUT') {
          // Expand INOUT into concrete IN and OUT rules (translator handles only IN/OUT).
          const inRule = { ...rule, direction: 'IN' as const }
          lines.push(FirewallRuleTranslator.translateToTokens(inRule, tapDeviceName).join(' '))
          const outRule = { ...rule, direction: 'OUT' as const }
          lines.push(FirewallRuleTranslator.translateToTokens(outRule, tapDeviceName).join(' '))
        } else {
          lines.push(FirewallRuleTranslator.translateToTokens(rule, tapDeviceName).join(' '))
        }
        applied++
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error)
        failures.push({ ruleName: rule.name, error: errorMsg })
        this.debug.log('error', `Failed to translate rule ${rule.name}: ${errorMsg}`)
      }
    }

    return { lines, applied, failures }
  }

  /**
   * Builds the atomic `nft -f` ruleset for a VM chain: re-assert the chain (idempotent),
   * flush it, re-add every rule body, and append the terminal posture rule.
   */
  private buildAtomicRuleset (
    chainName: string,
    ruleBodies: string[],
    defaultAction: FirewallDefaultAction
  ): string {
    const prefix = `${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME} ${chainName}`
    const terminal = defaultAction === 'drop' ? 'drop' : 'accept'
    const lines = [
      `add chain ${prefix}`,
      `flush chain ${prefix}`,
      ...ruleBodies.map(body => `add rule ${prefix} ${body}`),
      `add rule ${prefix} ${terminal} comment "infinization-default-${terminal}"`
    ]
    return lines.join('\n') + '\n'
  }

  /**
   * Applies a complete ruleset atomically via `nft -f -` (read from stdin).
   * The whole ruleset is one nftables transaction: all-or-nothing.
   */
  private async execFile (ruleset: string): Promise<string> {
    this.debug.log(`Applying atomic ruleset via 'nft -f -':\n${ruleset}`)
    try {
      return await this.executor.execute('nft', ['-f', '-'], { stdin: ruleset })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.debug.log('error', `nft -f failed (transaction rolled back): ${message}`)
      throw error
    }
  }

  /**
   * Belt-and-suspenders underlay ingress filter for the department overlay
   * (07-networking.md §2, ADR-N4). Installs an ISOLATED `inet` table whose input
   * chain drops VXLAN (UDP/4789) and WireGuard (UDP/<wgPort>) packets from any
   * source that is NOT an enrolled peer, while `policy accept` leaves ALL other
   * traffic (SSH, the API, everything) untouched — so a misconfiguration can never
   * lock the host out. WireGuard is the PRIMARY authentication boundary; this is
   * defense-in-depth for a shared/dedicated underlay.
   *
   * Idempotent: the whole table is atomically replaced each call (add→delete→declare
   * in one `nft -f -` transaction), so the peer set exactly matches `peerHostIps`.
   * Lives in its own table, entirely separate from the bridge-family per-VM firewall,
   * so it cannot disturb VM filtering. Invalid IPs/ports are dropped defensively.
   */
  async ensureUnderlayIngressFilter (peerHostIps: string[], ports: number[]): Promise<void> {
    const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
    const validIp = (ip: string): boolean => {
      const m = IPV4.exec(ip)
      return m !== null && m.slice(1, 5).every(o => Number(o) >= 0 && Number(o) <= 255)
    }
    const ips = [...new Set(peerHostIps.filter(validIp))]
    const portSet = [...new Set(ports.filter(p => Number.isInteger(p) && p > 0 && p < 65536))]
    if (portSet.length === 0) return

    const table = 'inet infinibay_overlay'
    // NO peers → REMOVE the table entirely rather than install a blanket `drop` that
    // would blackhole ALL VXLAN/WireGuard input node-wide (H5). `add`+`delete` in one
    // transaction is a safe idempotent "ensure absent".
    if (ips.length === 0) {
      await this.execFile(`add table ${table}\ndelete table ${table}`)
      return
    }

    const portList = portSet.join(', ')
    // add→delete→re-declare in ONE atomic transaction = idempotent full replace.
    const ruleset = [
      `add table ${table}`,
      `delete table ${table}`,
      `table ${table} {`,
      `  set peers { type ipv4_addr; elements = { ${ips.join(', ')} } }`,
      `  chain underlay_ingress {`,
      '    type filter hook input priority -10; policy accept;',
      `    udp dport { ${portList} } ip saddr @peers accept`,
      `    udp dport { ${portList} } drop`,
      '  }',
      '}'
    ].join('\n')
    await this.execFile(ruleset)
  }

  /**
   * Removes a VM's firewall chain and all its rules.
   * Also removes jump rules from the base forward chain.
   *
   * The removal sequence is carefully ordered with delays to handle busy resources:
   * 1. Remove jump rules from forward chain (stops new traffic from reaching VM chain)
   * 2. Wait for kernel to process rule removal
   * 3. Flush all rules in VM chain
   * 4. Wait for kernel to release chain resources
   * 5. Delete the chain with retries on busy errors
   *
   * @param vmId - The VM identifier
   */
  async removeVMChain (vmId: string): Promise<void> {
    // Resolve the (non-invertible) chain name from the vmId and delegate, then drop
    // the vmId-keyed rule-hash cache entry regardless of the removal outcome.
    await this.removeVMChainByName(generateVMChainName(vmId))
    this.ruleHashCache.delete(vmId)
  }

  /**
   * Removes a VM firewall chain BY CHAIN NAME: detach jump rules, flush, delete.
   *
   * Reconciliation/cleanup paths know only the chain name — the chain name is a
   * SHA-256-derived, non-invertible function of the vmId, so they cannot recover the
   * vmId to call removeVMChain(). Best-effort: logs and returns on missing chains
   * rather than throwing.
   *
   * @param chainName - The nftables chain name (e.g. from listChains())
   */
  async removeVMChainByName (chainName: string): Promise<void> {
    // Same per-chain lock as applyRules — a remove must not interleave with an apply.
    return this.chainLock.runExclusive(chainName, () => this.removeVMChainByNameUnlocked(chainName))
  }

  private async removeVMChainByNameUnlocked (chainName: string): Promise<void> {
    this.debug.log(`Removing VM chain: ${chainName}`)

    try {
      // Step 1: Remove jump rules referencing this chain from the base forward chain
      // This stops new packets from being directed to the VM chain
      await this.removeJumpRules(chainName)

      // Step 1b: Verify jump rules were actually removed
      const verifyOutput = await this.exec([
        '-a', 'list', 'chain',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
        BASE_FORWARD_CHAIN
      ])

      const verifyRegex = new RegExp(`jump\\s+${chainName}`, 'g')
      const remainingJumps = verifyOutput.match(verifyRegex)

      if (remainingJumps && remainingJumps.length > 0) {
        this.debug.log('warn', `Found ${remainingJumps.length} remaining jump rules for ${chainName} after removal attempt`)
        // Try one more time to remove them
        await this.removeJumpRules(chainName)
      }

      // Step 2: Wait for kernel to process jump rule removal
      // This ensures no new packets are being processed by the chain
      await sleep(POST_JUMP_REMOVAL_DELAY_MS)

      // Step 3: Check if chain exists before trying to delete
      const exists = await this.chainExists(chainName)
      if (!exists) {
        this.debug.log(`Chain ${chainName} does not exist, nothing to remove`)
        return
      }

      // Step 4: Flush all rules in the chain first (required before deletion)
      await this.exec([
        'flush', 'chain',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
        chainName
      ])

      // Step 5: Wait for kernel to release chain resources after flush
      await sleep(POST_FLUSH_DELAY_MS)

      // Step 6: Delete the chain with retries on busy errors
      await retryOnBusy(
        async () => {
          await this.exec([
            'delete', 'chain',
            INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
            chainName
          ])
        },
        {
          maxRetries: 5,
          initialDelayMs: 500,
          debugNamespace: 'nftables'
        }
      )

      this.debug.log(`VM chain removed: ${chainName}`)

      // Persist changes to disk after successful removal
      await this.persistToDiskIfEnabled()
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)

      // Handle gracefully if chain doesn't exist
      if (errorMessage.includes('No such file or directory') ||
          errorMessage.includes('does not exist') ||
          errorMessage.includes('No such chain')) {
        this.debug.log(`Chain ${chainName} does not exist, nothing to remove`)
        return
      }

      // Last resort: try to manually flush and delete without retries
      if (errorMessage.includes('Device or resource busy')) {
        this.debug.log('warn', `Attempting manual cleanup for busy chain ${chainName}`)
        try {
          // List all rules in forward chain and manually delete any remaining jumps
          const output = await this.exec([
            '-a', 'list', 'chain',
            INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
            BASE_FORWARD_CHAIN
          ])

          const handleRegex = new RegExp(`jump\\s+${chainName}.*#\\s*handle\\s+(\\d+)`, 'g')
          let match
          while ((match = handleRegex.exec(output)) !== null) {
            const handle = match[1]
            this.debug.log(`Manually removing orphaned jump rule handle ${handle}`)
            await this.exec([
              'delete', 'rule',
              INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
              BASE_FORWARD_CHAIN,
              'handle', handle
            ])
          }

          // Wait and try delete again
          await sleep(1000)
          await this.exec([
            'delete', 'chain',
            INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
            chainName
          ])

          this.debug.log(`Manual cleanup succeeded for chain ${chainName}`)
          return // Success
        } catch (manualError) {
          this.debug.log('error', `Manual cleanup also failed: ${manualError instanceof Error ? manualError.message : String(manualError)}`)
        }
      }

      this.debug.log('error', `Failed to remove chain ${chainName}: ${errorMessage}`)
      // Don't throw on cleanup operations - log and continue
    }
  }

  /**
   * Flushes all rules from a VM's chain without deleting the chain.
   * Useful for re-applying updated rules.
   *
   * @param vmId - The VM identifier
   */
  async flushVMRules (vmId: string): Promise<void> {
    // Same per-chain lock as applyRules/removeVMChain — a flush must not interleave
    // with an apply or a jump-rule mutation on this VM's chain.
    return this.chainLock.runExclusive(generateVMChainName(vmId), () =>
      this.flushVMRulesUnlocked(vmId))
  }

  private async flushVMRulesUnlocked (vmId: string): Promise<void> {
    const chainName = generateVMChainName(vmId)
    this.debug.log(`Flushing rules from chain: ${chainName}`)

    try {
      await this.exec([
        'flush', 'chain',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
        chainName
      ])
      this.debug.log(`Rules flushed from chain: ${chainName}`)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)

      // Handle gracefully if chain doesn't exist
      if (errorMessage.includes('does not exist') ||
          errorMessage.includes('No such chain')) {
        this.debug.log(`Chain ${chainName} does not exist, nothing to flush`)
        return
      }

      this.debug.log('error', `Failed to flush rules from chain ${chainName}: ${errorMessage}`)
      // Don't throw on flush operations - log and continue
    }
  }

  /**
   * Lists all chains in the infinization table.
   * Useful for debugging and health checks.
   *
   * @returns Array of chain names
   */
  async listChains (): Promise<string[]> {
    this.debug.log('Listing chains in infinization table')

    try {
      const output = await this.exec([
        'list', 'chains',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME
      ])

      // Parse output to extract chain names
      // Format: table bridge infinization { chain forward { ... } chain vm_abc { ... } }
      const chainRegex = /chain\s+(\w+)\s*\{/g
      const chains: string[] = []
      let match

      while ((match = chainRegex.exec(output)) !== null) {
        chains.push(match[1])
      }

      this.debug.log(`Found ${chains.length} chains: ${chains.join(', ')}`)
      return chains
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)

      // If table doesn't exist, return empty array
      if (errorMessage.includes('does not exist') ||
          errorMessage.includes('No such table')) {
        this.debug.log('Table does not exist, returning empty chain list')
        return []
      }

      this.debug.log('error', `Failed to list chains: ${errorMessage}`)
      throw this.wrapError(error, NftablesErrorCode.COMMAND_FAILED)
    }
  }

  /**
   * Checks if a chain exists in the infinization table.
   *
   * @param chainName - Chain name to check
   * @returns true if chain exists
   */
  async chainExists (chainName: string): Promise<boolean> {
    this.debug.log(`Checking if chain exists: ${chainName}`)

    // Quiet probe: absence is EXPECTED (boot, and the VM-start path before the chain
    // is created). execProbe never throws, so a real fault returns null here too —
    // identical to the previous catch-returns-false behavior — but is logged at ERROR.
    const output = await this.execProbe([
      'list', 'chain',
      INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
      chainName
    ])
    const exists = output !== null
    this.debug.log(`Chain ${chainName} ${exists ? 'exists' : 'does not exist'}`)
    return exists
  }

  // ============================================================================
  // Persistent Firewall Methods
  // These methods support persistent firewall rules that survive VM stop/start cycles.
  // The chain and rules persist; only jump rules are attached/detached with TAP lifecycle.
  // ============================================================================

  /**
   * Ensures a VM chain exists without adding jump rules.
   * This is idempotent - safe to call multiple times.
   * Used for persistent firewall where chain outlives TAP device.
   *
   * @param vmId - The VM identifier
   * @returns The chain name
   */
  async ensureVMChain (vmId: string): Promise<string> {
    // Serialize against concurrent apply/remove/jump mutations on this VM's chain.
    return this.chainLock.runExclusive(generateVMChainName(vmId), () =>
      this.ensureVMChainUnlocked(vmId))
  }

  private async ensureVMChainUnlocked (vmId: string): Promise<string> {
    const chainName = generateVMChainName(vmId)
    this.debug.log(`Ensuring VM chain exists: ${chainName} for VM: ${vmId}`)

    try {
      const exists = await this.chainExists(chainName)
      if (exists) {
        this.debug.log(`Chain ${chainName} already exists`)
        return chainName
      }

      // Create the VM chain (regular chain, no hook)
      await this.exec([
        'add', 'chain',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
        chainName
      ])
      this.debug.log(`VM chain created: ${chainName}`)

      // FAIL-CLOSED (audit L86): we just recreated an EMPTY chain (no terminal drop).
      // The in-memory rule-hash cache may still hold the hash from before the chain
      // vanished; if we leave it, the next applyRulesIfChanged() sees a cache HIT and
      // skips re-applying, booting the VM with an empty chain that falls through to
      // the base forward `policy accept` — i.e. unrestricted L3. Invalidate the cache
      // here so the next applyRulesIfChanged() is forced to re-write the terminal drop.
      this.ruleHashCache.delete(vmId)
      return chainName
    } catch (error) {
      const message = `Failed to ensure VM chain ${chainName}: ${error instanceof Error ? error.message : String(error)}`
      this.debug.log('error', message)
      throw this.wrapError(error, NftablesErrorCode.COMMAND_FAILED, {
        command: 'add chain',
        args: [chainName]
      })
    }
  }

  /**
   * Attaches jump rules for a TAP device to route traffic to VM chain.
   * Called when VM starts to connect the active TAP device to persistent rules.
   *
   * @param vmId - The VM identifier
   * @param tapDeviceName - The TAP device name to route traffic from/to
   */
  async attachJumpRules (vmId: string, tapDeviceName: string): Promise<void> {
    // Serialize forward-jump mutations for this VM chain (audit L102): without the
    // lock, two concurrent attaches (or an attach racing a detach/cleanup) list the
    // forward chain at the same time and both decide the jump is absent, appending
    // duplicates / deleting the wrong handle.
    return this.chainLock.runExclusive(generateVMChainName(vmId), () =>
      this.attachJumpRulesUnlocked(vmId, tapDeviceName))
  }

  private async attachJumpRulesUnlocked (vmId: string, tapDeviceName: string): Promise<void> {
    const chainName = generateVMChainName(vmId)
    this.debug.log(`Attaching jump rules for VM ${vmId} (chain: ${chainName}, TAP: ${tapDeviceName})`)

    try {
      // addJumpRules is now idempotent (lists the forward chain and skips already-present
      // directional jumps), so no "already exists" swallow is needed here.
      await this.addJumpRules(chainName, tapDeviceName)
      this.debug.log(`Jump rules attached for VM ${vmId}`)
    } catch (error) {
      throw this.wrapError(error, NftablesErrorCode.COMMAND_FAILED, {
        command: 'attach jump rules',
        args: [vmId, tapDeviceName]
      })
    }
  }

  /**
   * Detaches jump rules when VM stops.
   * The chain and firewall rules persist - only the routing from TAP is removed.
   * This allows rules to survive stop/start cycles.
   *
   * @param vmId - The VM identifier
   */
  async detachJumpRules (vmId: string): Promise<void> {
    // Serialize the list-then-delete-by-handle against concurrent attach/cleanup
    // on this VM chain (audit L102).
    return this.chainLock.runExclusive(generateVMChainName(vmId), () =>
      this.detachJumpRulesUnlocked(vmId))
  }

  private async detachJumpRulesUnlocked (vmId: string): Promise<void> {
    const chainName = generateVMChainName(vmId)
    this.debug.log(`Detaching jump rules for VM ${vmId} (chain: ${chainName})`)

    try {
      await this.removeJumpRules(chainName)
      this.debug.log(`Jump rules detached for VM ${vmId} - chain and rules persist`)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      // Log but don't throw - detach is best-effort on stop
      this.debug.log('warn', `Failed to detach jump rules for VM ${vmId}: ${errorMessage}`)
    }
  }

  /**
   * Applies firewall rules only if they have changed since last application.
   * Uses SHA-256 hashing to detect changes, avoiding unnecessary rule flushes.
   * This optimization is important for persistent firewall chains that may be
   * re-applied on VM restart without actual rule changes.
   *
   * @param vmId - The VM identifier
   * @param tapDeviceName - The TAP device name for this VM
   * @param departmentRules - Rules inherited from the department
   * @param vmRules - Rules specific to this VM
   * @returns Object with changed flag and apply result (if changed)
   */
  async applyRulesIfChanged (
    vmId: string,
    tapDeviceName: string,
    departmentRules: FirewallRuleInput[],
    vmRules: FirewallRuleInput[],
    defaultAction: FirewallDefaultAction = 'drop'
  ): Promise<{ changed: boolean; result?: FirewallApplyResult }> {
    // Resolve host bridge-conntrack capability BEFORE hashing (audit MF-5) so the hash
    // reflects whether the established/related rule will actually be folded in. Without
    // this, an instance that never called initialize() would hash WITH the ct-state rule
    // (support still null) while applyRules() — having run the probe — omits it in
    // degraded mode, so the cached hash would never match and we'd re-apply every time.
    // The probe is memoized process-wide, so this is a no-op after the first call.
    await this.ensureBridgeConntrackSupport()

    // Compute hash of the merged rules (including default established/related rule)
    // AND the terminal posture — changing the policy must invalidate the cache.
    // This ensures the hash matches the effective rule set applied by applyRules().
    const mergedRules = this.mergeRules(departmentRules, vmRules)
    // Mirror applyRulesUnlocked: only fold in the established/related rule when bridge
    // conntrack is available, so the cache hash matches the effective applied ruleset
    // (audit L94 degraded mode). Reads the SHARED static flag (audit MF-5).
    if (NftablesService.bridgeConntrackSupported !== false) {
      mergedRules.push(this.getDefaultEstablishedRule())
    }
    const newHash = this.hashRules(mergedRules, defaultAction)
    const cachedHash = this.ruleHashCache.get(vmId)

    if (cachedHash === newHash) {
      // FAIL-CLOSED (audit L86): never trust the in-memory hash over a vanished kernel
      // chain. If the chain was deleted/recreated-empty out from under us (e.g. a
      // restart that recreated an empty chain via ensureVMChain), honoring the cache
      // hit would skip the re-apply and boot the VM WITHOUT its terminal drop. Only
      // honor the hit when the chain genuinely exists in the kernel; otherwise fall
      // through and re-write the full ruleset (terminal drop included).
      const chainName = generateVMChainName(vmId)
      if (await this.chainExists(chainName)) {
        this.debug.log(`Rules unchanged for VM ${vmId} (hash: ${newHash.substring(0, 8)}...), skipping apply`)
        return { changed: false }
      }
      this.debug.log('warn', `Cache hit for VM ${vmId} but chain ${chainName} is missing from the kernel — forcing re-apply (fail-closed)`)
    }

    this.debug.log(`Rules changed for VM ${vmId} (old: ${cachedHash?.substring(0, 8) ?? 'none'}..., new: ${newHash.substring(0, 8)}...), applying`)

    // Apply the rules
    const result = await this.applyRules(vmId, tapDeviceName, departmentRules, vmRules, defaultAction)

    // Update cache only on successful apply
    if (result.failedRules === 0) {
      this.ruleHashCache.set(vmId, newHash)
      this.debug.log(`Rules hash cached for VM ${vmId}`)
    }

    return { changed: true, result }
  }

  /**
   * Clears the rules hash cache for a VM.
   * Call this when removing a VM to free memory.
   *
   * @param vmId - The VM identifier
   */
  clearRulesCache (vmId: string): void {
    this.ruleHashCache.delete(vmId)
    this.debug.log(`Rules cache cleared for VM ${vmId}`)
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Returns the default established/related rule that is automatically injected.
   * This rule ensures connections initiated by the VM (or accepted via explicit rules) continue to work.
   * Priority 9999 means it's evaluated last, after all user-defined rules.
   */
  private getDefaultEstablishedRule (): FirewallRuleInput {
    return {
      id: '__default_established',
      name: 'Allow Established/Related (Auto)',
      action: 'ACCEPT',
      direction: 'INOUT',
      protocol: 'all',
      priority: 9999,
      connectionState: { established: true, related: true },
      overridesDept: false
    }
  }

  /**
   * Computes a SHA-256 hash of the firewall rules plus the terminal posture.
   * Rules are sorted by priority before hashing for consistent results.
   */
  private hashRules (rules: FirewallRuleInput[], defaultAction: FirewallDefaultAction = 'drop'): string {
    // Sort by priority to ensure consistent hash regardless of input order
    const sorted = [...rules].sort((a, b) => a.priority - b.priority)
    const serialized = JSON.stringify({ defaultAction, rules: sorted })
    return createHash('sha256').update(serialized).digest('hex')
  }

  /**
   * Creates the infinization table if it doesn't already exist.
   */
  private async createTableIfNotExists (): Promise<void> {
    // Quiet probe: a missing table is EXPECTED on first boot and must not log at ERROR
    // (the add below creates it). A real probe fault stays at ERROR inside execProbe.
    const existing = await this.execProbe(['list', 'table', INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME])
    if (existing !== null) {
      this.debug.log(`Table ${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME} already exists`)
      return
    }
    // Table doesn't exist, create it. The `add` still goes through exec() and fails
    // loudly on a real error.
    this.debug.log(`Creating table ${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME}`)
    await this.exec([
      'add', 'table',
      INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME
    ])
    this.debug.log(`Table created: ${INFINIZATION_TABLE_FAMILY} ${INFINIZATION_TABLE_NAME}`)
  }

  /**
   * Creates the base forward chain with hook if it doesn't exist.
   */
  private async createBaseChainIfNotExists (): Promise<void> {
    const chainExists = await this.chainExists(BASE_FORWARD_CHAIN)

    if (chainExists) {
      this.debug.log(`Base chain ${BASE_FORWARD_CHAIN} already exists`)
      // Ensure DHCP rules exist even if chain already exists
      await this.addDHCPAllowRules()
      return
    }

    this.debug.log(`Creating base chain ${BASE_FORWARD_CHAIN}`)

    // Create base chain with forward hook.
    //
    // IMPORTANT: the base forward chain keeps `policy accept` ON PURPOSE. This is a
    // bridge-family chain hooked at `forward`, so it sees ALL bridged forwarding on
    // the host — not just infinization-managed TAPs. Setting `policy drop` here would
    // silently break any unrelated bridge on the box. Default-deny is enforced
    // PER-VM instead: applyRules() appends a terminal `drop` to each VM chain
    // (see buildAtomicRuleset), so traffic jumped into a VM chain that isn't
    // explicitly accepted is dropped within that chain. DHCP is allowed here (above
    // the jump rules) so VMs can still obtain a lease under default-deny.
    await this.exec([
      'add', 'chain',
      INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
      BASE_FORWARD_CHAIN,
      '{ type filter hook forward priority ' + DEFAULT_CHAIN_PRIORITY + '; policy accept; }'
    ])

    this.debug.log(`Base chain created: ${BASE_FORWARD_CHAIN}`)

    // Add DHCP allow rules to ensure VMs can obtain IP addresses
    await this.addDHCPAllowRules()
  }

  /**
   * Adds rules to allow DHCP traffic in the bridge firewall.
   * This is critical for VMs to obtain IP addresses from dnsmasq.
   *
   * DHCP uses UDP ports 67 (server) and 68 (client) with broadcast.
   * The br_netfilter kernel module causes bridge traffic to pass through
   * nftables, which can block DHCP if not explicitly allowed.
   */
  private async addDHCPAllowRules (): Promise<void> {
    this.debug.log('Adding DHCP allow rules to forward chain')

    // Interface-name wildcard matching the managed TAP devices (e.g. "vnet-*").
    // Scoping the DHCP accepts to managed interfaces + the exact DHCP flow (audit L98)
    // closes the bypass where a guest, on ANY bridge the host's forward hook sees,
    // could spoof bare udp sport/dport 67/68 and have it accepted ABOVE every per-VM
    // jump — sailing past its terminal drop. We now require BOTH a managed interface
    // AND the correct sport/dport pair for the direction.
    const tapWildcard = `${TAP_NAME_PREFIX}*`

    // Check if DHCP rules already exist by listing the chain (idempotent — these are
    // inserted at base-chain creation AND re-asserted when the chain already exists).
    // Quiet probe: on the cold-boot path the forward chain may not exist yet, which is
    // EXPECTED and must not log at ERROR; null => fall through and (re)insert the rules.
    const chainOutput = await this.execProbe([
      'list', 'chain',
      INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
      BASE_FORWARD_CHAIN
    ])
    // Match on our scoped comment markers so a partial/legacy rule set is replaced
    // rather than left in place.
    if (chainOutput !== null &&
        chainOutput.includes('infinization-dhcp-client-to-server') &&
        chainOutput.includes('infinization-dhcp-server-to-client')) {
      this.debug.log('Scoped DHCP allow rules already exist, skipping')
      return
    }

    try {
      // Rule 1: Allow DHCP client -> server (DHCPDISCOVER, DHCPREQUEST), scoped to a
      // managed TAP as the INPUT interface and the canonical client->server flow
      // (client :68 -> server :67). A guest cannot match this by merely targeting
      // dport 67 from an arbitrary source port.
      await this.exec([
        'insert', 'rule',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
        BASE_FORWARD_CHAIN,
        'iifname', tapWildcard,
        'udp', 'sport', '68', 'udp', 'dport', '67', 'accept',
        'comment', '"infinization-dhcp-client-to-server"'
      ])
      this.debug.log(`Added scoped DHCP client->server rule (iifname ${tapWildcard}, udp sport 68 dport 67)`)

      // Rule 2: Allow DHCP server -> client (DHCPOFFER, DHCPACK), scoped to a managed
      // TAP as the OUTPUT interface and the server->client flow (server :67 -> client :68).
      await this.exec([
        'insert', 'rule',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
        BASE_FORWARD_CHAIN,
        'oifname', tapWildcard,
        'udp', 'sport', '67', 'udp', 'dport', '68', 'accept',
        'comment', '"infinization-dhcp-server-to-client"'
      ])
      this.debug.log(`Added scoped DHCP server->client rule (oifname ${tapWildcard}, udp sport 67 dport 68)`)

      this.debug.log('Scoped DHCP allow rules added successfully')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      // Log but don't throw - DHCP rules are best-effort
      // If they fail, it might be because they already exist or nftables isn't available
      this.debug.log('warn', `Failed to add DHCP allow rules: ${errorMessage}`)
    }
  }

  /**
   * Adds jump rules from the base forward chain to a VM chain.
   * Creates rules for both traffic directions (to and from the VM).
   */
  private async addJumpRules (chainName: string, tapDeviceName: string): Promise<void> {
    this.debug.log(`Adding jump rules for chain ${chainName} (TAP: ${tapDeviceName})`)

    // Jump rule for traffic TO the VM (output interface is TAP)
    // Using tokens directly to avoid issues with quoted strings
    const toVmTokens: NftablesRuleTokens = ['oifname', tapDeviceName, 'jump', chainName]

    // Jump rule for traffic FROM the VM (input interface is TAP)
    const fromVmTokens: NftablesRuleTokens = ['iifname', tapDeviceName, 'jump', chainName]

    // Idempotency guard (audit L90), mirroring DepartmentNatService.hasMasquerade:
    // `nft add rule` does NOT report "File exists" (only add table/chain/element do),
    // so the old catch-and-ignore was dead code and every attach/reconcile appended
    // ANOTHER identical jump, accumulating duplicates in the shared forward chain.
    // Instead list the forward chain ONCE and only add each directional jump that is
    // not already present. Matching is anchored to the exact `<dir> <tap> jump <chain>`
    // token sequence so a tap/chain whose name is a prefix of another cannot collide.
    const existing = await this.listForwardChainText()
    const toVmPresent = this.forwardHasJump(existing, 'oifname', tapDeviceName, chainName)
    const fromVmPresent = this.forwardHasJump(existing, 'iifname', tapDeviceName, chainName)

    // Let real exec errors propagate (the dead `File exists` swallow is removed).
    if (!toVmPresent) {
      await this.addRuleTokens(BASE_FORWARD_CHAIN, toVmTokens)
      this.debug.log(`Added to-VM jump rule (oifname ${tapDeviceName} jump ${chainName})`)
    } else {
      this.debug.log(`To-VM jump rule already present for chain ${chainName}, skipping`)
    }

    if (!fromVmPresent) {
      await this.addRuleTokens(BASE_FORWARD_CHAIN, fromVmTokens)
      this.debug.log(`Added from-VM jump rule (iifname ${tapDeviceName} jump ${chainName})`)
    } else {
      this.debug.log(`From-VM jump rule already present for chain ${chainName}, skipping`)
    }

    this.debug.log(`Jump rules ensured for chain ${chainName}`)
  }

  /**
   * Lists the base forward chain ruleset text (best-effort). Returns '' if the chain
   * cannot be listed (e.g. not yet created) so the caller proceeds to add rules.
   */
  private async listForwardChainText (): Promise<string> {
    // Quiet probe: absence (chain not yet created) is EXPECTED and yields '' exactly as
    // before; a real fault is logged at ERROR inside execProbe and still yields ''.
    return (await this.execProbe([
      'list', 'chain',
      INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
      BASE_FORWARD_CHAIN
    ])) ?? ''
  }

  /**
   * Returns true if the forward-chain text already contains the exact directional
   * jump `<dir> <tap> jump <chain>`. Anchored on the full token sequence (with word
   * boundaries) so a prefix-collision (vnet-abc vs vnet-abc1, or vm_abc vs vm_abc1)
   * does not yield a false positive that would skip installing the real jump.
   */
  private forwardHasJump (
    forwardText: string,
    direction: 'oifname' | 'iifname',
    tapDeviceName: string,
    chainName: string
  ): boolean {
    const esc = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const re = new RegExp(`${direction}\\s+"?${esc(tapDeviceName)}"?\\s+jump\\s+${esc(chainName)}\\b`)
    return re.test(forwardText)
  }

  /**
   * Removes jump rules referencing a VM chain from the base forward chain.
   */
  private async removeJumpRules (chainName: string): Promise<void> {
    this.debug.log(`Removing jump rules for chain ${chainName}`)

    try {
      // Get current rules in the forward chain
      const output = await this.exec([
        '-a', 'list', 'chain',
        INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
        BASE_FORWARD_CHAIN
      ])

      // Log forward chain output for debugging
      this.debug.log(`Forward chain output:\n${output}`)

      // Find and delete rules that jump to this chain
      // Format: ... jump vm_abc123 # handle 42 (handle is at end of line in nft -a output)
      const handleRegex = new RegExp(`jump\\s+${chainName}.*#\\s*handle\\s+(\\d+)`, 'g')
      let match
      const matches: string[] = []

      while ((match = handleRegex.exec(output)) !== null) {
        const handle = match[1]
        matches.push(`handle ${handle}`)
        this.debug.log(`Removing jump rule with handle ${handle}`)

        await this.exec([
          'delete', 'rule',
          INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
          BASE_FORWARD_CHAIN,
          'handle', handle
        ])
      }

      this.debug.log(`Found ${matches.length} jump rules to remove: ${matches.join(', ')}`)

      if (matches.length === 0) {
        this.debug.log('warn', `No jump rules found for chain ${chainName} - may already be removed or regex failed`)
      }

      this.debug.log(`Jump rules removed for chain ${chainName}`)
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error)
      // Log but don't throw - cleanup should be best-effort
      this.debug.log('error', `Failed to remove jump rules for ${chainName}: ${errorMessage}`)
    }
  }

  /**
   * Adds a single rule to a chain using token array.
   * This method accepts an array of tokens that are spread directly into the
   * nft command, avoiding issues with space-splitting quoted values.
   *
   * @param chainName - The chain to add the rule to
   * @param tokens - Array of rule tokens (e.g., ['oifname', 'vnet-abc', 'accept'])
   */
  private async addRuleTokens (chainName: string, tokens: NftablesRuleTokens): Promise<void> {
    await this.exec([
      'add', 'rule',
      INFINIZATION_TABLE_FAMILY, INFINIZATION_TABLE_NAME,
      chainName,
      ...tokens
    ])
  }

  /**
   * Merges department rules with VM rules.
   * VM rules with overridesDept=true will exclude conflicting department rules.
   *
   * IMPORTANT: Rule Priority Ordering
   * ---------------------------------
   * Rules are sorted by their `priority` field (ascending order, where lower number = higher priority).
   * Since nftables evaluates rules in the order they are added to a chain, we rely on append order
   * to enforce priority. Rules are applied sequentially in `applyRules()` after sorting.
   *
   * This means:
   * - Rules added first (lower priority number) are evaluated first by nftables
   * - The first matching rule determines the action for the packet
   * - No other part of the system should write rules to these VM chains to avoid unexpected reordering
   *
   * For stronger guarantees in future iterations, consider using explicit insert semantics
   * (e.g., `nft insert rule` with position handles or index-based insertion).
   *
   * @param departmentRules - Rules from department
   * @param vmRules - Rules specific to VM
   * @returns Merged and sorted rules (by priority ascending)
   */
  private mergeRules (
    departmentRules: FirewallRuleInput[],
    vmRules: FirewallRuleInput[]
  ): FirewallRuleInput[] {
    // Find VM rules that override department rules
    const overridingRules = vmRules.filter(r => r.overridesDept)

    // Filter out department rules that are overridden. A department rule is
    // overridden only by a VM rule (overridesDept=true) that targets the SAME
    // traffic — full tuple: protocol + direction + port ranges + IPs. The old
    // check matched on (direction, protocol) alone, so a VM override for a single
    // port (e.g. tcp/443 IN) silently suppressed EVERY department tcp/IN rule
    // (including, say, "block tcp/23 telnet"), defeating department policy.
    const filteredDeptRules = departmentRules.filter(deptRule => {
      const overriddenBy = overridingRules.find(vmRule => this.rulesTargetSameTraffic(vmRule, deptRule))
      if (overriddenBy) {
        this.debug.log(`Department rule "${deptRule.name}" overridden by VM rule "${overriddenBy.name}" (same traffic)`)
        return false
      }
      return true
    })

    // Combine and sort by priority (lower number = higher priority in evaluation order)
    // This sorting is critical: rules with lower priority numbers are added to the chain first
    // and will be evaluated first by nftables
    const merged = [...filteredDeptRules, ...vmRules]
    merged.sort((a, b) => a.priority - b.priority)

    this.debug.log(
      `Merged ${departmentRules.length} dept rules + ${vmRules.length} VM rules = ${merged.length} total (sorted by priority)`
    )

    return merged
  }

  /**
   * Returns true if two rules target the same traffic flow (protocol + direction +
   * source/destination port ranges + source/destination IPs). INOUT matches both
   * IN and OUT. This MUST stay consistent with the backend's conflict detection so
   * an override suppresses exactly the department rule(s) it actually conflicts with.
   */
  private rulesTargetSameTraffic (a: FirewallRuleInput, b: FirewallRuleInput): boolean {
    const protocolMatch = (a.protocol || 'all').toLowerCase() === (b.protocol || 'all').toLowerCase()
    const directionMatch = a.direction === b.direction || a.direction === 'INOUT' || b.direction === 'INOUT'
    const portMatch =
      (a.srcPortStart ?? null) === (b.srcPortStart ?? null) &&
      (a.srcPortEnd ?? null) === (b.srcPortEnd ?? null) &&
      (a.dstPortStart ?? null) === (b.dstPortStart ?? null) &&
      (a.dstPortEnd ?? null) === (b.dstPortEnd ?? null)
    const ipMatch =
      (a.srcIpAddr ?? null) === (b.srcIpAddr ?? null) &&
      (a.dstIpAddr ?? null) === (b.dstIpAddr ?? null)
    return protocolMatch && directionMatch && portMatch && ipMatch
  }


  /**
   * Executes an nftables command using CommandExecutor.
   * Wraps the command with debug logging and error handling.
   */
  private async exec (args: string[]): Promise<string> {
    this.debug.log(`Executing: nft ${args.join(' ')}`)

    try {
      const result = await this.executor.execute('nft', args)
      return result
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.debug.log('error', `nft command failed: ${message}`)
      throw error
    }
  }

  /**
   * True when an executor failure is the benign "table/chain does not exist yet"
   * negative of an EXISTENCE probe: nft exits non-zero and writes "No such file or
   * directory" to stderr. This is the ONLY nft failure treated as expected absence;
   * permission denied, syntax errors, 'Device or resource busy' and timeouts are REAL
   * faults that must stay at ERROR. Classifies on the structured stderr of
   * CommandExecutionError, falling back to the message (covers non-CommandExecutionError
   * throws and the bounded stderr tail the executor embeds in the message). English
   * phrasing is guaranteed because CommandExecutor forces LC_ALL=C/LANG=C, and nft emits
   * "No such file or directory" at the START of stderr (before the 8 KB message tail),
   * so truncation cannot hide it. If a future nft reworded this, the phrase would simply
   * not match and the fault would be reported at ERROR (fail-loud), never silenced.
   */
  private isMissingObjectError (error: unknown): boolean {
    const stderr = typeof (error as { stderr?: unknown })?.stderr === 'string'
      ? (error as { stderr: string }).stderr
      : ''
    const message = error instanceof Error ? error.message : String(error)
    return /No such file or directory/i.test(stderr) ||
      /No such file or directory/i.test(message)
  }

  /**
   * Runs an nft EXISTENCE probe (`list table` / `list chain`) WITHOUT the ERROR-level
   * noise exec() emits on non-zero exit. A missing object is EXPECTED on boot (the
   * table/chain is created lazily right after this probe), so it is logged at DEBUG and
   * reported as absent (null). `expectNonZeroExit` also demotes the executor's own
   * non-zero-exit log to debug, so an expected absence produces ZERO ERROR lines.
   *
   * A genuinely real failure (permission denied, syntax error, resource busy, timeout)
   * is logged at ERROR — never hidden — and still reported as absent to preserve the
   * existing best-effort control flow of the call sites (which already handle a missing
   * object and fail loudly on the subsequent add/insert if the fault persists).
   *
   * @returns command stdout when the object exists, or null when it is absent.
   */
  private async execProbe (args: string[]): Promise<string | null> {
    this.debug.log(`Probing: nft ${args.join(' ')}`)
    try {
      return await this.executor.execute('nft', args, { expectNonZeroExit: true })
    } catch (error) {
      if (this.isMissingObjectError(error)) {
        this.debug.log(`Probe negative — object absent: nft ${args.join(' ')}`)
        return null
      }
      const message = error instanceof Error ? error.message : String(error)
      this.debug.log('error', `nft existence probe failed: nft ${args.join(' ')}: ${message}`)
      return null
    }
  }

  /**
   * Wraps an error in a structured NftablesError.
   */
  private wrapError (
    error: unknown,
    code: NftablesErrorCode,
    context?: { command?: string; args?: string[] }
  ): NftablesError {
    const originalMessage = error instanceof Error ? error.message : String(error)
    const nftError = new Error(originalMessage) as NftablesError
    nftError.code = code
    nftError.context = context

    return nftError
  }

  /**
   * Persists the current nftables ruleset to disk if persistence is enabled.
   * Called after rule changes to ensure rules survive reboots.
   * Errors are logged but not thrown to avoid affecting rule application.
   */
  private async persistToDiskIfEnabled (): Promise<void> {
    if (!this.enablePersistence) {
      return
    }

    try {
      const result = await this.persistence.exportToDisk()
      if (result.success) {
        this.debug.log(`Rules persisted to ${result.filePath}`)
      } else {
        this.debug.log('warn', `Failed to persist rules: ${result.error}`)
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error)
      this.debug.log('warn', `Failed to persist rules to disk: ${errorMsg}`)
      // Don't throw - persistence failure shouldn't affect rule application
    }
  }

  // ============================================================================
  // Persistence Public Methods
  // ============================================================================

  /**
   * Gets the persistence handler for direct access to persistence operations.
   * Useful for system startup/shutdown operations.
   *
   * @returns The NftablesPersistence instance
   */
  getPersistence (): NftablesPersistence {
    return this.persistence
  }

  /**
   * Manually triggers a persistence export.
   * Useful when external operations modify rules outside of this service.
   *
   * @returns Result indicating success/failure
   */
  async forcePersist (): Promise<{ success: boolean; error?: string }> {
    try {
      const result = await this.persistence.exportToDisk()
      return { success: result.success, error: result.error }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error)
      return { success: false, error: errorMsg }
    }
  }
}
