import { CommandExecutor } from '@utils/commandExecutor'
import { Debugger } from '@utils/debug'
import { KeyedMutex } from '../utils/KeyedMutex'
import { BridgeManager } from './BridgeManager'
import { TAP_NAME_PREFIX } from '../types/network.types'
import {
  OVERLAY_VXLAN_PREFIX,
  OVERLAY_WG_INTERFACE,
  VXLAN_DSTPORT,
  type OverlayPeer,
  type OverlaySelfIdentity,
  type OverlaySegmentSpec
} from '../types/overlay.types'

/** Department bridge name prefix (must match backend DepartmentNetworkService). */
const BRIDGE_PREFIX = 'infinibr-'
/** Linux interface names: max 15 chars, safe charset (no whitespace/shell metachars). */
const IFNAME_RE = /^[A-Za-z0-9_.-]{1,15}$/
/** Bare IPv4 address (octets 0-255 checked separately). */
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
/** IPv4 with CIDR suffix, e.g. "10.10.100.1/24". */
const IPV4_CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/
/** VXLAN VNI valid range (24-bit, excluding 0). */
const VNI_MIN = 1
const VNI_MAX = 16_777_215
/** Global mutex keys for node-wide resources (the single WG iface + the ingress table). */
const WG_LOCK_KEY = '__infiwg__'
const INGRESS_LOCK_KEY = '__ingress__'

/**
 * Minimal surface OverlayManager needs from NftablesService to install the optional
 * underlay ingress filter — kept as a local interface so OverlayManager takes no
 * hard dependency on the firewall class.
 */
export interface UnderlayIngressFilter {
  ensureUnderlayIngressFilter (peerHostIps: string[], ports: number[]): Promise<void>
}

/**
 * OverlayManager realizes a department's node-spanning L2 segment on THIS host
 * (07-networking.md §1). It is a no-DB, idempotent realizer driven entirely by
 * master-pushed arguments: it ensures the department bridge exists, brings up the
 * single node-global WireGuard mesh `infiwg`, creates the per-department VXLAN
 * netdev `infivx-<bridgeSuffix>` (VNI = Department.vni) enslaved to that bridge, and
 * installs head-end-replication FDB entries so BUM frames flood to every peer VTEP.
 *
 * The VXLAN device name is derived from the department's UNIQUE `bridgeName` suffix
 * (which the master already de-collides), NOT from the raw department id — two
 * departments whose ids share a 6-char prefix must never share a netdev.
 *
 * Naming is a load-bearing guardrail: overlay netdevs use the `infivx-`/`infiwg`
 * prefixes, never `vnet-`, so infinization's TAP sweep and the vnet-scoped DHCP
 * rules never touch them.
 */
export class OverlayManager {
  private readonly executor: CommandExecutor
  private readonly bridge: BridgeManager
  private readonly debug: Debugger
  /** Serialize per-department realize/teardown. */
  private readonly lock = new KeyedMutex()
  /** Serialize node-global resources (infiwg + the ingress table) independently of
   *  the per-department lock so two departments cannot race creating them. */
  private readonly globalLock = new KeyedMutex()
  /** Per-department peer underlay IPs, for computing the ingress filter UNION across
   *  every department realized on this node (the ingress table is node-global). */
  private readonly deptPeerHostIps = new Map<string, string[]>()

  constructor (
    /** This node's overlay identity. Undefined ⇒ host is not overlay-capable and
     *  ensureSegment/setPeers throw rather than realize a half-built segment. */
    private readonly self?: OverlaySelfIdentity,
    bridge?: BridgeManager,
    executor?: CommandExecutor,
    /** Optional firewall for the belt-and-suspenders underlay ingress filter
     *  (07-networking.md §2). Applied only when INFINIZATION_OVERLAY_INGRESS_FILTER=1. */
    private readonly ingressFilter?: UnderlayIngressFilter
  ) {
    this.executor = executor ?? new CommandExecutor()
    this.bridge = bridge ?? new BridgeManager()
    this.debug = new Debugger('overlay')
  }

  /** True when this host was given an overlay identity (vtepIp + WG key + port). */
  get isConfigured (): boolean {
    return this.self !== undefined
  }

  /** Per-department VXLAN netdev name derived from the UNIQUE bridge suffix:
   *  `infinibr-ab12cd` → `infivx-ab12cd`. Falls back to the whole name if the prefix
   *  is unexpected (still deterministic + unique per bridge). */
  private vxlanDevForBridge (bridgeName: string): string {
    const suffix = bridgeName.startsWith(BRIDGE_PREFIX) ? bridgeName.slice(BRIDGE_PREFIX.length) : bridgeName
    return `${OVERLAY_VXLAN_PREFIX}${suffix}`
  }

  private assertValidName (name: string, label: string): void {
    if (!IFNAME_RE.test(name)) {
      throw new Error(`Invalid ${label} "${name}" (must match ${IFNAME_RE})`)
    }
  }

  private assertValidIPv4 (ip: string, label: string): void {
    const m = IPV4_RE.exec(ip)
    if (!m || !m.slice(1, 5).every((o) => Number(o) >= 0 && Number(o) <= 255)) {
      throw new Error(`Invalid ${label} "${ip}"`)
    }
  }

  private assertValidCidr (cidr: string, label: string): void {
    const m = IPV4_CIDR_RE.exec(cidr)
    const ok = m &&
      m.slice(1, 5).every((o) => Number(o) >= 0 && Number(o) <= 255) &&
      Number(m[5]) >= 0 && Number(m[5]) <= 32
    if (!ok) throw new Error(`Invalid ${label} "${cidr}"`)
  }

  private requireSelf (): OverlaySelfIdentity {
    if (!this.self) {
      throw new Error(
        'Overlay is not configured on this host (no vtepIp / WireGuard key). ' +
        'Pass InfinizationConfig.overlay on a compute node before realizing a segment.'
      )
    }
    return this.self
  }

  /** `ip link show <dev>` existence probe (non-zero exit ⇒ absent, expected). */
  private async deviceExists (dev: string): Promise<boolean> {
    try {
      await this.executor.execute('ip', ['link', 'show', dev], { expectNonZeroExit: true })
      return true
    } catch {
      return false
    }
  }

  /**
   * Idempotently realize a department's L2 segment on this node:
   * bridge → WireGuard mesh → peers/FDB → VXLAN netdev → (gateway IP if owner, else
   * actively remove a stale gateway IP). Safe to call repeatedly; a second call with
   * the same spec issues no destructive commands. Throws if this host has no overlay
   * identity or on a naming violation.
   */
  async ensureSegment (spec: OverlaySegmentSpec): Promise<void> {
    const self = this.requireSelf()
    this.assertValidName(spec.bridgeName, 'bridge name')
    if (spec.bridgeName.startsWith(TAP_NAME_PREFIX)) {
      throw new Error(`Refusing overlay bridge named like a TAP ("${spec.bridgeName}") — vnet-* is reserved`)
    }
    if (!Number.isInteger(spec.vni) || spec.vni < VNI_MIN || spec.vni > VNI_MAX) {
      throw new Error(`Invalid VNI ${spec.vni} (must be an integer in ${VNI_MIN}..${VNI_MAX})`)
    }
    if (!Number.isInteger(spec.mtu) || spec.mtu < 576 || spec.mtu > 9000) {
      throw new Error(`Invalid overlay MTU ${spec.mtu}`)
    }
    if (spec.gatewayCidr) this.assertValidCidr(spec.gatewayCidr, 'gateway CIDR')
    const dev = this.vxlanDevForBridge(spec.bridgeName)
    this.assertValidName(dev, 'vxlan device name')

    return this.lock.runExclusive(spec.deptId, async () => {
      this.debug.log(`ensureSegment dept=${spec.deptId} vni=${spec.vni} bridge=${spec.bridgeName} dev=${dev} peers=${spec.peers.length} gatewayOwner=${spec.isGatewayOwner}`)

      // 1. Department bridge — create locally if this node never had it (the core of
      //    the cross-node bug: the bridge only ever existed on the master).
      if (!(await this.bridge.exists(spec.bridgeName))) {
        await this.bridge.create(spec.bridgeName)
      }
      await this.setMtu(spec.bridgeName, spec.mtu)

      // 2. Node-global WireGuard mesh (idempotent, serialized node-wide).
      await this.ensureWgInterface(self)

      // 3. VXLAN device (with VNI/VTEP drift reconciliation) enslaved to the bridge.
      await this.ensureVxlanDevice(dev, spec.vni, spec.mtu, self.vtepIp)
      await this.bridge.addInterface(spec.bridgeName, dev) // idempotent (`ip link set … master …`)

      // 4. Peers: WireGuard peer set + head-end FDB + (optional) ingress filter.
      await this.applyPeers(spec.deptId, dev, spec.peers)

      // 5. Gateway IP — SYMMETRIC (ADR-N2 single owner). The owner holds the .1; a
      //    non-owner must NOT keep a stale .1 from a prior ownership (dual-gateway
      //    ARP conflict + DHCP/NAT blackhole), so actively remove it when told the
      //    CIDR but not to own it.
      if (spec.gatewayCidr) {
        if (spec.isGatewayOwner) {
          await this.bridge.assignIP(spec.bridgeName, spec.gatewayCidr)
        } else {
          await this.removeGatewayIp(spec.bridgeName, spec.gatewayCidr)
        }
      }
    })
  }

  /**
   * Update the mesh for a department (membership fan-out): refresh WireGuard peers
   * and reconcile the FDB. The bridge name is required to resolve the department's
   * VXLAN device deterministically. No-op for the FDB if the device is not yet
   * realized on this node (ensureSegment applies peers when it creates it).
   */
  async setPeers (deptId: string, bridgeName: string, peers: OverlayPeer[]): Promise<void> {
    const self = this.requireSelf()
    this.assertValidName(bridgeName, 'bridge name')
    const dev = this.vxlanDevForBridge(bridgeName)
    return this.lock.runExclusive(deptId, async () => {
      await this.ensureWgInterface(self)
      await this.applyPeers(deptId, dev, peers)
    })
  }

  /**
   * Tear down a department's overlay presence on this node when it hosts 0 VMs of
   * the department. Removes the per-department VXLAN netdev (which also drops its FDB
   * and detaches it from the bridge) and this department's contribution to the
   * ingress-filter peer union. The shared bridge and the node-global `infiwg` peers
   * are intentionally left alone (bridge teardown is the backend's job; WG peers are
   * shared across departments). Idempotent.
   */
  async destroySegment (deptId: string, bridgeName: string): Promise<void> {
    this.assertValidName(bridgeName, 'bridge name')
    const dev = this.vxlanDevForBridge(bridgeName)
    await this.lock.runExclusive(deptId, async () => {
      if (await this.deviceExists(dev)) {
        this.debug.log(`destroySegment dept=${deptId}: removing ${dev}`)
        await this.executor.execute('ip', ['link', 'del', dev])
      } else {
        this.debug.log(`destroySegment dept=${deptId}: ${dev} already absent`)
      }
    })
    // Drop this dept from the ingress union and recompute (node-global lock).
    await this.refreshIngressUnion(deptId, undefined)
  }

  // ---------------------------------------------------------------------------
  // internals
  // ---------------------------------------------------------------------------

  private async setMtu (dev: string, mtu: number): Promise<void> {
    await this.executor.execute('ip', ['link', 'set', dev, 'mtu', String(mtu)])
  }

  /** Remove an overlay gateway CIDR from a bridge, tolerating "does not exist". */
  private async removeGatewayIp (bridgeName: string, cidr: string): Promise<void> {
    try {
      await this.executor.execute('ip', ['addr', 'del', cidr, 'dev', bridgeName], { expectNonZeroExit: true })
      this.debug.log(`Removed stale gateway ${cidr} from ${bridgeName} (this node is not the gateway owner)`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      if (!/Cannot assign|does not exist|No such|Cannot find/i.test(msg)) throw err
    }
  }

  /**
   * Bring up the single node-global WireGuard interface `infiwg` and pin its
   * identity: private key (read from a 0600 file so it never appears in argv/logs),
   * listen port, and the node's VTEP address. Idempotent and serialized node-wide so
   * two concurrent per-department realizes cannot both `ip link add infiwg`.
   */
  private async ensureWgInterface (self: OverlaySelfIdentity): Promise<void> {
    this.assertValidIPv4(self.vtepIp, 'vtepIp')
    if (!Number.isInteger(self.wgListenPort) || self.wgListenPort < 1 || self.wgListenPort > 65535) {
      throw new Error(`Invalid WireGuard listen port ${self.wgListenPort}`)
    }

    await this.globalLock.runExclusive(WG_LOCK_KEY, async () => {
      if (!(await this.deviceExists(OVERLAY_WG_INTERFACE))) {
        // Tolerate a concurrent creator (another instance/process) — "File exists".
        try {
          await this.executor.execute('ip', ['link', 'add', OVERLAY_WG_INTERFACE, 'type', 'wireguard'], { expectNonZeroExit: true })
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          if (!/File exists|already exists/i.test(msg)) throw err
        }
      }
      // `private-key <file>` reads the key from disk — the secret never enters argv.
      await this.executor.execute('wg', [
        'set', OVERLAY_WG_INTERFACE,
        'listen-port', String(self.wgListenPort),
        'private-key', self.wgPrivateKeyPath
      ])
      // The VTEP address lives ON the WireGuard interface (§1: VXLAN local/FDB dst are
      // the WG-interface addresses). Tolerate re-adding an existing address.
      try {
        await this.executor.execute('ip', ['addr', 'add', `${self.vtepIp}/32`, 'dev', OVERLAY_WG_INTERFACE], { expectNonZeroExit: true })
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        if (!/File exists/i.test(msg)) throw err
      }
      await this.executor.execute('ip', ['link', 'set', OVERLAY_WG_INTERFACE, 'up'])
    })
  }

  /**
   * Ensure the per-department VXLAN netdev exists with the CORRECT VNI + local VTEP.
   * If an existing device has drifted (VNI reallocated, node re-enrolled with a new
   * VTEP), delete and recreate it rather than silently blackholing on stale params.
   */
  private async ensureVxlanDevice (dev: string, vni: number, mtu: number, localVtep: string): Promise<void> {
    if (await this.deviceExists(dev)) {
      const drift = await this.vxlanParamsDrifted(dev, vni, localVtep)
      if (drift) {
        this.debug.log('warn', `${dev} drifted (${drift}) — recreating`)
        await this.executor.execute('ip', ['link', 'del', dev])
      }
    }
    if (!(await this.deviceExists(dev))) {
      // nolearning: MAC learning is disabled; reachability is head-end static FDB.
      await this.executor.execute('ip', [
        'link', 'add', dev, 'type', 'vxlan',
        'id', String(vni),
        'dstport', String(VXLAN_DSTPORT),
        'local', localVtep,
        'nolearning'
      ])
    }
    await this.setMtu(dev, mtu)
    await this.executor.execute('ip', ['link', 'set', dev, 'up'])
  }

  /** Returns a reason string if the live device's VNI or local VTEP differs from the
   *  desired values, else null. Best-effort: an unreadable device is treated as OK. */
  private async vxlanParamsDrifted (dev: string, vni: number, localVtep: string): Promise<string | null> {
    let out: string
    try {
      out = await this.executor.execute('ip', ['-d', 'link', 'show', dev], { expectNonZeroExit: true })
    } catch {
      return null
    }
    const idM = /vxlan\s+id\s+(\d+)/.exec(out)
    const localM = /\blocal\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/.exec(out)
    if (idM && Number(idM[1]) !== vni) return `vni ${idM[1]}→${vni}`
    if (localM && localM[1] !== localVtep) return `local ${localM[1]}→${localVtep}`
    return null
  }

  /**
   * Reconcile WireGuard peers + head-end-replication FDB for a department to exactly
   * `peers`, and refresh this department's contribution to the node-global ingress
   * filter. WireGuard peers are updated idempotently. The FDB is diffed against the
   * live device (del stale, append missing) so repeated calls do not accumulate
   * duplicate all-zeros entries.
   */
  private async applyPeers (deptId: string, dev: string, peers: OverlayPeer[]): Promise<void> {
    // WireGuard peer set (node-global infiwg). allowed-ips = the peer's VTEP /32.
    for (const p of peers) {
      this.assertValidIPv4(p.vtepIp, 'peer vtepIp')
      if (!p.wgPubKey || /\s/.test(p.wgPubKey)) throw new Error(`Invalid peer wgPubKey for node ${p.nodeId}`)
      if (!p.wgEndpoint || /\s/.test(p.wgEndpoint)) throw new Error(`Invalid peer wgEndpoint for node ${p.nodeId}`)
      await this.executor.execute('wg', [
        'set', OVERLAY_WG_INTERFACE,
        'peer', p.wgPubKey,
        'endpoint', p.wgEndpoint,
        'allowed-ips', `${p.vtepIp}/32`
      ])
    }

    // Optional belt-and-suspenders underlay ingress filter (node-global UNION).
    await this.refreshIngressUnion(deptId, peers)

    // Head-end FDB on the per-department VXLAN device (skip if not realized yet).
    if (!(await this.deviceExists(dev))) return
    const desired = new Set(peers.map((p) => p.vtepIp))
    const current = await this.fdbHeadEndDsts(dev)
    for (const dst of current) {
      if (!desired.has(dst)) {
        await this.executor.execute('bridge', ['fdb', 'del', '00:00:00:00:00:00', 'dev', dev, 'dst', dst], { expectNonZeroExit: true }).catch(() => { /* best-effort */ })
      }
    }
    for (const dst of desired) {
      if (!current.has(dst)) {
        await this.executor.execute('bridge', ['fdb', 'append', '00:00:00:00:00:00', 'dev', dev, 'dst', dst])
      }
    }
  }

  /**
   * Recompute and apply the node-global underlay ingress filter from the UNION of
   * every department's peer host IPs (the `inet infinibay_overlay` table is a single
   * node-wide object — a per-department replace would evict other departments'
   * peers). Pass `peers=undefined` to drop a department from the union. Opt-in
   * (INFINIZATION_OVERLAY_INGRESS_FILTER=1); WireGuard is the primary auth boundary.
   */
  private async refreshIngressUnion (deptId: string, peers: OverlayPeer[] | undefined): Promise<void> {
    if (!this.ingressFilter || !this.self || process.env.INFINIZATION_OVERLAY_INGRESS_FILTER !== '1') return
    const self = this.self
    await this.globalLock.runExclusive(INGRESS_LOCK_KEY, async () => {
      // Accept BOTH address planes a peer's traffic legitimately carries: the WG
      // ENDPOINT host (source of the OUTER encrypted UDP on wgListenPort) AND the peer
      // VTEP (source of the INNER VXLAN packet after WireGuard decapsulates and
      // re-injects it on the input hook — dport 4789, saddr = peer VTEP). Omitting the
      // VTEP makes the 4789 drop rule blackhole every cross-node guest frame.
      if (peers === undefined) {
        this.deptPeerHostIps.delete(deptId)
      } else {
        const ips: string[] = []
        for (const p of peers) { ips.push(this.endpointHost(p.wgEndpoint), p.vtepIp) }
        this.deptPeerHostIps.set(deptId, ips)
      }
      const merged: string[] = []
      for (const ips of this.deptPeerHostIps.values()) merged.push(...ips)
      const union = [...new Set(merged)]
      try {
        await this.ingressFilter!.ensureUnderlayIngressFilter(union, [VXLAN_DSTPORT, self.wgListenPort])
      } catch (err) {
        this.debug.log('warn', `underlay ingress filter update failed (continuing): ${err instanceof Error ? err.message : String(err)}`)
      }
    })
  }

  /** Extract the host from a "host:port" or "[ipv6]:port" WireGuard endpoint. */
  private endpointHost (endpoint: string): string {
    const v6 = /^\[(.+)\]:\d+$/.exec(endpoint)
    if (v6) return v6[1]
    return endpoint.replace(/:\d+$/, '')
  }

  /** Parse `bridge fdb show dev <dev>` for the head-end (all-zeros MAC) `dst` set. */
  private async fdbHeadEndDsts (dev: string): Promise<Set<string>> {
    const out = await this.executor.execute('bridge', ['fdb', 'show', 'dev', dev], { expectNonZeroExit: true }).catch(() => '')
    const dsts = new Set<string>()
    for (const line of out.split('\n')) {
      if (!line.includes('00:00:00:00:00:00')) continue
      const m = /dst\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/.exec(line)
      if (m) dsts.add(m[1])
    }
    return dsts
  }
}
