/**
 * HealthMonitor - Periodic crash detection and resource cleanup
 *
 * This class periodically checks all VMs marked as 'running' in the database,
 * detects crashed QEMU processes, and cleans up resources.
 */

import { EventEmitter } from 'events'
import * as fs from 'fs'
import * as path from 'path'
import {
  DatabaseAdapter,
  MachineConfigurationRecord,
  RunningVMRecord,
  HealthMonitorConfig,
  HealthCheckResult,
  HealthCheckSummary,
  CrashEvent,
  OrphanEvent,
  ReconcileResult,
  ReconcileSummary,
  DEFAULT_HEALTH_CHECK_INTERVAL,
  CleanupResourceType,
  CleanupStatus,
  CleanupResourceState,
  CleanupResult,
  CleanupAlertEvent,
  MAX_CLEANUP_RETRIES,
  CLEANUP_RETRY_BASE_DELAY_MS,
  CLEANUP_RETRY_MAX_DELAY_MS
} from '../types/sync.types'
import { NftablesService } from '../network/NftablesService'
import { TapDeviceManager } from '../network/TapDeviceManager'
import { CgroupsManager } from '../system/CgroupsManager'
import { Debugger } from '../utils/debug'
import { isProcessAlive as sharedIsProcessAlive, forceKillProcess, pidIdentityState } from '../utils/processIdentity'
import { KeyedMutex } from '../utils/KeyedMutex'
import { isPrismaAdapterError } from '../types/db.types'
import { DEFAULT_PIDFILE_DIR } from '../types/lifecycle.types'

/**
 * HealthMonitor configuration extended with the optional facade vmLock.
 *
 * Following CORE2's local-Options pattern (EventHandlerOptions): the (non-config)
 * `vmLock` is carried alongside the public {@link HealthMonitorConfig} but kept
 * out of that interface in sync.types. When the Infinization facade supplies its
 * shared `vmLock` (a KeyedMutex keyed by vmId), HealthMonitor serializes its
 * per-VM destructive cleanup against locked lifecycle ops on the same VM. When
 * absent (back-compat), HealthMonitor behaves exactly as before (no locking).
 */
export type HealthMonitorOptions = Partial<HealthMonitorConfig> & {
  vmLock?: KeyedMutex
}

/** DB statuses that the startup reconcile pass owns; the orphan scanner must NOT
 *  act on a VM in one of these (a still-booting VM looks like an orphan). */
const TRANSIENT_STATUSES = new Set(['starting', 'powering_off_update', 'rebuilding'])

/**
 * Default configuration for HealthMonitor
 */
const DEFAULT_CONFIG: HealthMonitorConfig = {
  checkIntervalMs: DEFAULT_HEALTH_CHECK_INTERVAL,
  enableCleanup: true
}

/**
 * Type alias for cleanup resource map keys
 */
type CleanupKey = `${CleanupResourceType}:${string}`

/**
 * Creates a typed cleanup key from resource type and identifier
 */
function makeCleanupKey (type: CleanupResourceType, identifier: string): CleanupKey {
  return `${type}:${identifier}`
}

/**
 * CleanupOrchestrator manages transactional cleanup with retry logic.
 *
 * It tracks the state of each cleanup resource through its lifecycle
 * (PENDING → SUCCESS/FAILED) and implements exponential backoff retries
 * for transient failures.
 */
class CleanupOrchestrator {
  private readonly vmId: string
  private resources: Map<CleanupKey, CleanupResourceState> = new Map()
  private debug: Debugger

  constructor (vmId: string, debug: Debugger) {
    this.vmId = vmId
    this.debug = debug
  }

  /**
   * Registers a resource for cleanup tracking
   */
  registerResource (type: CleanupResourceType, identifier: string): void {
    const key = makeCleanupKey(type, identifier)
    this.resources.set(key, {
      type,
      identifier,
      status: CleanupStatus.PENDING,
      attempts: 0
    })
  }

  /**
   * Executes a cleanup operation with retry logic
   */
  async executeCleanup (
    type: CleanupResourceType,
    identifier: string,
    cleanupFn: () => Promise<void>
  ): Promise<void> {
    const key = makeCleanupKey(type, identifier)
    let resource = this.resources.get(key)

    if (!resource) {
      // Auto-register if not already registered
      this.registerResource(type, identifier)
      resource = this.resources.get(key)!
    }

    for (let attempt = 1; attempt <= MAX_CLEANUP_RETRIES; attempt++) {
      resource.attempts = attempt
      resource.status = attempt > 1 ? CleanupStatus.RETRYING : CleanupStatus.PENDING
      resource.lastAttemptAt = new Date()

      try {
        await cleanupFn()
        resource.status = CleanupStatus.SUCCESS
        this.debug.log(`Cleanup succeeded for ${type} (${identifier})`)
        return
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error)
        resource.lastError = errorMsg

        if (attempt < MAX_CLEANUP_RETRIES) {
          const delay = this.calculateBackoff(attempt)
          this.debug.log(`Cleanup failed for ${type}, retrying in ${delay}ms (attempt ${attempt}/${MAX_CLEANUP_RETRIES})`)
          await this.sleep(delay)
        } else {
          resource.status = CleanupStatus.FAILED
          this.debug.log('error', `Cleanup failed for ${type} after ${MAX_CLEANUP_RETRIES} attempts: ${errorMsg}`)
        }
      }
    }
  }

  /**
   * Calculates exponential backoff delay
   */
  private calculateBackoff (attempt: number): number {
    const delay = CLEANUP_RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1)
    return Math.min(delay, CLEANUP_RETRY_MAX_DELAY_MS)
  }

  /**
   * Sleep helper
   */
  private sleep (ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  /**
   * Checks if any non-DB resources have failed
   */
  hasNonDbFailures (): boolean {
    return Array.from(this.resources.values()).some(
      r => r.status === CleanupStatus.FAILED && r.type !== CleanupResourceType.DB_CONFIGURATION
    )
  }

  /**
   * Marks a resource as skipped due to upstream failures
   */
  markSkipped (type: CleanupResourceType, identifier: string, reason: string): void {
    const key = makeCleanupKey(type, identifier)
    this.resources.set(key, {
      type,
      identifier,
      status: CleanupStatus.FAILED,
      attempts: 0,
      lastError: reason
    })
  }

  /**
   * Gets the final cleanup result
   */
  getResult (): CleanupResult {
    const resourceArray = Array.from(this.resources.values())
    return {
      vmId: this.vmId,
      totalResources: resourceArray.length,
      successfulCleanups: resourceArray.filter(r => r.status === CleanupStatus.SUCCESS).length,
      failedCleanups: resourceArray.filter(r => r.status === CleanupStatus.FAILED).length,
      resources: resourceArray,
      timestamp: new Date()
    }
  }

  /**
   * Gets all failed resources
   */
  getFailedResources (): CleanupResourceState[] {
    return Array.from(this.resources.values())
      .filter(r => r.status === CleanupStatus.FAILED)
  }
}

/**
 * HealthMonitor periodically checks for crashed QEMU processes and cleans up resources.
 *
 * Features:
 * - Automatic crash detection via process liveness checks
 * - Transactional cleanup with retry logic (exponential backoff)
 * - State tracking for all cleanup operations
 * - Alert emission for persistent failures
 * - Manual cleanup retry capability
 *
 * @example
 * ```typescript
 * const adapter: DatabaseAdapter = { ... }
 * const healthMonitor = new HealthMonitor(adapter, {
 *   checkIntervalMs: 30000,
 *   enableCleanup: true,
 *   onCrashDetected: async (vmId) => {
 *     console.log(`VM ${vmId} crashed, sending notification...`)
 *   },
 *   onCleanupAlert: async (alert) => {
 *     // Send to monitoring system (e.g., PagerDuty, Slack)
 *     await notificationService.send({
 *       severity: alert.severity,
 *       message: `Cleanup failed for VM ${alert.vmId}`,
 *       resources: alert.failedResources
 *     })
 *   }
 * })
 *
 * // Start monitoring
 * await healthMonitor.start()
 *
 * // Listen for crash events with cleanup details
 * healthMonitor.on('crash', (event) => {
 *   console.log(`Crash detected: VM ${event.vmId}`)
 *   if (event.cleanupResult) {
 *     console.log(`Cleanup: ${event.cleanupResult.successfulCleanups}/${event.cleanupResult.totalResources} successful`)
 *   }
 * })
 *
 * // Listen for cleanup alerts
 * healthMonitor.on('cleanup-alert', (alert) => {
 *   console.error(`Cleanup alert for VM ${alert.vmId}:`, alert.failedResources)
 * })
 *
 * // Manual retry if needed
 * const result = await healthMonitor.retryCleanup(vmId, config)
 *
 * // Stop monitoring
 * await healthMonitor.stop()
 * ```
 */
export class HealthMonitor extends EventEmitter {
  private db: DatabaseAdapter
  private config: HealthMonitorConfig
  private intervalHandle: NodeJS.Timeout | null = null
  private isRunning: boolean = false
  private isChecking: boolean = false
  private tapManager: TapDeviceManager
  private nftables: NftablesService
  private cgroupsManager: CgroupsManager
  private debug: Debugger
  private readonly pidfileDir: string

  // Optional facade vmLock (CORE3). When set, per-VM destructive cleanup
  // (handleCrashedVM, killOrphan's cleanup, reconcile's per-VM body) is serialized
  // against locked lifecycle ops on the same vmId. See HealthMonitorOptions.
  private readonly vmLock?: KeyedMutex

  /**
   * Creates a new HealthMonitor instance
   * @param db Database adapter instance for database operations
   * @param config Optional configuration options (may include the facade vmLock)
   */
  constructor (db: DatabaseAdapter, config?: HealthMonitorOptions) {
    super()
    this.db = db
    // Pull the (non-config) vmLock out before merging the rest into config so it
    // isn't carried into HealthMonitorConfig.
    const { vmLock, ...monitorConfig } = config ?? {}
    this.vmLock = vmLock
    this.config = { ...DEFAULT_CONFIG, ...monitorConfig }
    this.tapManager = new TapDeviceManager()
    this.nftables = new NftablesService()
    this.cgroupsManager = new CgroupsManager()
    this.debug = new Debugger('health-monitor')
    this.pidfileDir = config?.pidfileDir ?? DEFAULT_PIDFILE_DIR

    // Default 'error' listener: an unhandled 'error' emit on an EventEmitter
    // throws and would crash the privileged backend. A real consumer listener
    // still fires alongside this one.
    this.on('error', (err) => this.debug.log('error', `HealthMonitor error event: ${err instanceof Error ? err.message : String(err)}`))
  }

  /**
   * Starts periodic health checks
   */
  public async start (): Promise<void> {
    if (this.isRunning) {
      this.debug.log('Health monitor already running')
      return
    }

    this.debug.log(`Starting health monitor with ${this.config.checkIntervalMs}ms interval`)
    this.isRunning = true

    // Run first check immediately
    await this.runCheck()

    // stop() may have been called (and cleared isRunning) while the initial
    // runCheck() was awaiting. If so, do NOT arm the interval — otherwise it
    // leaks forever because stop() already ran and found intervalHandle null.
    if (!this.isRunning) {
      this.debug.log('Health monitor stopped during initial check; not arming interval')
      return
    }

    // Schedule periodic checks
    this.intervalHandle = setInterval(async () => {
      // Guard the body too: a tick can fire after stop() between clearInterval and
      // the event-loop draining an already-queued callback.
      if (!this.isRunning) return
      await this.runCheck()
    }, this.config.checkIntervalMs)
  }

  /**
   * Stops periodic health checks
   */
  public async stop (): Promise<void> {
    if (!this.isRunning) {
      return
    }

    this.debug.log('Stopping health monitor')
    this.isRunning = false

    if (this.intervalHandle) {
      clearInterval(this.intervalHandle)
      this.intervalHandle = null
    }
  }

  /**
   * Checks if the health monitor is running
   */
  public isMonitoring (): boolean {
    return this.isRunning
  }

  /**
   * Runs a single health check cycle on all running VMs
   * @returns Summary of health check results
   */
  public async checkAllVMs (): Promise<HealthCheckSummary> {
    const timestamp = new Date()
    const results: HealthCheckResult[] = []
    let alive = 0
    let crashed = 0
    let errors = 0

    try {
      // Query all VMs marked as running with their configuration
      const runningVMs = await this.db.findRunningVMs()

      this.debug.log(`Checking ${runningVMs.length} running VMs`)

      for (const vm of runningVMs) {
        const pid = vm.MachineConfiguration?.qemuPid
        const checkResult: HealthCheckResult = {
          vmId: vm.id,
          pid: pid ?? null,
          isAlive: false,
          status: vm.status,
          timestamp
        }

        if (pid === null || pid === undefined) {
          // No PID recorded, can't check
          this.debug.log(`VM ${vm.id} has no PID recorded, skipping`)
          checkResult.isAlive = true // Assume alive if we can't check
          results.push(checkResult)
          alive++
          continue
        }

        try {
          // H8: a PID is only THIS VM's QEMU when liveness AND identity both hold.
          // A bare isProcessAlive on a recycled PID (an unrelated host process that
          // grabbed the dead VM's old PID) would otherwise keep a dead VM pinned
          // 'running' forever, leaking its TAP/firewall/config.
          //
          // LOW-regression fix: use the TRI-STATE pidIdentityState (NOT the fail-
          // closed boolean) for this NON-destructive decision. The boolean collapses
          // a TRANSIENT /proc read error (EMFILE/EACCES under load) to false, which
          // here would tear down a LIVE VM's TAP/firewall and flip it to 'off' — a
          // false-crash. We only treat the PID as CRASHED when the process is dead
          // OR identity is DEFINITIVELY 'mismatch'. 'match' (it's ours) and 'unknown'
          // (we couldn't tell — could be transient) are both treated as alive/ours so
          // a flaky read never destroys a healthy VM. A genuinely recycled PID still
          // reads cleanly as 'mismatch' and is torn down.
          const liveProcess = this.isProcessAlive(pid)
          const identity = liveProcess ? pidIdentityState(pid, vm.internalName) : 'mismatch'
          const isAlive = liveProcess && identity !== 'mismatch'
          checkResult.isAlive = isAlive

          if (isAlive) {
            if (liveProcess && identity === 'unknown') {
              this.debug.log('warn',
                `VM ${vm.id} DB PID ${pid} is alive but identity is UNKNOWN ` +
                `(transient /proc read failure, internalName='${vm.internalName}') — ` +
                `treating as ALIVE (NOT tearing down) to avoid a false-crash`
              )
            }
            alive++
          } else {
            if (liveProcess) {
              this.debug.log('warn',
                `VM ${vm.id} DB PID ${pid} is alive but is NOT this VM's QEMU ` +
                `(recycled PID, internalName='${vm.internalName}') — treating as crashed`
              )
            }
            crashed++
            // Periodic path: defer to an in-flight operator lifecycle op on this VM
            // rather than blocking the scan. The op (or a later cycle) finishes it.
            await this.tryRunDestructiveLocked(vm.id, () =>
              this.handleCrashedVM(vm.id, pid, vm.MachineConfiguration)
            )
          }
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Unknown error'
          this.debug.log('error', `Error checking VM ${vm.id}: ${message}`)
          errors++
          checkResult.isAlive = true // Assume alive on error
        }

        results.push(checkResult)
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      this.debug.log('error', `Health check cycle failed: ${message}`)
      this.emit('error', { message, timestamp })
    }

    const summary: HealthCheckSummary = {
      totalChecked: results.length,
      alive,
      crashed,
      errors,
      orphansDetected: 0,
      orphansCleaned: 0,
      timestamp,
      results
    }

    if (crashed > 0) {
      this.debug.log(`Health check complete: ${alive} alive, ${crashed} crashed, ${errors} errors`)
    }

    return summary
  }

  /**
   * Scans pidfile directory for QEMU processes whose VM is NOT in 'running' state.
   *
   * This detects "orphan" processes that survived an incorrect shutdown — e.g. the
   * backend crashed/restarted and lost its in-memory state while a QEMU process kept
   * running. For each orphan found, the process is killed, resources cleaned up, and
   * an 'orphan-detected' event emitted.
   *
   * @returns Array of orphan events describing what was found and cleaned up
   */
  public async checkOrphanProcesses (): Promise<OrphanEvent[]> {
    const orphans: OrphanEvent[] = []
    const detectedAt = new Date()

    if (!fs.existsSync(this.pidfileDir)) {
      this.debug.log('Pidfile directory does not exist, skipping orphan scan')
      return orphans
    }

    let pidFiles: string[]
    try {
      pidFiles = fs.readdirSync(this.pidfileDir)
        .filter(f => f.endsWith('.pid'))
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      this.debug.log('error', `Failed to read pidfile directory: ${message}`)
      return orphans
    }

    if (pidFiles.length === 0) {
      return orphans
    }

    this.debug.log(`Scanning ${pidFiles.length} pidfiles for orphan processes`)

    for (const pidFile of pidFiles) {
      const pidfilePath = path.join(this.pidfileDir, pidFile)
      const internalName = path.basename(pidFile, '.pid')

      try {
        // Read PID from file
        const pidContent = fs.readFileSync(pidfilePath, 'utf8').trim()
        const pid = parseInt(pidContent, 10)

        if (isNaN(pid)) {
          this.debug.log('warn', `Invalid PID in ${pidfilePath}: "${pidContent}" — removing stale pidfile`)
          fs.unlinkSync(pidfilePath)
          continue
        }

        // Check if the process is actually alive
        if (!this.isProcessAlive(pid)) {
          // Dead process with leftover pidfile — just clean up the file
          this.debug.log(`Removing stale pidfile for dead process: ${pidfilePath} (PID ${pid})`)
          fs.unlinkSync(pidfilePath)
          continue
        }

        // Process is alive — check DB status. A DB OUTAGE must never be treated
        // as "no record" (which would get this live process killed): findMachine
        // ByInternalName now throws on error, so skip this pidfile and re-scan
        // next cycle rather than acting on stale/absent data (fail-closed).
        let vmRecord: RunningVMRecord | null
        try {
          vmRecord = await this.db.findMachineByInternalName(internalName)
        } catch (dbErr) {
          if (isPrismaAdapterError(dbErr)) {
            this.debug.log('warn', `Skipping orphan check for ${internalName} (PID ${pid}): DB query failed (${dbErr.code}) — will not kill an unverified process; retry next cycle`)
            continue
          }
          throw dbErr
        }

        if (!vmRecord) {
          // No DB record at all — orphan from a deleted VM. killOrphan still
          // verifies /proc identity before signalling, so a recycled PID is safe.
          this.debug.log('warn', `Orphan QEMU process ${pid} has no DB record (internalName: ${internalName}) — verifying identity before kill`)
          const event = await this.killOrphan(internalName, pid, pidfilePath, 'unknown (no DB record)', detectedAt)
          orphans.push(event)
          continue
        }

        // VM is migrating between nodes ('moving'): the master's migration flow is
        // the sole writer of its status/nodeId, and during a cross-node move its
        // QEMU may legitimately run on the destination while the row still names the
        // source. Never reap it here — resolving cross-node ownership is the
        // master's job. (findMachineByInternalName deliberately surfaces moving VMs
        // regardless of local node ownership so this guard can see them; a strictly
        // node-scoped read would have returned null above and authorized a kill.)
        if (vmRecord.status === 'moving') {
          this.debug.log(`Skipping ${internalName} (PID ${pid}): VM is migrating (status 'moving'), owned by the master migration flow`)
          continue
        }

        // VM is in a transient state (still booting / rebuilding / powering off):
        // the startup reconcile pass owns these. Acting here would reap a VM that
        // is legitimately mid-start. Skip and let reconcileTransientStates resolve it.
        if (TRANSIENT_STATUSES.has(vmRecord.status)) {
          this.debug.log(`Skipping ${internalName} (PID ${pid}): VM in transient state '${vmRecord.status}', owned by startup reconcile`)
          continue
        }

        if (vmRecord.status === 'running') {
          // Legitimate running VM — skip
          // But verify PID matches what the DB says
          const dbPid = vmRecord.MachineConfiguration?.qemuPid
          if (dbPid !== null && dbPid !== undefined && dbPid !== pid) {
            this.debug.log('warn',
              `PID mismatch for ${internalName}: pidfile says ${pid}, DB says ${dbPid}. ` +
              `Killing orphan ${pid} and cleaning up.`
            )
            const event = await this.killOrphan(internalName, pid, pidfilePath, vmRecord.status, detectedAt)
            orphans.push(event)
          }
          continue
        }

        // Process alive but VM not in 'running' state — this is an orphan
        this.debug.log('warn',
          `Orphan QEMU process ${pid} found for VM ${vmRecord.id} ` +
          `(internalName: ${internalName}, DB status: "${vmRecord.status}") — killing`
        )

        // Update DB status to 'off' in case it was stale — but NEVER clobber a
        // deliberately-set terminal 'error' (e.g. InstallResetTracker force-kills
        // a boot/install-looping VM and marks it 'error'). That kill races this
        // orphan scan: the just-killed QEMU is still momentarily alive here, so an
        // unconditional 'off' would erase the 'error' the tracker just wrote and
        // hide the failure from the UI. The onlyIfNotIn guard makes it atomic.
        try {
          await this.db.updateMachineStatus(vmRecord.id, 'off', { onlyIfNotIn: ['error'] })
        } catch {
          // Best effort — the important thing is killing the process
        }

        const event = await this.killOrphan(
          internalName,
          pid,
          pidfilePath,
          vmRecord.status,
          detectedAt,
          vmRecord
        )
        orphans.push(event)
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error'
        this.debug.log('error', `Error processing pidfile ${pidfilePath}: ${message}`)
      }
    }

    if (orphans.length > 0) {
      this.debug.log(`Orphan scan complete: ${orphans.length} orphan(s) detected and killed`)
    }

    return orphans
  }

  /**
   * Startup reconciliation for VMs stuck in transient states after a
   * backend/process crash. For each VM in 'starting' / 'powering_off_update' /
   * 'rebuilding' (overridable), checks real qemuPid liveness and resolves the row
   * to a terminal state:
   *   live pid                    -> 'running' (caller re-attaches QMP)
   *   dead/no pid + 'rebuilding'  -> 'error' (half-rebuilt qcow2 must not be handed out)
   *   dead/no pid otherwise       -> 'off' + clearVolatileMachineConfiguration
   * Complements checkAllVMs() (running) and checkOrphanProcesses() (live-but-not-
   * running). Invoke once at startup BEFORE attachToRunningVMs.
   */
  public async reconcileTransientStates (
    statuses: string[] = ['starting', 'powering_off_update', 'rebuilding']
  ): Promise<ReconcileSummary> {
    const timestamp = new Date()
    const results: ReconcileResult[] = []
    const promotedToRunning: string[] = []
    const resetToOff: string[] = []
    const resetToError: string[] = []
    const skipped: string[] = []

    let vms: RunningVMRecord[] = []
    try {
      vms = await this.db.findMachinesByStatuses(statuses)
    } catch (err) {
      this.debug.log('error', `reconcileTransientStates query failed: ${String(err)}`)
      return { totalChecked: 0, promotedToRunning, resetToOff, resetToError, skipped, timestamp, results }
    }

    if (vms.length === 0) {
      this.debug.log('No VMs in transient states to reconcile')
      return { totalChecked: 0, promotedToRunning, resetToOff, resetToError, skipped, timestamp, results }
    }

    this.debug.log(`Reconciling ${vms.length} VM(s) in transient states`)

    for (const vm of vms) {
      const pid = vm.MachineConfiguration?.qemuPid ?? null
      // H7: only promote to 'running' when the live PID is actually THIS VM's QEMU.
      // After a host reboot the kernel recycles PIDs, so a stale qemuPid may now be
      // an unrelated host process; promoting on bare liveness corrupts state
      // permanently.
      //
      // LOW-regression fix: gate the promote with the TRI-STATE pidIdentityState
      // (NOT the fail-closed boolean) and keep it conservative:
      //   - promote to 'running' ONLY on a definitive 'match'.
      //   - a live-but-DEFINITIVELY-'mismatch' PID (recycled foreign process) falls
      //     through to the dead-PID branch and is demoted (unchanged behavior).
      //   - a live-but-'unknown' PID (TRANSIENT /proc read failure) is SKIPPED: do
      //     NOT promote (might be foreign) but ALSO do NOT demote/cleanup (might be
      //     a live VM whose /proc read just flaked) — a later cycle or the operator
      //     resolves it. The boolean would have demoted it here, falsely tearing
      //     down a live VM's resources.
      const liveProcess = pid !== null && this.isProcessAlive(pid)
      const identity = liveProcess ? pidIdentityState(pid!, vm.internalName) : 'mismatch'
      const pidAlive = liveProcess && identity === 'match'
      const previousStatus = vm.status

      if (liveProcess && identity === 'unknown') {
        this.debug.log('warn',
          `Reconcile: VM ${vm.id} (${previousStatus}) PID ${pid} is alive but identity is ` +
          `UNKNOWN (transient /proc read failure, internalName='${vm.internalName}') — ` +
          `SKIPPING (not promoting, not demoting) to avoid a false teardown`
        )
        skipped.push(vm.id)
        results.push({ vmId: vm.id, previousStatus, pid, pidAlive, action: 'skipped', reason: 'identity unknown (transient /proc read)' })
        continue
      }

      if (liveProcess && identity === 'mismatch') {
        this.debug.log('warn',
          `Reconcile: VM ${vm.id} (${previousStatus}) PID ${pid} is alive but is NOT this ` +
          `VM's QEMU (recycled PID, internalName='${vm.internalName}') — treating as dead`
        )
      }

      try {
        if (pidAlive) {
          await this.db.updateMachineStatus(vm.id, 'running')
          promotedToRunning.push(vm.id)
          results.push({ vmId: vm.id, previousStatus, pid, pidAlive, action: 'promoted_running' })
          this.debug.log('info', `Reconcile: VM ${vm.id} (${previousStatus}) has live PID ${pid} -> 'running'`)
          continue
        }

        // Startup reconcile runs BEFORE the monitor starts, so there is no monitor
        // contention; we still take the facade vmLock (blocking) when present so a
        // concurrent operator op that races startup is serialized correctly.
        await this.runDestructiveLocked(vm.id, async () => {
          if (this.config.enableCleanup && vm.MachineConfiguration) {
            try {
              await this.cleanupVMResources(vm.id, vm.MachineConfiguration)
            } catch (cleanupErr) {
              this.debug.log('warn', `Reconcile cleanup failed for VM ${vm.id}: ${String(cleanupErr)}`)
            }
          }

          if (previousStatus === 'rebuilding') {
            await this.db.clearVolatileMachineConfiguration(vm.id)
            await this.db.updateMachineStatus(vm.id, 'error')
            resetToError.push(vm.id)
            results.push({ vmId: vm.id, previousStatus, pid, pidAlive, action: 'reset_error', reason: 'crash during rebuild' })
            this.debug.log('warn', `Reconcile: VM ${vm.id} stuck 'rebuilding' with no live PID -> 'error'`)
            return
          }

          await this.db.clearVolatileMachineConfiguration(vm.id)
          // Safety net: reconcile only fetches transient statuses, but guard the
          // demotion anyway so a terminal 'error' can never be reset to 'off'.
          await this.db.updateMachineStatus(vm.id, 'off', { onlyIfNotIn: ['error'] })
          resetToOff.push(vm.id)
          results.push({ vmId: vm.id, previousStatus, pid, pidAlive, action: 'reset_off' })
          this.debug.log('info', `Reconcile: VM ${vm.id} (${previousStatus}) no live PID -> 'off' (TAP preserved)`)
        })
      } catch (err) {
        skipped.push(vm.id)
        results.push({ vmId: vm.id, previousStatus, pid, pidAlive, action: 'skipped', reason: String(err) })
        this.debug.log('error', `Reconcile failed for VM ${vm.id}: ${String(err)}`)
      }
    }

    this.debug.log(
      `Reconcile complete: ${promotedToRunning.length} promoted, ${resetToOff.length} -> off, ` +
      `${resetToError.length} -> error, ${skipped.length} skipped`
    )
    this.emit('reconcile-complete', { promotedToRunning, resetToOff, resetToError, skipped, timestamp })
    return { totalChecked: vms.length, promotedToRunning, resetToOff, resetToError, skipped, timestamp, results }
  }

  /**
   * Kills an orphan QEMU process with SIGTERM → SIGKILL escalation,
   * cleans up its pidfile, and optionally cleans up VM resources.
   */
  private async killOrphan (
    internalName: string,
    pid: number,
    pidfilePath: string,
    dbStatus: string,
    detectedAt: Date,
    vmRecord?: RunningVMRecord | null
  ): Promise<OrphanEvent> {
    let killed = false

    // IDENTITY-CHECKED kill. forceKillProcess reads /proc/<pid>/cmdline and only
    // signals if it contains 'qemu-system' AND this VM's internalName. If the PID
    // was recycled into an unrelated host process, it is NOT signalled (skipped) —
    // this is the single most dangerous path in the library (root, every 30s).
    try {
      const result = await forceKillProcess(pid, internalName)
      if (result.skipped) {
        this.debug.log('warn', `Refused to kill PID ${pid}: not identifiable as ${internalName}'s QEMU (likely a recycled PID) — removing stale pidfile only`)
      } else if (result.confirmedGone) {
        killed = true
        this.debug.log(`Orphan process ${pid} (${internalName}) terminated`)
      } else {
        this.debug.log('error', `Orphan process ${pid} (${internalName}) survived SIGKILL — manual intervention required`)
      }
    } catch (err) {
      this.debug.log('error', `Failed to kill orphan process ${pid}: ${String(err)}`)
    }

    // Remove pidfile
    try {
      if (fs.existsSync(pidfilePath)) {
        fs.unlinkSync(pidfilePath)
        this.debug.log(`Removed orphan pidfile: ${pidfilePath}`)
      }
    } catch (err) {
      this.debug.log('error', `Failed to remove pidfile ${pidfilePath}: ${String(err)}`)
    }

    // Attempt resource cleanup if we have the VM record
    let cleanupPerformed = false
    let cleanupResult: CleanupResult | undefined

    if (vmRecord?.MachineConfiguration) {
      const record = vmRecord
      try {
        // Periodic orphan scan: defer the destructive cleanup to an in-flight
        // operator op on this VM rather than blocking it. The process is already
        // killed above (identity-checked); only resource/DB cleanup is deferred.
        await this.tryRunDestructiveLocked(record.id, async () => {
          cleanupResult = await this.cleanupVMResources(record.id, record.MachineConfiguration!)
          cleanupPerformed = true
        })
      } catch (err) {
        this.debug.log('error', `Resource cleanup failed for orphan VM ${record.id}: ${String(err)}`)
      }
    }

    const event: OrphanEvent = {
      vmId: vmRecord?.id ?? internalName,
      pid,
      dbStatus,
      pidfilePath,
      detectedAt,
      killed,
      cleanupPerformed,
      cleanupResult
    }

    this.emit('orphan-detected', event)
    return event
  }


  /**
   * Checks if a specific VM process is alive
   *
   * @param vmId The VM identifier
   * @param pid The process ID to check
   * @returns True if the process is alive
   */
  public checkVM (vmId: string, pid: number): boolean {
    this.debug.log(`Checking VM ${vmId} with PID ${pid}`)
    return this.isProcessAlive(pid)
  }

  /**
   * Checks if a process is alive using kill -0 and /proc/{pid}/stat
   *
   * This method checks both process existence and zombie status.
   * A process in zombie state (Z) is not truly alive - it has exited
   * but its parent hasn't collected its exit status yet.
   *
   * @param pid The process ID to check
   * @returns True if the process exists and is not a zombie
   */
  public isProcessAlive (pid: number): boolean {
    // Delegates to the single shared implementation (kill -0 + /proc zombie check,
    // EPERM => alive) so liveness semantics are identical in HealthMonitor,
    // EventHandler and VMLifecycle.
    return sharedIsProcessAlive(pid)
  }

  /**
   * Runs a per-VM destructive block under the facade vmLock when present,
   * BLOCKING until the lock is free. Used by the startup reconcile pass (which
   * runs before the monitor starts, so there is no scan contention to defer).
   * If no vmLock was provided (back-compat), runs the block directly.
   */
  private async runDestructiveLocked<T> (vmId: string, fn: () => Promise<T>): Promise<T> {
    if (this.vmLock) {
      return this.vmLock.runExclusive(vmId, fn)
    }
    return fn()
  }

  /**
   * Runs a per-VM destructive block under the facade vmLock, NON-BLOCKING: if an
   * operator lifecycle op already holds (or is queued for) this VM's lock, the
   * block is SKIPPED so the periodic scan never stalls behind an in-flight op —
   * that op (or a later scan cycle) re-observes the state and finishes the work.
   * If no vmLock was provided (back-compat), runs the block directly.
   */
  private async tryRunDestructiveLocked (vmId: string, fn: () => Promise<void>): Promise<void> {
    if (this.vmLock) {
      const outcome = await this.vmLock.tryRunExclusive(vmId, fn)
      if (!outcome.ran) {
        this.debug.log(`Deferring cleanup for VM ${vmId}: a locked lifecycle op is in flight`)
      }
      return
    }
    await fn()
  }

  /**
   * Handles a crashed VM by updating status and cleaning up resources
   */
  private async handleCrashedVM (
    vmId: string,
    pid: number,
    config: MachineConfigurationRecord | null
  ): Promise<void> {
    const detectedAt = new Date()
    this.debug.log(`Crash detected for VM ${vmId} (PID ${pid})`)

    let cleanupResult: CleanupResult | null = null

    try {
      // Update database status to 'off' — but NEVER downgrade a deliberate
      // terminal 'error'. During an install the VM is 'running' and this monitor
      // is attached; when InstallResetTracker force-kills a boot/install-looping
      // VM it marks the row 'error', and this crash handler fires on the same
      // process death. Without the guard, the two race and 'off' can land last,
      // hiding the failure. onlyIfNotIn makes the demotion atomic + conditional.
      await this.db.updateMachineStatus(vmId, 'off', { onlyIfNotIn: ['error'] })
      this.debug.log(`VM ${vmId} status updated to 'off'`)

      // Cleanup resources if enabled
      if (this.config.enableCleanup && config) {
        cleanupResult = await this.cleanupVMResources(vmId, config)
      }

      // Call custom handler if provided
      if (this.config.onCrashDetected) {
        await this.config.onCrashDetected(vmId)
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      this.debug.log('error', `Failed to handle crashed VM ${vmId}: ${message}`)
    }

    // Emit crash event with cleanup details
    const crashEvent: CrashEvent = {
      vmId,
      pid,
      lastKnownStatus: 'running',
      detectedAt,
      cleanupPerformed: cleanupResult !== null,
      cleanupResult: cleanupResult ?? undefined
    }

    this.emit('crash', crashEvent)
  }

  /**
   * Cleans up resources for a crashed VM with retry logic and state tracking
   *
   * @param vmId The VM identifier
   * @param config The machine configuration with resource identifiers
   * @returns Cleanup result with status of all operations
   */
  private async cleanupVMResources (
    vmId: string,
    config: MachineConfigurationRecord
  ): Promise<CleanupResult> {
    this.debug.log(`Starting transactional cleanup for VM ${vmId}`)

    const orchestrator = new CleanupOrchestrator(vmId, this.debug)

    // TAP device cleanup - detach from bridge but preserve for reuse
    // This enables persistent TAP devices across crash/restart cycles
    if (config.tapDeviceName) {
      await orchestrator.executeCleanup(
        CleanupResourceType.TAP_DEVICE,
        config.tapDeviceName,
        async () => {
          await this.tapManager.detachFromBridge(config.tapDeviceName!)
        }
      )
    }

    // Firewall chain cleanup - detach jump rules but preserve chain and rules
    // Chain persists for reuse when VM restarts
    await orchestrator.executeCleanup(
      CleanupResourceType.FIREWALL_CHAIN,
      vmId,
      async () => {
        await this.nftables.detachJumpRules(vmId)
      }
    )

    // QMP socket cleanup
    if (config.qmpSocketPath) {
      await orchestrator.executeCleanup(
        CleanupResourceType.QMP_SOCKET,
        config.qmpSocketPath,
        async () => {
          if (fs.existsSync(config.qmpSocketPath!)) {
            fs.unlinkSync(config.qmpSocketPath!)
          }
        }
      )
    }

    // Guest agent socket cleanup
    if (config.guestAgentSocketPath) {
      await orchestrator.executeCleanup(
        CleanupResourceType.QMP_SOCKET,
        config.guestAgentSocketPath,
        async () => {
          if (fs.existsSync(config.guestAgentSocketPath!)) {
            fs.unlinkSync(config.guestAgentSocketPath!)
          }
        }
      )
    }

    // InfiniService socket cleanup
    if (config.infiniServiceSocketPath) {
      await orchestrator.executeCleanup(
        CleanupResourceType.QMP_SOCKET,
        config.infiniServiceSocketPath,
        async () => {
          if (fs.existsSync(config.infiniServiceSocketPath!)) {
            fs.unlinkSync(config.infiniServiceSocketPath!)
          }
        }
      )
    }

    // Pidfile cleanup - derive path from qmpSocketPath
    // qmpSocketPath: /path/to/sockets/{internalName}.sock
    // pidfilePath: {pidfileDir}/{internalName}.pid
    if (config.qmpSocketPath) {
      const socketBasename = path.basename(config.qmpSocketPath, '.sock')
      const pidfilePath = path.join(this.pidfileDir, `${socketBasename}.pid`)
      await orchestrator.executeCleanup(
        CleanupResourceType.PIDFILE,
        pidfilePath,
        async () => {
          if (fs.existsSync(pidfilePath)) {
            // Verify the pidfile points to a dead process before deleting
            // This prevents accidentally deleting pidfiles for processes that are still running
            try {
              const pidContent = fs.readFileSync(pidfilePath, 'utf8').trim()
              const pid = parseInt(pidContent, 10)
              if (!isNaN(pid)) {
                // Check if process is still alive
                try {
                  process.kill(pid, 0)
                  // Process is still alive - this shouldn't happen but log warning
                  this.debug.log('warn', `Pidfile ${pidfilePath} points to alive process ${pid} - skipping cleanup`)
                  return
                } catch {
                  // Process is dead, safe to delete pidfile
                }
              }
            } catch {
              // Error reading pidfile - safe to delete
            }
            fs.unlinkSync(pidfilePath)
            this.debug.log(`Deleted orphan pidfile: ${pidfilePath}`)
          }
        }
      )
    }

    // Database configuration cleanup - skip if upstream resources failed
    // This preserves configuration for compensation/manual retry
    if (orchestrator.hasNonDbFailures()) {
      this.debug.log(
        `Skipping DB configuration cleanup for VM ${vmId} due to upstream resource cleanup failures`
      )
      orchestrator.markSkipped(
        CleanupResourceType.DB_CONFIGURATION,
        vmId,
        'Skipped due to upstream resource cleanup failures'
      )
    } else {
      // Clear volatile configuration but preserve tapDeviceName for persistent TAP reuse
      await orchestrator.executeCleanup(
        CleanupResourceType.DB_CONFIGURATION,
        vmId,
        async () => {
          await this.db.clearVolatileMachineConfiguration(vmId)
        }
      )
    }

    // Cgroup scope reclaim — a crashed/orphaned/transient-dead VM leaks its
    // qemu-<pid>.scope (created when the VM was CPU-pinned). cleanupEmptyScopes is
    // self-scanning, only removes scopes whose cgroup.procs is empty, swallows its
    // own errors and is idempotent, so it is safe to call unconditionally on every
    // cleanup. Best-effort: a failure here must not fail the rest of the cleanup.
    try {
      const reclaimed = await this.cgroupsManager.cleanupEmptyScopes()
      if (reclaimed > 0) {
        this.debug.log(`Reclaimed ${reclaimed} empty cgroup scope(s) during cleanup for VM ${vmId}`)
      }
    } catch (err) {
      this.debug.log('warn', `Cgroup scope reclaim failed for VM ${vmId}: ${err instanceof Error ? err.message : String(err)}`)
    }

    const result = orchestrator.getResult()

    // Log summary
    this.debug.log(
      `Cleanup completed for VM ${vmId}: ${result.successfulCleanups}/${result.totalResources} successful, ${result.failedCleanups} failed`
    )

    // Emit alert if there are failures
    if (result.failedCleanups > 0) {
      this.emitCleanupAlert(vmId, orchestrator.getFailedResources())
    }

    return result
  }

  /**
   * Emits a cleanup alert for failed resources
   */
  private emitCleanupAlert (vmId: string, failedResources: CleanupResourceState[]): void {
    const severity = failedResources.length >= 3 ? 'error' : 'warning'

    const alertEvent: CleanupAlertEvent = {
      vmId,
      failedResources,
      timestamp: new Date(),
      severity
    }

    this.debug.log('error',
      `ALERT: Cleanup failures for VM ${vmId}: ${failedResources.map(r => r.type).join(', ')}`
    )

    // Emit event for external monitoring systems
    this.emit('cleanup-alert', alertEvent)

    // Call custom alert handler if provided
    if (this.config.onCleanupAlert) {
      this.config.onCleanupAlert(alertEvent).catch(err => {
        const message = err instanceof Error ? err.message : 'Unknown error'
        this.debug.log('error', `Alert handler failed: ${message}`)
      })
    }
  }

  /**
   * Manually retry cleanup for a VM with failed resources.
   * Useful for operations teams to retry after fixing underlying issues.
   *
   * @param vmId The VM identifier
   * @param config The machine configuration with resource identifiers
   * @returns Cleanup result with updated state
   */
  public async retryCleanup (
    vmId: string,
    config: MachineConfigurationRecord
  ): Promise<CleanupResult> {
    this.debug.log(`Manual cleanup retry requested for VM ${vmId}`)
    return await this.cleanupVMResources(vmId, config)
  }

  /**
   * Runs a single health check cycle with re-entrancy guard
   */
  private async runCheck (): Promise<void> {
    // Prevent overlapping check cycles
    if (this.isChecking) {
      this.debug.log('Health check already in progress, skipping')
      return
    }

    this.isChecking = true
    try {
      // Phase 1: Check known running VMs for crashes
      const summary = await this.checkAllVMs()

      // Phase 2: Scan for orphan QEMU processes (alive but VM not in 'running' state)
      const orphans = await this.checkOrphanProcesses()

      // Emit combined summary event with orphan stats
      this.emit('check-complete', {
        ...summary,
        orphansDetected: orphans.length,
        orphansCleaned: orphans.filter(o => o.killed).length
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      this.debug.log('error', `Health check failed: ${message}`)
      // Don't stop monitoring on errors
    } finally {
      this.isChecking = false
    }
  }
}
