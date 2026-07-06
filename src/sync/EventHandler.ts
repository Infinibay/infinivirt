/**
 * EventHandler - Listens to QMP events and updates database automatically
 *
 * This class wraps QMPClient instances, subscribes to VM state change events,
 * and automatically updates the database when events occur.
 */

import { EventEmitter } from 'events'
import { QMPClient } from '../core/QMPClient'
import { QMPEventType, QMPTimestamp, QMPShutdownEventData, QMPVMStatus } from '../types/qmp.types'
import {
  DatabaseAdapter,
  DBVMStatus,
  EventHandlerConfig,
  VMEventData
} from '../types/sync.types'
import { StateSync } from './StateSync'
import { TapDeviceManager } from '../network/TapDeviceManager'
import { NftablesService } from '../network/NftablesService'
import { CgroupsManager } from '../system/CgroupsManager'
import { Debugger } from '../utils/debug'
import { KeyedMutex } from '../utils/KeyedMutex'
import { waitForProcessExit as sharedWaitForProcessExit } from '../utils/processIdentity'

/**
 * EventHandler configuration, extended with the optional facade vmLock.
 *
 * CROSS-UNIT CONTRACT (CORE3): the wiring agent constructs EventHandler with the
 * Infinization facade's shared `vmLock` (a KeyedMutex keyed by vmId). When
 * provided, EventHandler serializes its destructive guest-shutdown cleanup
 * (terminateQEMUProcess + the 'off' status flip) against concurrent locked
 * lifecycle ops (start/stop/etc.) on the SAME vmId. When omitted, EventHandler
 * behaves exactly as before (no locking) — backward compatible. EventHandler
 * does NOT add tryRunExclusive to KeyedMutex (that is CORE3's concern); it only
 * calls runExclusive when a lock is present.
 */
export type EventHandlerOptions = Partial<EventHandlerConfig> & {
  vmLock?: KeyedMutex
}

/**
 * Default timeout for waiting for QEMU process to exit (30 seconds).
 *
 * This is a conservative timeout for monitoring guest-initiated shutdowns.
 * Host-initiated shutdowns via VMLifecycle.stop() use a configurable timeout
 * (default 30s, backend typically uses 120s for graceful operations).
 *
 * If this timeout expires during guest-initiated shutdown, it indicates:
 * 1. Guest OS is taking longer than expected to shutdown
 * 2. Guest OS does not support ACPI powerdown
 * 3. QEMU process is hung (requires manual investigation)
 *
 * Note: EventHandler does NOT force-kill on timeout (unlike VMLifecycle.stop()).
 * This is intentional - guest-initiated shutdowns should complete naturally,
 * and if they don't, manual investigation is warranted rather than force-kill.
 */
const DEFAULT_PROCESS_EXIT_TIMEOUT = 30000

/**
 * Interval for polling process status (100ms)
 */
const PROCESS_POLL_INTERVAL = 100

/**
 * Default configuration for EventHandler
 */
const DEFAULT_CONFIG: EventHandlerConfig = {
  enableLogging: true,
  emitCustomEvents: true
}

/**
 * QMP events that trigger state updates
 */
const STATE_CHANGE_EVENTS: QMPEventType[] = [
  'SHUTDOWN',
  'POWERDOWN',
  'RESET',
  'STOP',
  'RESUME',
  'SUSPEND',
  'WAKEUP'
]

/**
 * Mapping from QMP events to database status.
 *
 * Note: 'running' here only means "the QEMU CPU is executing", not "the OS
 * is ready". Whether the guest OS has finished installing and infiniservice
 * has handshaked is tracked separately by MachineConfiguration.setupComplete.
 */
const EVENT_TO_STATUS: Partial<Record<QMPEventType, DBVMStatus>> = {
  'SHUTDOWN': 'off',
  'POWERDOWN': 'off',
  'STOP': 'suspended',
  'RESUME': 'running',
  'SUSPEND': 'suspended',
  'WAKEUP': 'running'
}

/**
 * Internal structure for tracking attached VMs
 */
interface AttachedVM {
  qmpClient: QMPClient
  listeners: Map<string, (...args: unknown[]) => void>
}

/**
 * EventHandler automatically updates database when QMP events occur.
 *
 * @example
 * ```typescript
 * const adapter: DatabaseAdapter = { ... }
 * const eventHandler = new EventHandler(adapter)
 * const qmpClient = new QMPClient('/var/run/qemu/vm1.sock')
 *
 * await qmpClient.connect()
 * await eventHandler.attachToVM('vm-123', qmpClient)
 *
 * // Listen for custom events
 * eventHandler.on('vm:shutdown', (data) => {
 *   console.log(`VM ${data.vmId} shut down`)
 * })
 *
 * // Later, cleanup
 * await eventHandler.detachFromVM('vm-123')
 * ```
 */
export class EventHandler extends EventEmitter {
  private stateSync: StateSync
  private config: EventHandlerConfig
  private attachedVMs: Map<string, AttachedVM> = new Map()
  private debug: Debugger

  // Optional facade vmLock (CORE3). When set, destructive guest-shutdown cleanup
  // is serialized against locked lifecycle ops on the same vmId. See EventHandlerOptions.
  private readonly vmLock?: KeyedMutex

  // VMs with an unattended OS install in progress. While a vmId is in this set,
  // EventHandler MUST NOT reap QEMU or flip the row to 'off' on SHUTDOWN/POWERDOWN:
  // those power events are part of the install (end-of-install shutdown, reboot
  // cycles) and are owned by InstallationMonitor, which applies its own
  // minInstallTimeBeforeComplete/resetCount completion heuristic. VMLifecycle
  // registers the vmId here for the duration of the background install monitor
  // (B3 regression — the critic-found unattended-install race).
  private readonly installInProgress: Set<string> = new Set()

  // Resource cleanup services (created internally like HealthMonitor pattern)
  private readonly tapManager: TapDeviceManager
  private readonly nftables: NftablesService
  private readonly cgroupsManager: CgroupsManager

  /**
   * Creates a new EventHandler instance.
   *
   * EventHandler listens to QMP events and:
   * 1. Updates database status when VM state changes
   * 2. Performs resource cleanup on guest-initiated shutdowns
   *
   * Resource cleanup includes:
   * - Clearing volatile configuration (qmpSocketPath, qemuPid)
   * - Detaching TAP device from bridge (preserved for restart)
   * - Detaching firewall jump rules (chain preserved)
   * - Cleaning up empty cgroup scopes
   *
   * @param db Database adapter instance for database operations
   * @param config Optional configuration options
   */
  constructor (db: DatabaseAdapter, config?: EventHandlerOptions) {
    super()
    this.stateSync = new StateSync(db)
    // Pull the (non-config) vmLock out before merging the rest into config so it
    // isn't carried into EventHandlerConfig.
    const { vmLock, ...handlerConfig } = config ?? {}
    this.vmLock = vmLock
    this.config = { ...DEFAULT_CONFIG, ...handlerConfig }
    this.debug = new Debugger('event-handler')

    // Create service instances for resource cleanup (stateless, safe to create new instances)
    this.tapManager = new TapDeviceManager()
    this.nftables = new NftablesService()
    this.cgroupsManager = new CgroupsManager()

    // Default 'error' listener so a consumer that forgets to subscribe cannot
    // crash the whole (privileged) backend on the first transient emit. A real
    // consumer listener still fires alongside this one.
    this.on('error', (err) => this.debug.log('error', `EventHandler error event: ${err instanceof Error ? err.message : String(err)}`))
  }

  /**
   * Marks a VM as having an unattended OS install in progress.
   *
   * While marked, EventHandler will NOT reap QEMU or flip the row to 'off' on a
   * SHUTDOWN/POWERDOWN event — those power events belong to the install (the
   * end-of-install shutdown and intermediate reboot cycles) and are owned by
   * InstallationMonitor. EventHandler still updates DB status for non-terminal
   * events and still emits observability events.
   *
   * CROSS-UNIT CONTRACT: VMLifecycle.create() calls this BEFORE attaching the
   * general EventHandler for an unattended-install VM, and clears it when the
   * background install monitor settles (success OR failure). Idempotent.
   *
   * @param vmId The VM identifier whose install is in progress
   */
  public markInstallInProgress (vmId: string): void {
    this.installInProgress.add(vmId)
    this.debug.log('info', `Install-in-progress guard ENABLED for VM ${vmId}; SHUTDOWN/POWERDOWN will not reap until install completes`)
  }

  /**
   * Clears the unattended-install guard for a VM (install completed or failed).
   * After this, normal terminal SHUTDOWN/POWERDOWN handling resumes. Idempotent.
   *
   * @param vmId The VM identifier whose install has settled
   */
  public clearInstallInProgress (vmId: string): void {
    if (this.installInProgress.delete(vmId)) {
      this.debug.log('info', `Install-in-progress guard CLEARED for VM ${vmId}; terminal shutdown handling resumed`)
    }
  }

  /**
   * Returns whether an unattended install is currently in progress for a VM.
   */
  public isInstallInProgress (vmId: string): boolean {
    return this.installInProgress.has(vmId)
  }

  /**
   * Attaches event listeners to a QMP client for a specific VM
   *
   * @param vmId The VM identifier in the database
   * @param qmpClient Connected QMPClient instance
   */
  public async attachToVM (vmId: string, qmpClient: QMPClient): Promise<void> {
    if (this.attachedVMs.has(vmId)) {
      this.debug.log(`VM ${vmId} already attached, skipping`)
      return
    }

    this.debug.log(`Attaching to VM ${vmId}`)

    const listeners = new Map<string, (...args: unknown[]) => void>()

    // Create listeners for each state change event
    for (const eventType of STATE_CHANGE_EVENTS) {
      const listener = (data: unknown, timestamp: QMPTimestamp) => {
        this.handleEvent(vmId, eventType, data, timestamp)
      }

      listeners.set(eventType, listener as (...args: unknown[]) => void)
      qmpClient.on(eventType, listener)
    }

    // Track the disconnect event. H9: a 'disconnect' while the client still
    // intends to reconnect is a TRANSIENT flap — we keep the attachment and
    // listeners alive (so a post-reconnect SHUTDOWN is not missed) and only emit
    // for observability. Real teardown happens in reconnect_failed / detachFromVM.
    const disconnectListener = () => {
      this.handleDisconnect(vmId)
    }
    listeners.set('disconnect', disconnectListener)
    qmpClient.on('disconnect', disconnectListener)

    // Track reconnect: when the QMP client successfully re-establishes its socket
    // after a flap, re-sync VM state from the live guest (a SHUTDOWN/STOP that
    // happened during the blip would otherwise be lost) and surface 'vm:reconnect'
    // so the backend can clear any "disconnected" UI state.
    // CROSS-UNIT CONTRACT: emits 'vm:reconnect' { vmId } (a sibling backend agent
    // already subscribes to this).
    const reconnectListener = () => {
      this.handleReconnect(vmId).catch((err) => {
        this.debug.log('error', `Reconnect re-sync failed for VM ${vmId}: ${err instanceof Error ? err.message : String(err)}`)
      })
    }
    listeners.set('reconnect', reconnectListener)
    qmpClient.on('reconnect', reconnectListener)

    // Track reconnect_failed: when the QMP client exhausts its reconnect attempts
    // it goes permanently dead and stops syncing VM state. Previously NOTHING
    // subscribed, so the VM silently drifted (DB 'running' forever after QEMU
    // died, or vice-versa). Surface it as an actionable event the backend can
    // alarm on, and mark the VM as needing reconciliation. This is also the ONLY
    // place (besides explicit detachFromVM) where attachment is actually torn down.
    const reconnectFailedListener = () => {
      this.debug.log('error', `QMP reconnect failed for VM ${vmId}; client is dead, state sync stopped — needs re-attach/reconcile`)
      const attached = this.attachedVMs.get(vmId)
      if (attached) {
        this.removeListeners(attached)
        this.attachedVMs.delete(vmId)
      }
      this.emit('vm:stale', { vmId, reason: 'qmp_reconnect_failed' })
    }
    listeners.set('reconnect_failed', reconnectFailedListener)
    qmpClient.on('reconnect_failed', reconnectFailedListener)

    this.attachedVMs.set(vmId, { qmpClient, listeners })

    this.debug.log(`Attached to VM ${vmId}, listening for ${STATE_CHANGE_EVENTS.length} events`)
  }

  /**
   * Detaches event listeners from a VM
   *
   * @param vmId The VM identifier to detach
   */
  public async detachFromVM (vmId: string, disconnectClient = false): Promise<void> {
    const attached = this.attachedVMs.get(vmId)
    if (!attached) {
      this.debug.log(`VM ${vmId} not attached, skipping detach`)
      return
    }

    this.debug.log(`Detaching from VM ${vmId}`)

    this.removeListeners(attached)
    this.attachedVMs.delete(vmId)

    // On teardown, also disconnect the QMP client so its unix socket + reconnect
    // timer don't leak (used by shutdown()/detachAll).
    if (disconnectClient) {
      try {
        await attached.qmpClient.disconnect()
      } catch (error) {
        this.debug.log('warn', `Failed to disconnect QMP client for VM ${vmId}: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    this.debug.log(`Detached from VM ${vmId}`)
  }

  /**
   * Removes all listeners from an attached VM
   */
  private removeListeners (attached: AttachedVM): void {
    for (const [eventType, listener] of attached.listeners) {
      attached.qmpClient.off(eventType, listener)
    }
  }

  /**
   * Detaches from all VMs
   */
  public async detachAll (): Promise<void> {
    this.debug.log('Detaching from all VMs')

    const vmIds = Array.from(this.attachedVMs.keys())
    for (const vmId of vmIds) {
      // Disconnect each QMP client on full teardown so sockets/timers don't leak.
      await this.detachFromVM(vmId, true)
    }
  }

  /**
   * Gets the list of attached VM IDs
   */
  public getAttachedVMs (): string[] {
    return Array.from(this.attachedVMs.keys())
  }

  /**
   * Checks if a VM is currently attached
   */
  public isAttached (vmId: string): boolean {
    return this.attachedVMs.has(vmId)
  }

  /**
   * Gets the QMP client for an attached VM.
   * Returns undefined if the VM is not attached OR if its QMP client is no
   * longer connected. Callers should not need to defensively check
   * `isConnected()` themselves.
   *
   * @param vmId The VM identifier
   * @returns The connected QMPClient instance, or undefined
   */
  public getQMPClient (vmId: string): QMPClient | undefined {
    const client = this.attachedVMs.get(vmId)?.qmpClient
    if (!client || !client.isConnected()) {
      return undefined
    }
    return client
  }

  /**
   * Handles a QMP event
   */
  private async handleEvent (
    vmId: string,
    event: QMPEventType,
    data: unknown,
    timestamp: QMPTimestamp
  ): Promise<void> {
    if (this.config.enableLogging) {
      this.debug.log(`Event ${event} received for VM ${vmId}`)
    }

    try {
      // Get current status
      let previousStatus: string
      try {
        previousStatus = await this.stateSync.getVMStatus(vmId)
      } catch {
        previousStatus = 'unknown'
      }

      // Determine new status based on event
      const newStatus = EVENT_TO_STATUS[event]

      // B3 (unattended-install race): while an unattended install is in progress
      // for this VM, a SHUTDOWN/POWERDOWN is NOT terminal — it is the end-of-
      // install power-off or an intermediate reboot. InstallationMonitor owns the
      // completion decision (minInstallTimeBeforeComplete/resetCount heuristic).
      // The general EventHandler must NOT flip the row to 'off' or reap QEMU here,
      // or it would defeat the install. Defer entirely to InstallationMonitor:
      // skip the destructive path but still emit observability events below.
      const isTerminalShutdown = newStatus === 'off' && (event === 'SHUTDOWN' || event === 'POWERDOWN')
      if (isTerminalShutdown && this.isInstallInProgress(vmId)) {
        this.debug.log('warn', `${event} for VM ${vmId} while install in progress — deferring to InstallationMonitor, NOT reaping/flipping`)
        if (this.config.emitCustomEvents) {
          this.emitCustomEvents(vmId, event, previousStatus, previousStatus, timestamp, data)
        }
        return
      }

      if (isTerminalShutdown) {
        // Destructive terminal-shutdown path: status flip to 'off' + QEMU reap +
        // resource cleanup. When the facade vmLock is provided (CORE3), serialize
        // this whole block against concurrent locked lifecycle ops on the same
        // vmId. When absent, run inline (backward compatible).
        if (this.vmLock) {
          await this.vmLock.runExclusive(vmId, () => this.handleTerminalShutdown(vmId, event, data))
        } else {
          await this.handleTerminalShutdown(vmId, event, data)
        }
      } else if (newStatus) {
        // Non-terminal status change (STOP/RESUME/SUSPEND/WAKEUP). Just update DB.
        const result = await this.stateSync.updateStatusDirect(vmId, newStatus)

        if (result.success && this.config.enableLogging) {
          this.debug.log(`VM ${vmId} status updated: ${result.previousStatus} → ${result.newStatus}`)
        }
      } else if (event === 'RESET') {
        // RESET doesn't change status, just log it
        if (this.config.enableLogging) {
          this.debug.log(`VM ${vmId} reset, status remains running`)
        }
      }

      // Emit custom events for backend integration
      if (this.config.emitCustomEvents) {
        this.emitCustomEvents(vmId, event, previousStatus, newStatus ?? previousStatus, timestamp, data)
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error'
      this.debug.log('error', `Failed to handle event ${event} for VM ${vmId}: ${message}`)

      // Emit error event
      this.emit('error', { vmId, event, error: message })
    }
  }

  /**
   * Performs the destructive terminal-shutdown handling for a SHUTDOWN/POWERDOWN:
   * captures PID/TAP before the flip, flips the row to 'off', then reaps QEMU and
   * cleans up resources. Extracted so it can be wrapped in the facade vmLock
   * (CORE3) as a single critical section. The install-in-progress guard and the
   * terminal-event check are applied by the caller before invoking this.
   */
  private async handleTerminalShutdown (vmId: string, event: QMPEventType, data: unknown): Promise<void> {
    // CRITICAL: Get PID BEFORE updating status to 'off'.
    // Reason: findRunningVMs() filters by status='running', so if we update
    // status first, we won't be able to retrieve the PID for process monitoring.
    // This ensures we can track QEMU termination even after DB status changes.
    const qemuPid = await this.stateSync.getVMPid(vmId)
    // Capture the TAP name NOW too: getVMInfo()/findRunningVMs filter by
    // status='running', so once we flip to 'off' below it becomes unrecoverable
    // and the TAP would never be detached from the bridge (a leak on every ACPI
    // shutdown).
    let tapDeviceName: string | null = null
    try {
      const info = await this.stateSync.getVMInfo(vmId)
      tapDeviceName = info?.tapDeviceName ?? null
    } catch { /* best-effort capture */ }
    this.debug.log('debug', `Retrieved PID ${qemuPid}, TAP ${tapDeviceName ?? 'none'} for VM ${vmId} before status update`)

    // Flip the row to 'off'.
    const result = await this.stateSync.updateStatusDirect(vmId, 'off')
    if (result.success && this.config.enableLogging) {
      this.debug.log(`VM ${vmId} status updated: ${result.previousStatus} → ${result.newStatus}`)
    }

    // Determine shutdown type from QMP event data.
    // IMPORTANT QEMU LIMITATION: We cannot reliably distinguish between:
    //   1. Guest clicked PowerOff inside VM
    //   2. Host sent system_powerdown via QMP
    // Both produce identical events: {guest: true, reason: 'guest-shutdown'}
    //
    // The ONLY distinguishable case is direct quit command:
    //   - Host sent 'quit' via QMP → {guest: false, reason: 'host-qmp-quit'}
    //
    // For ACPI shutdowns (cases 1 & 2), QEMU will exit automatically after
    // guest completes shutdown. We monitor the process but do NOT send quit.
    const shutdownData = data as QMPShutdownEventData | undefined
    const isHostQmpQuit = shutdownData?.reason === 'host-qmp-quit'

    this.debug.log('info', `Shutdown event - isHostQmpQuit: ${isHostQmpQuit}, reason: ${shutdownData?.reason ?? 'unknown'}`)
    await this.terminateQEMUProcess(vmId, isHostQmpQuit, qemuPid, tapDeviceName)
  }

  /**
   * Emits the custom backend-integration events for a handled QMP event. Shared
   * by the normal path and the install-guard early-return path (where the status
   * does NOT change, so previousStatus is passed as newStatus).
   */
  private emitCustomEvents (
    vmId: string,
    event: QMPEventType,
    previousStatus: string,
    newStatus: string,
    timestamp: QMPTimestamp,
    data: unknown
  ): void {
    const eventData: VMEventData = {
      vmId,
      event,
      previousStatus,
      newStatus,
      timestamp: new Date(timestamp.seconds * 1000 + timestamp.microseconds / 1000),
      qmpData: data
    }

    // Emit specific QMP event (e.g., vm:shutdown, vm:stop)
    this.emit(`vm:${event.toLowerCase()}`, eventData)

    // Emit higher-level status events for easier consumption
    if (newStatus === 'off') {
      this.emit('vm:off', eventData)
    } else if (newStatus === 'suspended') {
      this.emit('vm:suspended', eventData)
    } else if (newStatus === 'running') {
      this.emit('vm:running', eventData)
    }

    // Emit generic event
    this.emit('vm:event', eventData)
  }

  /**
   * Handles QMP client disconnect.
   *
   * H9: Do NOT tear down attachment on a transient flap. If the QMPClient still
   * intends to reconnect (reconnect enabled, not intentionally closed, retry
   * budget remaining), we keep the entry in attachedVMs and keep the listeners
   * bound so a SHUTDOWN/POWERDOWN delivered after a successful reconnect is still
   * handled. Tearing down here would silently stop state sync and defeat the
   * reconnect_failed -> vm:stale surfacing. Real teardown happens only inside the
   * reconnect_failed listener and in explicit detachFromVM().
   *
   * If the client is NOT going to reconnect (e.g. reconnect disabled), this is a
   * terminal disconnect and we fall back to the old behavior: remove listeners +
   * drop the entry, so we don't leak a dead attachment.
   */
  private handleDisconnect (vmId: string): void {
    const attached = this.attachedVMs.get(vmId)
    const willReconnect = attached?.qmpClient.isReconnecting() ?? false

    if (willReconnect) {
      this.debug.log('warn', `QMP transient disconnect for VM ${vmId}; client is reconnecting — keeping attachment, awaiting reconnect/reconnect_failed`)
      // Observability only — do NOT detach.
      this.emit('vm:disconnect', { vmId, timestamp: new Date(), transient: true })
      return
    }

    this.debug.log(`QMP client disconnected for VM ${vmId} (terminal — not reconnecting)`)

    // Terminal disconnect: remove listeners before deleting so the dead client
    // doesn't leak listeners/closures.
    if (attached) {
      this.removeListeners(attached)
      this.attachedVMs.delete(vmId)
    }

    // Emit disconnect event
    this.emit('vm:disconnect', { vmId, timestamp: new Date(), transient: false })
  }

  /**
   * Handles a successful QMP reconnect after a transient flap.
   *
   * Re-syncs DB status from the live guest (query-status -> updateStatusDirect)
   * so any state change missed during the blip is reconciled, then emits
   * 'vm:reconnect' { vmId } for the backend.
   *
   * LOW fix: a reconnect that re-syncs to a TERMINAL run-state (shutdown /
   * guest-panicked, mapped to 'off') must NOT be written as a bare terminal 'off'
   * here. That write-only path skipped reap + cleanupVMResources (leaking the
   * VM's TAP/firewall) AND bypassed the B3 install-in-progress guard (a reconnect
   * mid-unattended-install would stomp the install by flipping it 'off'). Instead
   * we route a terminal re-sync through the SAME path a normal terminal SHUTDOWN
   * uses — handleTerminalShutdown — which respects the install guard, takes the
   * facade vmLock, and runs cleanupVMResources. Non-terminal states keep the
   * lightweight status re-sync.
   *
   * CROSS-UNIT CONTRACT: emits 'vm:reconnect' { vmId } on success.
   */
  private async handleReconnect (vmId: string): Promise<void> {
    this.debug.log('info', `QMP reconnected for VM ${vmId}; re-syncing state`)

    const attached = this.attachedVMs.get(vmId)
    const client = attached?.qmpClient

    if (client && client.isConnected()) {
      try {
        const status = await client.queryStatus()
        // Map the live run-state to a DB status via the canonical mapper.
        // 'running' is the common case; paused/suspended/etc. map to their
        // canonical DB status. Only 'off' is terminal (process gone).
        const mapped = this.mapQmpStatusToDB(status.status, status.running)
        if (mapped === 'off') {
          // Terminal re-sync: the VM powered off during the blip. Do NOT
          // bare-write 'off'. Defer to InstallationMonitor while an unattended
          // install is in progress — a reconnect mid-install must not trigger a
          // terminal teardown (the end-of-install power-off / reboot cycle is
          // owned by the installer; flipping 'off' + reaping here would stomp
          // it). Otherwise run the full terminal-shutdown path (reap +
          // cleanupVMResources) under the facade vmLock, exactly like a live
          // SHUTDOWN event would.
          if (this.isInstallInProgress(vmId)) {
            this.debug.log('warn', `Reconnect re-sync for VM ${vmId} resolved to terminal while install in progress — deferring to InstallationMonitor, NOT reaping/flipping`)
          } else {
            this.debug.log('info', `Reconnect re-sync for VM ${vmId} resolved to terminal — routing through terminal-shutdown path (reap + cleanup)`)
            if (this.vmLock) {
              await this.vmLock.runExclusive(vmId, () => this.handleTerminalShutdown(vmId, 'SHUTDOWN', undefined))
            } else {
              await this.handleTerminalShutdown(vmId, 'SHUTDOWN', undefined)
            }
          }
        } else {
          // Lightweight re-sync: the VM is still alive in some non-terminal
          // state (running, suspended, error, etc.). Just flip the DB status —
          // no resource reap needed.
          await this.stateSync.updateStatusDirect(vmId, mapped)
          this.debug.log('info', `Re-synced VM ${vmId} status to '${mapped}' after reconnect`)
        }
      } catch (err) {
        this.debug.log('warn', `Could not query live status during reconnect re-sync for VM ${vmId}: ${err instanceof Error ? err.message : String(err)}`)
      }
    }

    this.emit('vm:reconnect', { vmId })
  }

  /**
   * Maps a QMP run-state to a DB status for reconnect re-sync.
   *
   * Delegates to {@link StateSync.mapQMPStatusToDBStatus} (the canonical,
   * exhaustive 13-state mapper) so there is a SINGLE source of truth for the
   * QMP→DB status mapping across the entire sync layer.
   *
   * ## Why this exists as a thin wrapper
   *
   * Previously this method reimplemented a PARTIAL mapping (only 6 of 13 QMP
   * run-states) that diverged from StateSync's table in two material ways:
   *
   * 1. **guest-panicked** → `'off'` here vs `'error'` in StateSync. Mapping it
   *    to `'off'` was actively harmful: a panicked guest's QEMU process is
   *    still alive, so the caller's terminal branch (`mapped === 'off'` →
   *    reap + cleanupVMResources) would prematurely destroy resources for a
   *    process that hasn't exited. `'error'` (lightweight status flip) is
   *    correct — the operator can then decide whether to force-kill.
   *
   * 2. **7 states had no mapping at all** (returned `null`): inmigrate,
   *    postmigrate, finish-migrate, restore-vm, watchdog, io-error, colo. The
   *    caller treated `null` as "skip re-sync", so a VM that entered any of
   *    these states during a QMP blip would silently keep a stale DB status
   *    after reconnect. Now all states resolve to a concrete DBVMStatus.
   *
   * The `running` boolean override is retained: QMP's `running` field is
   * authoritative for "is the VM executing", and some QEMU versions report
   * `running: true` alongside a transitional status (e.g. during COLO).
   *
   * @param qmpStatus The QMP `status` field from query-status.
   * @param running   The QMP `running` boolean from query-status.
   * @returns The canonical DB status — always defined (never null).
   */
  private mapQmpStatusToDB (qmpStatus: string, running: boolean): DBVMStatus {
    // QMP's `running` boolean is authoritative for "is the VM executing".
    // Some QEMU versions report running=true with a non-'running' status (e.g.
    // during colo or a brief state transition); honour it as 'running'.
    if (running || qmpStatus === 'running') {
      return 'running'
    }
    // Delegate to the canonical, exhaustive mapper in StateSync. The cast is
    // safe: mapQMPStatusToDBStatus validates the input via isValidQMPStatus()
    // and falls back to 'error' for any unrecognised string.
    return this.stateSync.mapQMPStatusToDBStatus(qmpStatus as QMPVMStatus)
  }

  /**
   * Handles QEMU process termination after a SHUTDOWN/POWERDOWN event.
   *
   * ## Shutdown Flow Context
   *
   * When a SHUTDOWN event is received, QEMU has initiated termination via ACPI.
   * The complete flow is:
   * 1. ACPI powerdown signal sent to guest (via system_powerdown or guest click)
   * 2. Guest OS runs shutdown scripts, flushes buffers, unmounts filesystems
   * 3. Guest completes shutdown
   * 4. QEMU exits automatically (no -no-shutdown flag configured)
   * 5. This handler monitors exit and cleans up resources
   *
   * ## Important Distinction on Shutdown Sources
   *
   * - `isHostQmpQuit=true`: SHUTDOWN resulted from direct QMP `quit` command.
   *   This is the only case where we explicitly initiated termination.
   * - `isHostQmpQuit=false`: SHUTDOWN was triggered via ACPI (system_powerdown).
   *   This includes BOTH "guest clicked PowerOff" AND "host sent system_powerdown via QMP"
   *   because QEMU reports both identically (guest=true, reason='guest-shutdown').
   *
   * ## Resource Cleanup
   *
   * For guest-initiated shutdowns (or host ACPI shutdowns where VMLifecycle.stop()
   * wasn't called), this handler performs cleanup that VMLifecycle.stop() would
   * normally do:
   * - Clear volatile configuration (qmpSocketPath, qemuPid) - TAP preserved
   * - Detach TAP device from bridge (device preserved for restart)
   * - Detach firewall jump rules (chain and rules preserved)
   * - Clean up empty cgroup scopes (opportunistic)
   *
   * This ensures VM resources are properly released regardless of shutdown source.
   *
   * ## Why quit() is NOT Called
   *
   * After ACPI shutdown, QEMU exits automatically. Calling quit() would be:
   * 1. Redundant - QEMU already terminating
   * 2. Risky - socket may be unavailable (race condition)
   * 3. Data-lossy - quit() is immediate, bypassing guest flush
   *
   * @param vmId The VM identifier
   * @param isHostQmpQuit Whether the shutdown was triggered by a direct QMP `quit` command
   * @param pid The QEMU process PID (retrieved before status update)
   *
   * @see VMLifecycle.stop() for host-initiated shutdown flow
   * @see QMPClient.powerdown() for ACPI shutdown command
   */
  private async terminateQEMUProcess (vmId: string, isHostQmpQuit: boolean, pid: number | null, tapDeviceName: string | null = null): Promise<void> {
    const attached = this.attachedVMs.get(vmId)
    if (!attached) {
      this.debug.log(`Cannot terminate QEMU for VM ${vmId}: not attached`)
      return
    }

    if (isHostQmpQuit) {
      // Direct QMP quit - QEMU has already been told to terminate
      // No cleanup needed here - the caller (likely VMLifecycle.stop()) handles cleanup
      this.debug.log('info', `Host QMP quit for VM ${vmId} - QEMU termination already initiated by caller`)
      return
    }

    // ACPI-based shutdown (guest or host system_powerdown) - QEMU will close automatically
    // Do NOT send quit command - the socket may already be unavailable
    this.debug.log('info', `ACPI shutdown detected for VM ${vmId} - QEMU will exit automatically (no -no-shutdown flag, no quit command needed)`)

    const startTime = Date.now()

    if (pid) {
      // L194: use the shared, zombie-aware waitForProcessExit/isProcessAlive so a
      // single implementation governs liveness semantics across the codebase.
      const exited = await sharedWaitForProcessExit(pid, DEFAULT_PROCESS_EXIT_TIMEOUT, PROCESS_POLL_INTERVAL)
      const elapsed = Date.now() - startTime
      if (exited) {
        this.debug.log('info', `✓ QEMU process (PID ${pid}) exited cleanly after ACPI shutdown for VM ${vmId} (took ${elapsed}ms)`)
      } else {
        this.debug.log('warn', `⚠ QEMU process (PID ${pid}) did not exit within ${DEFAULT_PROCESS_EXIT_TIMEOUT}ms for VM ${vmId}. This may indicate:
  1. Guest OS is taking longer than expected to shutdown
  2. Guest OS does not support ACPI powerdown
  3. QEMU process is hung (requires manual investigation)`)
        // The guest failed to complete the ACPI shutdown but QEMU is STILL RUNNING.
        // We must NOT clear the volatile config / detach TAP+firewall / leave the row
        // 'off' (handleTerminalShutdown flipped it optimistically before this wait):
        // doing so ORPHANS a live QEMU — the management plane reports 'off' while the
        // process keeps serving SPICE and holding the disk, and the next start() would
        // then delete its live QMP socket, leaving it permanently unstoppable via QMP.
        // Reconcile the row back to 'running' and SKIP cleanup so the VM stays tracked
        // and manageable. We still do NOT force-kill here (a slow guest may yet finish,
        // and a genuinely hung one warrants investigation); an explicit stop() with
        // force is the supported way to terminate it. If QEMU does exit later, the QMP
        // disconnect + HealthMonitor reconciliation flips the row to 'off' as for a crash.
        try {
          await this.stateSync.updateStatusDirect(vmId, 'running')
          this.debug.log('warn', `VM ${vmId}: reverted row to 'running' and skipped resource cleanup (QEMU PID ${pid} still alive) to avoid orphaning it`)
        } catch (revertErr) {
          this.debug.log('error', `VM ${vmId}: failed to revert status to 'running' after non-exit: ${revertErr instanceof Error ? revertErr.message : String(revertErr)}`)
        }
        return
      }
    } else {
      this.debug.log('debug', `No PID available for VM ${vmId}, cannot monitor process exit`)
    }

    // Perform resource cleanup — reached only when QEMU actually exited (or when no
    // PID was known to monitor). Mirrors the cleanup logic in VMLifecycle.stop() to
    // ensure consistent state regardless of shutdown source (host vs guest).
    await this.cleanupVMResources(vmId, tapDeviceName)
  }

  /**
   * Cleans up VM resources after shutdown.
   *
   * This method performs the same cleanup as VMLifecycle.stop() to ensure
   * consistent state regardless of whether shutdown was host-initiated
   * (via PowerOff mutation) or guest-initiated (via guest OS shutdown).
   *
   * Cleanup includes:
   * - Clear volatile configuration (qmpSocketPath, qemuPid) - TAP name preserved
   * - Detach TAP device from bridge (device preserved for restart)
   * - Detach firewall jump rules (chain and rules preserved)
   * - Clean up empty cgroup scopes (opportunistic, best-effort)
   *
   * All operations are best-effort with error logging - cleanup failures
   * should not prevent the shutdown from being considered complete.
   *
   * @param vmId The VM identifier
   */
  private async cleanupVMResources (vmId: string, preCapturedTapName: string | null = null): Promise<void> {
    this.debug.log('info', `Cleaning up resources for VM ${vmId} after guest-initiated shutdown`)

    // 1. Prefer the TAP name captured BEFORE the status flip (the caller passes it
    // in). Only fall back to getVMInfo() — which filters by status='running' and
    // would now return null — when no pre-captured value is available.
    let tapDeviceName: string | null = preCapturedTapName
    if (!tapDeviceName) {
      try {
        const vmInfo = await this.stateSync.getVMInfo(vmId)
        tapDeviceName = vmInfo?.tapDeviceName ?? null
      } catch (error) {
        this.debug.log('warn', `Failed to retrieve VM info for cleanup: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // 2. Clear volatile configuration (qmpSocketPath, qemuPid)
    // Note: tapDeviceName is preserved for persistent TAP device reuse on restart
    try {
      await this.stateSync.clearVolatileMachineConfiguration(vmId)
      this.debug.log('info', `Cleared volatile configuration for VM ${vmId}`)
    } catch (error) {
      this.debug.log('warn', `Failed to clear volatile configuration: ${error instanceof Error ? error.message : String(error)}`)
    }

    // 3. Detach TAP device from bridge (persistent - not destroyed)
    // The TAP device persists for reuse when VM restarts
    if (tapDeviceName) {
      try {
        await this.tapManager.detachFromBridge(tapDeviceName)
        this.debug.log('info', `Detached TAP device ${tapDeviceName} from bridge`)
      } catch (error) {
        this.debug.log('warn', `Failed to detach TAP device: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // 4. Detach firewall jump rules (chain and rules persist)
    // Only the routing from TAP to chain is removed; firewall rules survive stop/start
    try {
      await this.nftables.detachJumpRules(vmId)
      this.debug.log('info', `Detached firewall jump rules for VM ${vmId}`)
    } catch (error) {
      this.debug.log('warn', `Failed to detach firewall jump rules: ${error instanceof Error ? error.message : String(error)}`)
    }

    // 5. Cleanup empty cgroup scopes (best-effort). ALWAYS run this scan: it only
    // removes scopes that are already empty, and the previous `hasCpuPinning` gate
    // was hardcoded false at the source (getVMInfo), so a pinned VM's scope leaked
    // on every guest shutdown. cleanupEmptyScopes() is cheap and safe to run
    // unconditionally.
    try {
      const cleanedCount = await this.cgroupsManager.cleanupEmptyScopes()
      if (cleanedCount > 0) {
        this.debug.log('info', `Cleaned up ${cleanedCount} empty cgroup scope(s)`)
      }
    } catch (error) {
      this.debug.log('warn', `Failed to cleanup cgroup scopes: ${error instanceof Error ? error.message : String(error)}`)
    }

    this.debug.log('info', `Completed resource cleanup for VM ${vmId} after guest-initiated shutdown`)
  }
}
