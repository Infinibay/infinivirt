/**
 * Infinization - Main Public API for VM Management
 *
 * This is the primary entry point for the infinization library.
 * It manages shared resources (database, event handling, health monitoring)
 * and provides a clean interface for VM lifecycle operations.
 *
 * Note: Pass your application's PrismaClient singleton for connection pooling.
 * Infinization does not create or manage its own Prisma instance.
 *
 * @example
 * ```typescript
 * import { PrismaClient } from '@prisma/client'
 * import { Infinization } from '@infinibay/infinization'
 * import { getEventManager } from '@backend/services/EventManager'
 *
 * // Use your application's Prisma singleton
 * const prisma = new PrismaClient()
 *
 * const infinization = new Infinization({
 *   prismaClient: prisma,
 *   eventManager: getEventManager(),
 *   healthMonitorInterval: 30000
 * })
 *
 * await infinization.initialize()
 *
 * const result = await infinization.createVM({
 *   vmId: 'machine-uuid-from-db',
 *   name: 'test-vm',
 *   internalName: 'vm-abc123',
 *   os: 'ubuntu',
 *   cpuCores: 4,
 *   ramGB: 8,
 *   diskSizeGB: 50,
 *   bridge: 'virbr0',
 *   displayType: 'spice',
 *   displayPort: 5901
 * })
 *
 * console.log('VM created:', result.vmId)
 *
 * // Later, cleanup
 * await infinization.stopVM(result.vmId)
 * await infinization.shutdown()
 * ```
 */

import { VMLifecycle } from './VMLifecycle'
import { InfinigpuDeviceServer } from './InfinigpuDeviceServer'
import * as path from 'path'
import { QMPClient } from './QMPClient'
import { KeyedMutex } from '../utils/KeyedMutex'
import { GuestAgentClient } from './GuestAgentClient'
import { PrismaAdapter, type InfinizationDatabase } from '../db/PrismaAdapter'
import { EventHandler } from '../sync/EventHandler'
import { HealthMonitor } from '../sync/HealthMonitor'
import { NftablesService } from '../network/NftablesService'
import { OverlayManager } from '../network/OverlayManager'
import { CgroupsManager } from '../system/CgroupsManager'
import { Debugger } from '../utils/debug'
import type { OverlayPeer, OverlaySegmentSpec } from '../types/overlay.types'
import {
  InfinizationConfig,
  VMCreateConfig,
  InfinigpuVmOptions,
  VMCreateResult,
  VMStartConfig,
  VMStopConfig,
  VMOperationResult,
  VMStatusResult,
  ActiveVMResources,
  EventManagerLike,
  LifecycleError,
  LifecycleErrorCode,
  DEFAULT_QMP_SOCKET_DIR,
  DEFAULT_DISK_DIR,
  DEFAULT_PIDFILE_DIR
} from '../types/lifecycle.types'
import { DEFAULT_HEALTH_CHECK_INTERVAL, ReconcileSummary } from '../types/sync.types'
import { QMPBlockInfo } from '../types/qmp.types'

/**
 * Infinization is the main public API for VM management.
 *
 * It handles:
 * - Automatic nftables initialization
 * - Health monitoring for crash detection
 * - Event emission to backend
 * - Centralized resource management
 * - Clean interface for VM operations
 */
export class Infinization {
  private readonly debug: Debugger
  private readonly config: InfinizationConfig
  private prisma!: InfinizationDatabase
  private eventHandler!: EventHandler
  private healthMonitor!: HealthMonitor
  private nftables!: NftablesService
  private overlay!: OverlayManager
  private cgroupsManager!: CgroupsManager
  private eventManager?: EventManagerLike
  private activeVMs: Map<string, ActiveVMResources> = new Map()
  // Per-VM infinigpu vfio-user device servers (one per GPU VM). Lives on the
  // singleton facade because VMLifecycle is rebuilt per operation; reaped on
  // stop / destroy / crash.
  private infinigpuServers: Map<string, InfinigpuDeviceServer> = new Map()
  private initialized: boolean = false
  private externalPrisma: boolean = false

  // Per-vmId operation lock. Every state-mutating VM operation (the 8 ops
  // below) is serialized per VM so concurrent power/lifecycle calls on the same
  // VM cannot interleave (double SIGKILL, start-while-stopping, destroy-during-
  // start, ...). Different VMs run concurrently. One instance per singleton =>
  // process-global serialization. See KeyedMutex for liveness/eviction notes.
  private readonly vmLock = new KeyedMutex()

  // Configuration directories
  private readonly diskDir: string
  private readonly qmpSocketDir: string
  private readonly pidfileDir: string

  /**
   * Creates a new Infinization instance.
   *
   * @param config - Configuration options (prismaClient is required)
   */
  constructor (config: InfinizationConfig) {
    this.debug = new Debugger('infinization')
    this.config = config
    this.eventManager = config.eventManager

    // Configure directories
    this.diskDir = config.diskDir ?? DEFAULT_DISK_DIR
    this.qmpSocketDir = config.qmpSocketDir ?? DEFAULT_QMP_SOCKET_DIR
    this.pidfileDir = config.pidfileDir ?? DEFAULT_PIDFILE_DIR

    this.debug.log('Infinization instance created')
  }

  // ===========================================================================
  // Initialization & Lifecycle
  // ===========================================================================

  /**
   * Initializes the Infinization system.
   *
   * - Creates/configures database adapter
   * - Initializes nftables infrastructure
   * - Starts health monitoring (if enabled)
   *
   * @throws Error if initialization fails
   */
  async initialize (): Promise<void> {
    if (this.initialized) {
      this.debug.log('Already initialized')
      return
    }

    this.debug.log('Initializing Infinization')

    try {
      // Database facade: inject either a ready-made `databaseAdapter` (e.g. a
      // compute-node agent's RpcDatabaseAdapter proxying to the master — it holds
      // no Prisma) OR a `prismaClient` we wrap in a node-scoped PrismaAdapter (the
      // master backend, the single writer). Exactly one is required.
      if (this.config.databaseAdapter && this.config.prismaClient) {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_CONFIG,
          'Provide either databaseAdapter or prismaClient in InfinizationConfig, not both'
        )
      }
      if (this.config.databaseAdapter) {
        this.prisma = this.config.databaseAdapter
        this.externalPrisma = true
        this.debug.log('Using injected database adapter (no local Prisma client)')
      } else if (this.config.prismaClient) {
        this.prisma = new PrismaAdapter(this.config.prismaClient, this.config.nodeId)
        this.externalPrisma = true
        this.debug.log(
          `Using external Prisma client${this.config.nodeId ? ` (node-scoped: ${this.config.nodeId})` : ''}`
        )
      } else {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_CONFIG,
          'Either databaseAdapter or prismaClient is required in InfinizationConfig'
        )
      }

      // Initialize EventHandler — share the facade vmLock so its destructive
      // guest-shutdown cleanup is serialized against locked lifecycle ops on the
      // same VM (prevents the reaper racing a concurrent start/stop/destroy).
      this.eventHandler = new EventHandler(this.prisma, {
        enableLogging: true,
        emitCustomEvents: true,
        vmLock: this.vmLock
      })
      this.debug.log('EventHandler initialized')

      // Initialize HealthMonitor — share the facade vmLock so its per-VM crash/
      // orphan/reconcile cleanup is serialized against locked lifecycle ops on the
      // same VM. The periodic scan defers (non-blocking) to in-flight operator ops.
      const healthInterval = this.config.healthMonitorInterval ?? DEFAULT_HEALTH_CHECK_INTERVAL
      this.healthMonitor = new HealthMonitor(this.prisma, {
        checkIntervalMs: healthInterval,
        enableCleanup: true,
        vmLock: this.vmLock,
        onCrashDetected: async (vmId: string) => {
          this.debug.log(`Crash detected for VM: ${vmId}`)
          this.activeVMs.delete(vmId)
          // Reap the infinigpu device server too, or a crashed GPU VM leaks the
          // host process + its broker admission ticket.
          await this.reapInfinigpuServer(vmId)
          // Emit crash event to backend
          if (this.eventManager?.emitCRUD) {
            this.eventManager.emitCRUD('machines', 'crash', vmId)
          }
        }
      })
      this.debug.log('HealthMonitor initialized')

      // CgroupsManager for startup scope reclaim (reclaims qemu-<pid>.scope leaked
      // by VM crashes during the PREVIOUS run). Self-scanning, removes only empty
      // scopes, idempotent — safe to call unconditionally.
      this.cgroupsManager = new CgroupsManager()

      // Initialize nftables infrastructure. bridgeConntrackMode is operator-
      // configurable: default 'fail' (recommended fail-loud-at-init — initialize()
      // throws a clear error on a host lacking br_netfilter/nf_conntrack_bridge).
      // Precedence: explicit InfinizationConfig.bridgeConntrackMode wins; else the
      // INFINIZATION_BRIDGE_CONNTRACK_MODE env var (=degrade ⇒ stateless); else 'fail'.
      // The typed field makes this security-relevant knob discoverable in the public
      // config instead of living only in an undocumented env var (CODE_REVIEW §C.4 INT-02).
      this.nftables = new NftablesService({
        bridgeConntrackMode: this.config.bridgeConntrackMode ??
          (process.env.INFINIZATION_BRIDGE_CONNTRACK_MODE === 'degrade' ? 'degrade' : 'fail')
      })
      await this.nftables.initialize()
      this.debug.log('Nftables infrastructure initialized')

      // Department L2 overlay realizer (07-networking.md §1). No async init: a pure
      // command-executor over `ip`/`wg`/`bridge`. `config.overlay` (this node's VTEP
      // + WireGuard key/port) is present only on an overlay-capable host; when absent
      // the overlay verbs throw rather than realize a half-built segment. Given the
      // nftables service so it can install the optional underlay ingress filter
      // (opt-in). Master-pushed per-segment data arrives as call arguments.
      this.overlay = new OverlayManager(this.config.overlay, undefined, undefined, this.nftables)

      // Reconcile VMs stuck in transient states (starting/rebuilding/powering_off)
      // BEFORE the health monitor begins scanning. Otherwise the very first orphan
      // scan sees a still-booting VM's live QEMU as an orphan and reaps it. The
      // reconcile pass takes ownership of those rows (promote to running / reset to
      // off) so the scanner skips them. Enforced here in code, not by a doc contract.
      try {
        const reconcile = await this.healthMonitor.reconcileTransientStates()
        if (reconcile.totalChecked > 0) {
          this.debug.log('info', `Startup reconcile: ${reconcile.promotedToRunning.length} promoted, ${reconcile.resetToOff.length} reset to off, ${reconcile.resetToError.length} to error`)
        }
      } catch (error) {
        this.debug.log('error', `Startup reconcile failed (continuing): ${error instanceof Error ? error.message : String(error)}`)
      }

      // Reclaim cgroup scopes leaked by crashes in the previous run. Best-effort:
      // cleanupEmptyScopes is self-scanning and removes only already-empty scopes,
      // so it can never disturb a live VM. A failure must not block startup.
      try {
        const reclaimed = await this.cgroupsManager.cleanupEmptyScopes()
        if (reclaimed > 0) {
          this.debug.log('info', `Startup cgroup reclaim: removed ${reclaimed} empty scope(s) from prior crashes`)
        }
      } catch (error) {
        this.debug.log('warn', `Startup cgroup reclaim failed (continuing): ${error instanceof Error ? error.message : String(error)}`)
      }

      // Start health monitoring if enabled
      const autoStart = this.config.autoStartHealthMonitor ?? true
      if (autoStart) {
        await this.healthMonitor.start()
        this.debug.log('HealthMonitor started')
      }

      this.initialized = true
      this.debug.log('Infinization initialized successfully')
    } catch (error) {
      this.debug.log('error', `Initialization failed: ${error instanceof Error ? error.message : String(error)}`)
      throw error
    }
  }

  /**
   * Shuts down the Infinization system.
   *
   * - Stops health monitoring
   * - Detaches all event handlers
   * - Disconnects all QMP clients
   * - Clears active VMs map
   * - Closes database connection (if owned)
   */
  async shutdown (): Promise<void> {
    this.debug.log('Shutting down Infinization')

    // Stop health monitor
    if (this.healthMonitor) {
      await this.healthMonitor.stop()
      this.debug.log('HealthMonitor stopped')
    }

    // Detach all event handlers
    if (this.eventHandler) {
      await this.eventHandler.detachAll()
      this.debug.log('EventHandler detached from all VMs')
    }

    // Clear active VMs
    this.activeVMs.clear()

    // Disconnect Prisma if we own it
    if (!this.externalPrisma && this.prisma) {
      // If we created the Prisma client, we should disconnect it
      // For now, we always use external client so this won't run
    }

    this.initialized = false
    this.debug.log('Infinization shutdown complete')
  }

  /**
   * Checks if the system is initialized.
   */
  isInitialized (): boolean {
    return this.initialized
  }

  // ===========================================================================
  // VM Operations
  // ===========================================================================

  /**
   * Creates and starts a new VM.
   *
   * @param config - VM creation configuration
   * @returns VMCreateResult with all created resource details
   * @throws LifecycleError on failure
   */
  async createVM (config: VMCreateConfig): Promise<VMCreateResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(config.vmId, async () => {
      // Start the per-VM infinigpu device server BEFORE QEMU (which connects to
      // its socket at boot). Reaped if creation fails so we never leak the host
      // process or its broker admission ticket.
      if (config.gpu) {
        await this.startInfinigpuServer(config.vmId, config.gpu)
      }
      const lifecycle = this.createLifecycle()
      let result: VMCreateResult
      try {
        result = await lifecycle.create(config)
      } catch (err) {
        await this.reapInfinigpuServer(config.vmId)
        throw err
      }

      // Track the VM
      this.trackVM(result.vmId, {
        tapDevice: result.tapDevice,
        createdAt: new Date(),
        internalName: config.internalName
      })

      return result
    })
  }

  /**
   * Starts an existing VM.
   *
   * Reconstructs QEMU process from persisted configuration and starts the VM.
   *
   * @param vmId - VM identifier (database machine.id)
   * @param config - Optional start configuration
   * @returns VMOperationResult indicating success or failure
   */
  async startVM (vmId: string, config?: VMStartConfig): Promise<VMOperationResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(vmId, async () => {
      // Re-attach the GPU on every start (start reconstructs config from the DB,
      // which has no gpu field — the backend threads department policy here).
      if (config?.gpu) {
        await this.startInfinigpuServer(vmId, config.gpu)
      }
      const lifecycle = this.createLifecycle()
      let result: VMOperationResult
      try {
        result = await lifecycle.start(vmId, config)
      } catch (err) {
        await this.reapInfinigpuServer(vmId)
        throw err
      }

      if (result.success) {
        // Get internalName from DB for tracking
        const internalName = await this.prisma.getMachineInternalName(vmId)

        // Track or update the VM
        this.trackVM(vmId, {
          createdAt: new Date(),
          internalName: internalName ?? vmId
        })
      } else {
        // Clean (non-throwing) start failure — don't leak the device server.
        await this.reapInfinigpuServer(vmId)
      }

      return result
    })
  }

  /**
   * Stops a running VM.
   *
   * @param vmId - VM identifier
   * @param config - Stop configuration
   * @returns VMOperationResult indicating success or failure
   */
  async stopVM (vmId: string, config?: VMStopConfig): Promise<VMOperationResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(vmId, async () => {
      const lifecycle = this.createLifecycle()
      const result = await lifecycle.stop(vmId, config)

      if (result.success) {
        this.untrackVM(vmId)
        await this.reapInfinigpuServer(vmId)
      }

      return result
    })
  }

  /**
   * Destroys a VM and all its resources permanently.
   *
   * Use this when deleting a VM completely. This method:
   * 1. Stops the VM if running
   * 2. Destroys the TAP device permanently
   * 3. Removes the nftables firewall chain and all rules
   * 4. Clears machine configuration from database
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async destroyVM (vmId: string): Promise<VMOperationResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(vmId, async () => {
      const lifecycle = this.createLifecycle()
      const result = await lifecycle.destroyResources(vmId)

      if (result.success) {
        this.untrackVM(vmId)
        await this.reapInfinigpuServer(vmId)
      }

      return result
    })
  }

  // ===========================================================================
  // Department L2 overlay (07-networking.md §1) — OverlayRPC verbs.
  // These are per-node/per-department, NOT per-VM: the master computes each
  // department's segment + peer set and pushes it here (agents are told, they
  // don't read overlay rows from the DB). They serialize per-department inside
  // OverlayManager, so they take no vmLock.
  // ===========================================================================

  /**
   * Idempotently realize a department's node-spanning L2 segment on THIS host:
   * the `infinibr-<shortId>` bridge, the node-global `infiwg` WireGuard mesh, the
   * per-department `infivx-<shortId>` VXLAN netdev enslaved to that bridge, the
   * head-end-replication FDB, and — only on the gateway-owner node — the gateway
   * IP. All per-segment data (vni/mtu/peers/gatewayCidr) is master-pushed. Throws
   * on a host with no overlay identity (`InfinizationConfig.overlay`).
   */
  async ensureSegment (spec: OverlaySegmentSpec): Promise<void> {
    this.ensureInitialized()
    return this.overlay.ensureSegment(spec)
  }

  /**
   * Update a department's WireGuard peer set + FDB on this node (membership
   * fan-out when a node joins/leaves the department's mesh). The bridge name
   * resolves the department's VXLAN device deterministically.
   */
  async setPeers (deptId: string, bridgeName: string, peers: OverlayPeer[]): Promise<void> {
    this.ensureInitialized()
    return this.overlay.setPeers(deptId, bridgeName, peers)
  }

  /**
   * Remove this node's per-department VXLAN netdev when it no longer hosts any VM
   * of the department. Leaves the shared bridge (backend-owned) and node-global
   * WireGuard peers intact. Idempotent.
   */
  async destroySegment (deptId: string, bridgeName: string): Promise<void> {
    this.ensureInitialized()
    return this.overlay.destroySegment(deptId, bridgeName)
  }

  /**
   * Restarts a VM.
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async restartVM (vmId: string): Promise<VMOperationResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(vmId, () => this.createLifecycle().restart(vmId))
  }

  /**
   * Suspends a running VM.
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async suspendVM (vmId: string): Promise<VMOperationResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(vmId, () => this.createLifecycle().suspend(vmId))
  }

  /**
   * Resumes a suspended VM.
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async resumeVM (vmId: string): Promise<VMOperationResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(vmId, () => this.createLifecycle().resume(vmId))
  }

  /**
   * Resets a VM (hardware reset).
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async resetVM (vmId: string): Promise<VMOperationResult> {
    this.ensureInitialized()

    return this.vmLock.runExclusive(vmId, () => this.createLifecycle().reset(vmId))
  }

  /**
   * Gets detailed status of a VM.
   *
   * @param vmId - VM identifier
   * @returns VMStatusResult with detailed status information
   */
  async getVMStatus (vmId: string): Promise<VMStatusResult> {
    this.ensureInitialized()

    const lifecycle = this.createLifecycle()
    return lifecycle.getStatus(vmId)
  }

  // ===========================================================================
  // Resource Access
  // ===========================================================================

  /**
   * Gets the list of active VM IDs tracked by this instance.
   */
  getActiveVMs (): string[] {
    return Array.from(this.activeVMs.keys())
  }

  /**
   * Gets the HealthMonitor instance.
   */
  getHealthMonitor (): HealthMonitor {
    this.ensureInitialized()
    return this.healthMonitor
  }

  /**
   * Reconciles VMs stuck in transient states ('starting', 'powering_off_update',
   * 'rebuilding') after a backend/process crash. Call once at startup, AFTER
   * initialize() and BEFORE re-attaching to running VMs: VMs it promotes to
   * 'running' are then picked up by the backend's running-VM attach pass.
   */
  async reconcileStartupState (statuses?: string[]): Promise<ReconcileSummary> {
    this.ensureInitialized()
    return statuses
      ? this.healthMonitor.reconcileTransientStates(statuses)
      : this.healthMonitor.reconcileTransientStates()
  }

  /**
   * Gets the EventHandler instance.
   */
  getEventHandler (): EventHandler {
    this.ensureInitialized()
    return this.eventHandler
  }

  /**
   * Attaches to an already-running VM's QMP socket for event monitoring.
   *
   * Use this to re-attach to VMs that were running before the backend was restarted.
   * This connects to the QMP socket and subscribes to state change events.
   *
   * @param vmId - The VM identifier in the database
   * @param qmpSocketPath - Path to the VM's QMP Unix socket
   * @throws Error if connection fails or VM is not actually running
   */
  async attachToRunningVM (vmId: string, qmpSocketPath: string): Promise<void> {
    this.ensureInitialized()

    // Check if already attached
    if (this.eventHandler.isAttached(vmId)) {
      this.debug.log(`VM ${vmId} already attached, skipping`)
      return
    }

    this.debug.log(`Attaching to running VM ${vmId} via ${qmpSocketPath}`)

    const qmpClient = new QMPClient(qmpSocketPath)
    try {
      await qmpClient.connect()

      // Attach event listeners. If this throws AFTER connect() (e.g. listener
      // setup fails), the QMPClient holds a live socket + reconnect timer that
      // EventHandler never took ownership of — disconnect it so we don't leak a
      // dangling connection/timer on every failed attach.
      try {
        await this.eventHandler.attachToVM(vmId, qmpClient)
      } catch (attachError) {
        await qmpClient.disconnect().catch(() => { /* best-effort: already failing */ })
        throw attachError
      }

      // Track this VM (minimal resources - QMP client is managed by EventHandler)
      // We need internalName for proper tracking, but we only have vmId here
      // The EventHandler already tracks the QMP client
      this.activeVMs.set(vmId, {
        createdAt: new Date(),
        internalName: vmId // Use vmId as placeholder; actual internalName is in DB
      })

      this.debug.log(`Successfully attached to running VM ${vmId}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.debug.log('error', `Failed to attach to VM ${vmId}: ${message}`)
      throw error
    }
  }

  /**
   * Re-adopt a GPU VM's **surviving** infinigpu device server after a backend restart.
   *
   * The device is spawned detached (its own session, stdio to a file) and QEMU is
   * `-daemonize`d, so both keep running when the backend restarts — the guest's GPU never
   * drops. This re-takes ownership of the survivor (so a later stop reaps it) and returns the
   * infiniPixel port it is streaming on, which the caller uses to rebuild the host broker
   * ticket + console relay. Returns `undefined` when the VM has no GPU device or its device is
   * truly gone (no sidecar / dead pid) — nothing to re-adopt, and the display can only be
   * restored by a VM power-cycle. Idempotent: an already-tracked server just returns its port.
   */
  public async reattachInfinigpuServer (vmId: string): Promise<number | undefined> {
    this.ensureInitialized()
    const existing = this.infinigpuServers.get(vmId)
    if (existing) return existing.streamPixelPort

    const socketPath = path.join(this.qmpSocketDir, `${vmId}.gpu.sock`)
    const server = InfinigpuDeviceServer.adopt(
      socketPath,
      (_level, message) => this.debug.log(`[infinigpu ${vmId}] ${message}`)
    )
    if (!server) return undefined

    this.infinigpuServers.set(vmId, server)
    this.debug.log(`infinigpu device server re-adopted for VM ${vmId} (pixelPort ${server.streamPixelPort ?? '?'})`)
    return server.streamPixelPort
  }

  /**
   * Gets the active database facade (a PrismaAdapter on the master, or an
   * injected remote adapter on a compute-node agent).
   */
  getPrismaAdapter (): InfinizationDatabase {
    this.ensureInitialized()
    return this.prisma
  }

  /**
   * Gets the QMP client for a specific VM, if attached.
   * Returns undefined if the VM is not attached or the client is disconnected.
   *
   * @param vmId - The VM identifier in the database
   */
  public getQMPClient (vmId: string): QMPClient | undefined {
    return this.eventHandler.getQMPClient(vmId)
  }

  /**
   * Execute a command inside a running VM via the QEMU Guest Agent (QGA).
   *
   * QGA is a separate Unix socket from the QMP socket — `guest-exec` and
   * `guest-exec-status` are NOT QMP commands and must not be sent over the
   * QMP socket (QEMU rejects them as unknown).
   *
   * This method opens a transient `GuestAgentClient` against the VM's QGA
   * socket, runs the command, and disconnects. It does not cache the
   * connection because guest-exec is an infrequent operation.
   *
   * @param vmId - The VM identifier (used only for logging/tracing)
   * @param guestAgentSocketPath - Path to the VM's QEMU Guest Agent socket
   * @param command - Command to execute inside the guest
   * @param args - Optional command arguments
   * @param options - Optional execution options (timeout, cwd)
   * @returns stdout, stderr, and exit code
   * @throws Error if the guest agent is unreachable or the command times out
   */
  public async guestExec (
    vmId: string,
    guestAgentSocketPath: string,
    command: string,
    args?: string[],
    options?: { timeout?: number, cwd?: string }
  ): Promise<{ stdout: string, stderr: string, exitCode: number }> {
    this.ensureInitialized()
    this.debug.log(`Guest-exec on VM ${vmId}: ${command} ${(args ?? []).join(' ')}`)

    const client = new GuestAgentClient(guestAgentSocketPath)
    try {
      await client.connect()
      return await client.guestExec(command, args, options)
    } finally {
      await client.disconnect().catch((err) => {
        this.debug.log('warn', `Failed to disconnect QGA client for VM ${vmId}: ${err?.message ?? err}`)
      })
    }
  }

  /**
   * Gets the NftablesService instance.
   */
  getNftablesService (): NftablesService {
    this.ensureInitialized()
    return this.nftables
  }

  // ===========================================================================
  // Device Operations
  // ===========================================================================

  /**
   * Ejects a CD-ROM device from a running VM.
   *
   * @param vmId - The VM identifier
   * @param device - Device name (e.g., 'ide0-cd0', 'ide0-cd1', 'cdrom', 'cdrom2')
   * @param force - Whether to force ejection even if locked (default: true)
   * @throws LifecycleError if VM is not found or not running
   */
  async ejectCdrom (vmId: string, device: string, force = true): Promise<void> {
    this.ensureInitialized()

    const qmpClient = this.eventHandler.getQMPClient(vmId)
    if (!qmpClient) {
      throw new LifecycleError(
        LifecycleErrorCode.VM_NOT_FOUND,
        `VM ${vmId} not found or not running`
      )
    }

    this.debug.log(`Ejecting CD-ROM device ${device} from VM ${vmId}`)
    await qmpClient.eject(device, force)
    this.debug.log(`CD-ROM device ${device} ejected from VM ${vmId}`)
  }

  /**
   * Queries block devices from a running VM.
   *
   * @param vmId - The VM identifier
   * @returns Array of block device information
   * @throws LifecycleError if VM is not found or not running
   */
  async queryBlockDevices (vmId: string): Promise<QMPBlockInfo[]> {
    this.ensureInitialized()

    const qmpClient = this.eventHandler.getQMPClient(vmId)
    if (!qmpClient) {
      throw new LifecycleError(
        LifecycleErrorCode.VM_NOT_FOUND,
        `VM ${vmId} not found or not running`
      )
    }

    return qmpClient.queryBlock()
  }

  // ===========================================================================
  // Private Helpers
  // ===========================================================================

  /**
   * Ensures the system is initialized before operations.
   */
  private ensureInitialized (): void {
    if (!this.initialized) {
      throw new LifecycleError(
        LifecycleErrorCode.INVALID_STATE,
        'Infinization not initialized. Call initialize() first.'
      )
    }
  }

  /**
   * Creates a VMLifecycle instance with current dependencies.
   */
  private createLifecycle (): VMLifecycle {
    return new VMLifecycle(
      this.prisma,
      this.eventHandler,
      this.eventManager,
      {
        diskDir: this.diskDir,
        qmpSocketDir: this.qmpSocketDir,
        pidfileDir: this.pidfileDir
      }
    )
  }

  /**
   * Tracks a VM in the active VMs map.
   */
  private trackVM (vmId: string, resources: Omit<ActiveVMResources, 'createdAt'> & { createdAt?: Date }): void {
    this.activeVMs.set(vmId, {
      ...resources,
      createdAt: resources.createdAt ?? new Date()
    })
    this.debug.log(`Tracking VM: ${vmId}`)
  }

  /**
   * Removes a VM from the active VMs map.
   */
  private untrackVM (vmId: string): void {
    this.activeVMs.delete(vmId)
    this.debug.log(`Untracking VM: ${vmId}`)
  }

  /**
   * Start (or restart) the infinigpu device server for a GPU VM and stamp the
   * derived socket path onto `gpu` so buildQemuCommand + QEMU use it. Idempotent:
   * reaps any prior server for this vmId first. Must run inside vmLock.
   */
  private async startInfinigpuServer (vmId: string, gpu: InfinigpuVmOptions): Promise<void> {
    await this.reapInfinigpuServer(vmId)
    const socketPath = path.join(this.qmpSocketDir, `${vmId}.gpu.sock`)
    gpu.socketPath = socketPath
    const server = new InfinigpuDeviceServer({
      socketPath,
      vmId,
      pixelPort: gpu.pixelPort,
      log: (_level, message) => this.debug.log(`[infinigpu ${vmId}] ${message}`)
    })
    await server.start()
    this.infinigpuServers.set(vmId, server)
    this.debug.log(`infinigpu device server started for VM ${vmId} (${socketPath})`)
  }

  /**
   * Stop and forget the infinigpu device server for a VM (frees its broker
   * admission ticket + host process). Idempotent / safe when none exists.
   */
  private async reapInfinigpuServer (vmId: string): Promise<void> {
    const server = this.infinigpuServers.get(vmId)
    if (!server) return
    this.infinigpuServers.delete(vmId)
    try {
      await server.stop()
      this.debug.log(`infinigpu device server reaped for VM ${vmId}`)
    } catch (err) {
      this.debug.log(`infinigpu device server reap for VM ${vmId} errored: ${(err as Error).message}`)
    }
  }
}
