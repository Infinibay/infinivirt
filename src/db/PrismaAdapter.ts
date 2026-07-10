/**
 * Prisma Database Adapter
 *
 * This class provides a bridge between infinization and the PostgreSQL database via Prisma ORM.
 * It implements the DatabaseAdapter interface from sync.types.ts for compatibility with
 * StateSync, EventHandler, and HealthMonitor classes.
 *
 * @example
 * ```typescript
 * import { PrismaClient } from '@prisma/client'
 * import { PrismaAdapter } from '@infinibay/infinization'
 *
 * const prisma = new PrismaClient()
 * const adapter = new PrismaAdapter(prisma)
 *
 * // Use with sync module
 * const stateSync = new StateSync(adapter)
 * const healthMonitor = new HealthMonitor(adapter)
 * ```
 */

import { Debugger } from '../utils/debug'
import {
  DatabaseAdapter,
  MachineRecord,
  RunningVMRecord,
  MachineConfigurationRecord
} from '../types/sync.types'
import {
  PrismaAdapterError,
  PrismaAdapterErrorCode,
  MachineConfigUpdate,
  VMConfigRecord,
  FirewallRuleRecord,
  ExtendedMachineConfigurationRecord,
  DEFAULT_DISK_PATH_PREFIX,
  DEFAULT_DISK_EXTENSION
} from '../types/db.types'

// =============================================================================
// Minimal Prisma Interface Types
// =============================================================================

/**
 * Minimal machine record shape returned from Prisma queries.
 * Intentionally narrow to avoid coupling to the full Prisma schema.
 */
interface PrismaMachineRecord {
  id: string
  status: string
  name?: string
  nodeId?: string | null
  internalName?: string
  os?: string
  cpuCores?: number
  ramGB?: number
  diskSizeGB?: number
  gpuPciAddress?: string | null
  firewallRuleSetId?: string | null
  version?: number
  configuration?: PrismaMachineConfigurationRecord | null
  firewallRuleSet?: PrismaFirewallRuleSetRecord | null
  department?: PrismaDepartmentRecord | null
}

/**
 * Minimal machine configuration record shape.
 */
interface PrismaMachineConfigurationRecord {
  machineId: string
  qmpSocketPath: string | null
  qemuPid: number | null
  tapDeviceName: string | null
  graphicProtocol?: string | null
  graphicPort?: number | null
  graphicPassword?: string | null
  graphicHost?: string | null
  assignedGpuBus?: string | null
  // QEMU configuration fields
  bridge?: string | null
  machineType?: string | null
  cpuModel?: string | null
  diskBus?: string | null
  diskCacheMode?: string | null
  networkModel?: string | null
  networkQueues?: number | null
  memoryBalloon?: boolean | null
  // Multi-disk support
  diskPaths?: unknown | null // JSON field from Prisma
  // UEFI firmware configuration
  uefiFirmware?: string | null
  // Hugepages configuration
  hugepages?: boolean | null
  // CPU pinning configuration
  cpuPinning?: unknown | null // JSON field from Prisma
  // NUMA-aware CPU pinning via numactl
  enableNumaCtlPinning?: boolean | null
  cpuPinningStrategy?: string | null
  // Advanced device configuration
  tpmSocketPath?: string | null
  virtioDriversIso?: string | null
  enableAudio?: boolean | null
  enableUsbTablet?: boolean | null
  // Socket paths for guest agent and infini service
  guestAgentSocketPath?: string | null
  infiniServiceSocketPath?: string | null
}

/**
 * Minimal firewall rule set record shape.
 */
interface PrismaFirewallRuleSetRecord {
  id: string
  name: string
  internalName: string
  priority: number
  isActive: boolean
  rules?: PrismaFirewallRuleRecord[]
}

/**
 * Minimal firewall rule record shape.
 */
interface PrismaFirewallRuleRecord {
  id: string
  name: string
  description: string | null
  action: string
  direction: string
  priority: number
  protocol: string
  srcPortStart: number | null
  srcPortEnd: number | null
  dstPortStart: number | null
  dstPortEnd: number | null
  srcIpAddr: string | null
  srcIpMask: string | null
  dstIpAddr: string | null
  dstIpMask: string | null
  connectionState: Record<string, boolean> | null
  overridesDept: boolean
}

/**
 * Minimal department record shape.
 */
interface PrismaDepartmentRecord {
  id: string
  name: string
  firewallRuleSet?: PrismaFirewallRuleSetRecord | null
}

/**
 * Minimal PrismaClient interface.
 * This avoids a hard dependency on @prisma/client types while ensuring type safety.
 * The actual PrismaClient from the backend will satisfy this interface.
 */
export interface PrismaClientLike {
  machine: {
    findUnique: (args: {
      where: { id: string }
      select?: Record<string, unknown>
      include?: Record<string, unknown>
    }) => Promise<PrismaMachineRecord | null>
    findFirst: (args: {
      where: Record<string, unknown>
      select?: Record<string, unknown>
      include?: Record<string, unknown>
    }) => Promise<PrismaMachineRecord | null>
    findMany: (args: {
      where?: Record<string, unknown>
      select?: Record<string, unknown>
      include?: Record<string, unknown>
    }) => Promise<PrismaMachineRecord[]>
    update: (args: {
      where: { id: string }
      data: Record<string, unknown>
    }) => Promise<PrismaMachineRecord>
    updateMany: (args: {
      where: Record<string, unknown>
      data: Record<string, unknown>
    }) => Promise<{ count: number }>
  }
  machineConfiguration: {
    upsert: (args: {
      where: { machineId: string }
      create: Record<string, unknown>
      update: Record<string, unknown>
    }) => Promise<PrismaMachineConfigurationRecord>
    updateMany: (args: {
      where: Record<string, unknown>
      data: Record<string, unknown>
    }) => Promise<{ count: number }>
  }
  $transaction: <T>(fn: (tx: PrismaClientLike) => Promise<T>) => Promise<T>
}

// =============================================================================
// Shared configuration select
// =============================================================================

/**
 * SINGLE SOURCE OF TRUTH for the machineConfiguration `select` used by
 * findMachineWithConfig and transitionVMStatus. Previously this literal was
 * duplicated in two places and the two copies could silently drift — dropping a
 * column from one (but not the other) re-introduced the just-fixed
 * TPM/guest-agent/virtio/NUMA data-loss bug with NO compile error.
 *
 * Two safeguards now make that data loss a COMPILE error instead:
 *  1. The `satisfies` clause below requires every key of
 *     `PrismaMachineConfigurationRecord` to be present and set to `true`. Remove
 *     any column here and the `satisfies` check fails to type-check.
 *  2. mapToExtendedMachineConfiguration reads these columns with direct typed
 *     property access (no `as unknown` casts), so a missing field in the record
 *     interface also fails to compile.
 *
 * `as const` preserves the literal `true` types so both protections hold.
 */
const MACHINE_CONFIG_SELECT = {
  machineId: true,
  qemuPid: true,
  tapDeviceName: true,
  qmpSocketPath: true,
  graphicProtocol: true,
  graphicPort: true,
  graphicPassword: true,
  graphicHost: true,
  assignedGpuBus: true,
  // QEMU configuration fields
  bridge: true,
  machineType: true,
  cpuModel: true,
  diskBus: true,
  diskCacheMode: true,
  networkModel: true,
  networkQueues: true,
  memoryBalloon: true,
  // Multi-disk support
  diskPaths: true,
  // UEFI firmware configuration
  uefiFirmware: true,
  // Hugepages configuration
  hugepages: true,
  // CPU pinning configuration
  cpuPinning: true,
  // NUMA-aware CPU pinning via numactl
  enableNumaCtlPinning: true,
  cpuPinningStrategy: true,
  // Advanced devices / sockets — previously OMITTED from these selects, which
  // made mapToExtendedMachineConfiguration read them as null on every start,
  // silently dropping a VM's TPM (Win11), guest-agent, virtio drivers, audio,
  // USB tablet and NUMA-pinning config.
  tpmSocketPath: true,
  guestAgentSocketPath: true,
  infiniServiceSocketPath: true,
  virtioDriversIso: true,
  enableAudio: true,
  enableUsbTablet: true
} as const satisfies Record<keyof PrismaMachineConfigurationRecord, true>

/**
 * Shared configuration `select` for the lightweight RunningVMRecord queries
 * (findRunningVMs, findMachinesByStatuses, findMachineByInternalName). These
 * only need the subset of fields that map to MachineConfigurationRecord.
 */
const RUNNING_VM_CONFIG_SELECT = {
  qemuPid: true,
  tapDeviceName: true,
  qmpSocketPath: true,
  guestAgentSocketPath: true,
  infiniServiceSocketPath: true
} as const

// =============================================================================
// PrismaAdapter Class
// =============================================================================

/**
 * PrismaAdapter implements DatabaseAdapter for Prisma ORM.
 *
 * This adapter provides:
 * - Basic CRUD operations required by the DatabaseAdapter interface
 * - Extended methods for VM configuration management
 * - Firewall rule retrieval with department inheritance
 */
export class PrismaAdapter implements DatabaseAdapter {
  private readonly debug: Debugger

  /**
   * Creates a new PrismaAdapter instance.
   *
   * @param prisma - PrismaClient instance from the backend application
   */
  constructor (
    private readonly prisma: PrismaClientLike,
    /**
     * Optional node identity (the owning `Node.id` for this host). When set, the
     * ENUMERATION / orphan-mapping reads — `findRunningVMs`,
     * `findMachinesByStatuses` and `findMachineByInternalName` — are scoped to
     * `Machine.nodeId === nodeId`, so this host's HealthMonitor crash-detect,
     * startup reconcile and orphan reaper only ever see/act on VMs assigned to
     * THIS node.
     *
     * This is the structural G0 fix: those three reads drive destructive actions
     * (mark-off / promote / SIGKILL-orphan) keyed on the LOCAL `/proc`. Without
     * node scoping, two backends/agents sharing one Postgres each enumerate the
     * OTHER node's running VMs, find their PIDs absent locally, and cross-kill
     * them (status corruption + orphan reaping). Omit `nodeId` (single-host) to
     * preserve the original host-agnostic behaviour bit-for-bit.
     *
     * NOTE: id-targeted reads (`findMachine`, `findMachineWithConfig`) are NOT
     * scoped — a caller that already holds a specific `vmId` owns that VM.
     */
    private readonly nodeId?: string
  ) {
    this.debug = new Debugger('prisma-adapter')
    this.debug.log(`PrismaAdapter initialized${this.nodeId ? ` (node-scoped: ${this.nodeId})` : ''}`)
  }

  /**
   * Builds the node-scope fragment merged into enumeration `where` clauses.
   * Returns `{ nodeId }` when this adapter is node-scoped, otherwise `{}` so the
   * query is unchanged for single-host deployments.
   */
  private nodeScope (): Record<string, unknown> {
    return this.nodeId ? { nodeId: this.nodeId } : {}
  }

  // ===========================================================================
  // DatabaseAdapter Interface Implementation
  // ===========================================================================

  /**
   * Find a machine by ID.
   *
   * @param id - Machine UUID
   * @returns Machine record with id and status, or null if not found
   */
  async findMachine (id: string): Promise<MachineRecord | null> {
    this.debug.log(`findMachine: ${id}`)

    try {
      const machine = await this.prisma.machine.findUnique({
        where: { id },
        select: { id: true, status: true }
      })

      if (!machine) {
        this.debug.log('info', `Machine not found: ${id}`)
        return null
      }

      return {
        id: machine.id,
        status: machine.status
      }
    } catch (error) {
      this.debug.log('error', `findMachine failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to find machine: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        id,
        error
      )
    }
  }


  /**
   * Find a machine by its internal name.
   * Used by orphan process detection to map pidfile names back to VM records.
   *
   * @param internalName - The internal VM name (derived from pidfile name)
   * @returns RunningVMRecord with configuration, or null if not found
   */
  async findMachineByInternalName (internalName: string): Promise<RunningVMRecord | null> {
    this.debug.log(`findMachineByInternalName: ${internalName}`)

    try {
      // Node-scoped: a LOCAL pidfile maps to one of THIS node's VMs. A record owned
      // by another node must read as "not mine" so the orphan scanner does not reap a
      // process the local DB view cannot account for — EXCEPT a VM that is
      // mid-migration (status 'moving'). During a cross-node move the row's `nodeId`
      // still points at the source while the QEMU may already exist on the
      // destination, so a strictly node-scoped read returns null and would authorize a
      // kill of a legitimately-migrating VM. Surfacing moving VMs regardless of owner
      // lets checkOrphanProcesses recognise and skip them (they are owned by the
      // master migration flow); killOrphan still verifies /proc identity, so nothing
      // else widens. We key on `status:'moving'` (the migration flow's real marker),
      // NOT `migrationJobId` (never written). Single-host (no nodeId) is unchanged.
      const where = this.nodeId
        ? { internalName, OR: [{ nodeId: this.nodeId }, { status: 'moving' }] }
        : { internalName }
      const machine = await this.prisma.machine.findFirst({
        where,
        include: {
          configuration: {
            select: RUNNING_VM_CONFIG_SELECT
          }
        }
      })

      if (!machine) {
        this.debug.log('info', `Machine not found by internalName: ${internalName}`)
        return null
      }

      // A FOREIGN row can only have surfaced because it is 'moving' (the OR branch).
      // Do not hand back another node's qemuPid/socket paths — the orphan scanner
      // only needs `status` to skip it, and over the /cluster/db RPC this would be
      // cross-node info disclosure. Null the config for rows this node does not own.
      const foreign = this.nodeId != null && machine.nodeId != null && machine.nodeId !== this.nodeId
      return {
        id: machine.id,
        status: machine.status,
        // We queried by this exact internalName, so it is non-null here; fall
        // back to the queried value if Prisma did not echo the column.
        internalName: machine.internalName ?? internalName,
        MachineConfiguration: (!foreign && machine.configuration)
          ? {
              qemuPid: machine.configuration.qemuPid,
              tapDeviceName: machine.configuration.tapDeviceName,
              qmpSocketPath: machine.configuration.qmpSocketPath,
              guestAgentSocketPath: machine.configuration.guestAgentSocketPath ?? null,
              infiniServiceSocketPath: machine.configuration.infiniServiceSocketPath ?? null
            }
          : null
      }
    } catch (error) {
      // Fail CLOSED: a DB outage must NOT be collapsed into the same `null` that
      // means "VM not found". The orphan scanner kills processes that map to no DB
      // record; if a transient DB error returned null here, the scanner would
      // SIGKILL a live VM's QEMU (as root) on every blip. Re-throw so callers
      // treat it as "unknown — do not kill" and re-scan next cycle.
      this.debug.log('error', `findMachineByInternalName failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to query machine by internalName '${internalName}': ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        undefined,
        error
      )
    }
  }

  /**
   * Update machine status.
   *
   * Uses updateMany instead of update to be idempotent - if the machine
   * doesn't exist (e.g., deleted during shutdown), the operation succeeds
   * with no-op instead of throwing an error. This prevents race conditions
   * during VM shutdown where multiple events may try to update a deleted machine.
   *
   * @param id - Machine UUID
   * @param status - New status value
   * @throws PrismaAdapterError if update fails (not for missing records)
   */
  async updateMachineStatus (id: string, status: string, opts?: { onlyIfNotIn?: string[] }): Promise<void> {
    this.debug.log(`updateMachineStatus: ${id} -> ${status}`)

    try {
      // onlyIfNotIn folds the status guard INTO the WHERE clause so the check and
      // the write are one atomic statement — no read-then-write TOCTOU. A count of
      // 0 then means the row was in a guarded state (or gone), not a hard error.
      const where = (opts?.onlyIfNotIn && opts.onlyIfNotIn.length > 0)
        ? { id, status: { notIn: opts.onlyIfNotIn } }
        : { id }
      const result = await this.prisma.machine.updateMany({
        where,
        data: { status }
      })

      if (result.count === 0) {
        if (opts?.onlyIfNotIn && opts.onlyIfNotIn.length > 0) {
          this.debug.log('info', `Skipped status update ${id} -> ${status}: row is missing or in a guarded state (${opts.onlyIfNotIn.join(', ')})`)
          return
        }
        this.debug.log('warn', `Machine not found for status update: ${id} (may have been deleted)`)
        return
      }

      this.debug.log('info', `Status updated successfully: ${id} -> ${status}`)
    } catch (error) {
      this.debug.log('error', `updateMachineStatus failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to update machine status: ${String(error)}`,
        PrismaAdapterErrorCode.UPDATE_FAILED,
        id,
        error
      )
    }
  }

  /**
   * Find all VMs with 'running' status including their configuration.
   *
   * @returns Array of running VM records with configuration data
   */
  async findRunningVMs (): Promise<RunningVMRecord[]> {
    this.debug.log('findRunningVMs')

    try {
      const machines = await this.prisma.machine.findMany({
        // Node-scoped (G0): crash-detection marks a DB-'running' VM 'off' when its
        // PID is absent from the LOCAL /proc. Enumerating another node's running
        // VMs here would mark them all crashed. See constructor doc.
        where: { status: 'running', ...this.nodeScope() },
        include: {
          configuration: {
            select: RUNNING_VM_CONFIG_SELECT
          }
        }
      })

      this.debug.log('info', `Found ${machines.length} running VMs`)

      return machines.map(machine => ({
        id: machine.id,
        status: machine.status,
        internalName: machine.internalName ?? '',
        MachineConfiguration: machine.configuration
          ? {
              qemuPid: machine.configuration.qemuPid,
              tapDeviceName: machine.configuration.tapDeviceName,
              qmpSocketPath: machine.configuration.qmpSocketPath,
              guestAgentSocketPath: machine.configuration.guestAgentSocketPath ?? null,
              infiniServiceSocketPath: machine.configuration.infiniServiceSocketPath ?? null
            }
          : null
      }))
    } catch (error) {
      this.debug.log('error', `findRunningVMs failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to find running VMs: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        undefined,
        error
      )
    }
  }

  /**
   * Find all VMs whose status is in the given list, including configuration.
   * Used by startup reconciliation to locate VMs stuck in transient states.
   */
  async findMachinesByStatuses (statuses: string[]): Promise<RunningVMRecord[]> {
    this.debug.log(`findMachinesByStatuses: [${statuses.join(', ')}]`)
    try {
      const machines = await this.prisma.machine.findMany({
        // Node-scoped (G0): startup reconcile promotes transient-state VMs to
        // 'running' when their PID is alive in the LOCAL /proc; it must not
        // reconcile another node's transient VMs against this host's processes.
        where: { status: { in: statuses }, ...this.nodeScope() },
        include: {
          configuration: {
            select: RUNNING_VM_CONFIG_SELECT
          }
        }
      })

      this.debug.log('info', `Found ${machines.length} VM(s) in statuses [${statuses.join(', ')}]`)

      return machines.map(machine => ({
        id: machine.id,
        status: machine.status,
        internalName: machine.internalName ?? '',
        MachineConfiguration: machine.configuration
          ? {
              qemuPid: machine.configuration.qemuPid,
              tapDeviceName: machine.configuration.tapDeviceName,
              qmpSocketPath: machine.configuration.qmpSocketPath,
              guestAgentSocketPath: machine.configuration.guestAgentSocketPath ?? null,
              infiniServiceSocketPath: machine.configuration.infiniServiceSocketPath ?? null
            }
          : null
      }))
    } catch (error) {
      this.debug.log('error', `findMachinesByStatuses failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to find machines by statuses: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        undefined,
        error
      )
    }
  }

  /**
   * Clear machine configuration (qemuPid, tapDeviceName, qmpSocketPath).
   * Used during crash cleanup or full VM deletion.
   *
   * @param machineId - Machine UUID
   */
  async clearMachineConfiguration (machineId: string): Promise<void> {
    this.debug.log(`clearMachineConfiguration: ${machineId}`)

    try {
      await this.prisma.machineConfiguration.updateMany({
        where: { machineId },
        data: {
          qemuPid: null,
          tapDeviceName: null,
          qmpSocketPath: null
        }
      })

      this.debug.log('info', `Configuration cleared: ${machineId}`)
    } catch (error) {
      this.debug.log('error', `clearMachineConfiguration failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to clear machine configuration: ${String(error)}`,
        PrismaAdapterErrorCode.UPDATE_FAILED,
        machineId,
        error
      )
    }
  }

  /**
   * Clear only volatile machine configuration (qemuPid, qmpSocketPath).
   * Preserves tapDeviceName for persistent TAP device reuse across stop/start cycles.
   * Used during normal VM stop (not crash cleanup or deletion).
   *
   * @param machineId - Machine UUID
   */
  async clearVolatileMachineConfiguration (machineId: string): Promise<void> {
    this.debug.log(`clearVolatileMachineConfiguration: ${machineId}`)

    try {
      await this.prisma.machineConfiguration.updateMany({
        where: { machineId },
        data: {
          qemuPid: null,
          qmpSocketPath: null
          // Note: tapDeviceName is preserved for persistent TAP device reuse
        }
      })

      this.debug.log('info', `Volatile configuration cleared (TAP preserved): ${machineId}`)
    } catch (error) {
      this.debug.log('error', `clearVolatileMachineConfiguration failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to clear volatile machine configuration: ${String(error)}`,
        PrismaAdapterErrorCode.UPDATE_FAILED,
        machineId,
        error
      )
    }
  }

  // ===========================================================================
  // Extended VM Configuration Methods
  // ===========================================================================

  /**
   * Find a machine with full configuration includes.
   * Includes configuration, firewall rules, and department with inherited rules.
   *
   * @param id - Machine UUID
   * @returns Full VM configuration record or null if not found
   */
  async findMachineWithConfig (id: string): Promise<VMConfigRecord | null> {
    this.debug.log(`findMachineWithConfig: ${id}`)

    try {
      const machine = await this.prisma.machine.findUnique({
        where: { id },
        include: {
          configuration: {
            select: MACHINE_CONFIG_SELECT
          },
          firewallRuleSet: {
            include: {
              rules: true
            }
          },
          department: {
            include: {
              firewallRuleSet: {
                include: {
                  rules: true
                }
              }
            }
          }
        }
      })

      if (!machine) {
        this.debug.log('info', `Machine not found: ${id}`)
        return null
      }

      return this.mapToVMConfigRecord(machine)
    } catch (error) {
      this.debug.log('error', `findMachineWithConfig failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to find machine with config: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        id,
        error
      )
    }
  }

  /**
   * Update or create machine configuration.
   * Uses upsert to handle both creation and update scenarios.
   *
   * @param machineId - Machine UUID
   * @param config - Configuration fields to update
   */
  async updateMachineConfiguration (
    machineId: string,
    config: Partial<MachineConfigUpdate>
  ): Promise<void> {
    this.debug.log(`updateMachineConfiguration: ${machineId}`)

    if (!machineId) {
      throw new PrismaAdapterError(
        'Machine ID is required',
        PrismaAdapterErrorCode.INVALID_INPUT,
        machineId
      )
    }

    try {
      const data = {
        machineId,
        ...config
      }

      await this.prisma.machineConfiguration.upsert({
        where: { machineId },
        create: data,
        update: config
      })

      this.debug.log('info', `Configuration updated: ${machineId}`)
    } catch (error) {
      this.debug.log('error', `updateMachineConfiguration failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to update machine configuration: ${String(error)}`,
        PrismaAdapterErrorCode.UPDATE_FAILED,
        machineId,
        error
      )
    }
  }

  /**
   * Atomically transition VM status with optimistic locking.
   *
   * Uses Prisma transaction with version checking to prevent race conditions
   * when multiple processes attempt to start the same VM simultaneously.
   * This prevents duplicate QEMU processes from being spawned.
   *
   * @param machineId - Machine UUID
   * @param expectedStatus - Status the VM must be in to proceed (e.g., 'off')
   * @param newStatus - Status to transition to (e.g., 'starting')
   * @param expectedVersion - Version number that must match current version
   * @returns Object with success status, new version, and VM config if successful
   * @throws PrismaAdapterError with VERSION_CONFLICT if version mismatch
   * @throws PrismaAdapterError with UPDATE_FAILED if status doesn't match expected
   */
  async transitionVMStatus (
    machineId: string,
    expectedStatus: string,
    newStatus: string,
    expectedVersion: number
  ): Promise<{ success: boolean; newVersion: number; vmConfig: VMConfigRecord }> {
    this.debug.log(`transitionVMStatus: ${machineId} (${expectedStatus} -> ${newStatus}, version: ${expectedVersion})`)

    const MAX_TX_ATTEMPTS = 3
    for (let attempt = 1; ; attempt++) {
    try {
      return await this.prisma.$transaction(async (tx) => {
        // Fetch current VM state within the transaction
        const machine = await tx.machine.findUnique({
          where: { id: machineId },
          include: {
            configuration: {
              select: MACHINE_CONFIG_SELECT
            },
            firewallRuleSet: {
              include: {
                rules: true
              }
            },
            department: {
              include: {
                firewallRuleSet: {
                  include: {
                    rules: true
                  }
                }
              }
            }
          }
        })

        if (!machine) {
          throw new PrismaAdapterError(
            `Machine not found: ${machineId}`,
            PrismaAdapterErrorCode.MACHINE_NOT_FOUND,
            machineId
          )
        }

        // Check version matches (optimistic lock)
        const currentVersion = machine.version ?? 1
        if (currentVersion !== expectedVersion) {
          throw new PrismaAdapterError(
            `Version conflict: expected ${expectedVersion}, found ${currentVersion}. Another process may have modified this VM.`,
            PrismaAdapterErrorCode.VERSION_CONFLICT,
            machineId,
            { expectedVersion, currentVersion }
          )
        }

        // Check current status matches expected
        if (machine.status !== expectedStatus) {
          throw new PrismaAdapterError(
            `Status conflict: expected '${expectedStatus}', found '${machine.status}'. VM may already be ${machine.status}.`,
            PrismaAdapterErrorCode.UPDATE_FAILED,
            machineId,
            { expectedStatus, currentStatus: machine.status }
          )
        }

        // Atomically update status and increment version
        const newVersion = currentVersion + 1
        const result = await tx.machine.updateMany({
          where: {
            id: machineId,
            status: expectedStatus,
            version: expectedVersion
          },
          data: {
            status: newStatus,
            version: newVersion
          }
        })

        // If no rows were updated, another process beat us to it
        if (result.count === 0) {
          throw new PrismaAdapterError(
            `Failed to transition VM status: concurrent modification detected`,
            PrismaAdapterErrorCode.VERSION_CONFLICT,
            machineId,
            { expectedStatus, expectedVersion }
          )
        }

        this.debug.log('info', `VM status transitioned: ${machineId} (${expectedStatus} -> ${newStatus}, version: ${currentVersion} -> ${newVersion})`)

        // Return the VM config with the new version
        const vmConfig = this.mapToVMConfigRecord(machine)
        vmConfig.status = newStatus
        vmConfig.version = newVersion

        return {
          success: true,
          newVersion,
          vmConfig
        }
      })
    } catch (error) {
      if (error instanceof PrismaAdapterError) {
        throw error
      }
      // Retry a serialization failure / deadlock (P2034) — it is transient.
      if (this.isRetryablePrismaError(error) && attempt < MAX_TX_ATTEMPTS) {
        this.debug.log('warn', `transitionVMStatus serialization/deadlock on attempt ${attempt}/${MAX_TX_ATTEMPTS}; retrying`)
        continue
      }
      this.debug.log('error', `transitionVMStatus failed: ${String(error)}`)
      throw this.mapPrismaError(error, machineId, 'Failed to transition VM status')
    }
    }
  }

  /** True if a Prisma error is a transient, retryable transaction conflict. */
  private isRetryablePrismaError (error: unknown): boolean {
    const code = (error as { code?: string })?.code
    // P2034: "Transaction failed due to a write conflict or a deadlock".
    return code === 'P2034'
  }


  /**
   * Maps a raw Prisma error to a PrismaAdapterError, PRESERVING the original
   * Prisma code (P2002/P2025/P2034/...) in `details` instead of flattening it to
   * a string, so callers can classify and retry instead of treating every failure
   * as a permanent UPDATE_FAILED.
   */
  private mapPrismaError (error: unknown, vmId: string, context: string): PrismaAdapterError {
    const code = (error as { code?: string })?.code
    let mapped: PrismaAdapterErrorCode
    switch (code) {
      case 'P2002': mapped = PrismaAdapterErrorCode.CONSTRAINT_VIOLATION; break
      case 'P2025': mapped = PrismaAdapterErrorCode.MACHINE_NOT_FOUND; break
      case 'P2034': mapped = PrismaAdapterErrorCode.UPDATE_FAILED; break
      default: mapped = PrismaAdapterErrorCode.UPDATE_FAILED
    }
    return new PrismaAdapterError(
      `${context}: ${String(error)}`,
      mapped,
      vmId,
      { prismaCode: code, cause: error }
    )
  }

  // ===========================================================================
  // Firewall Rule Methods
  // ===========================================================================

  /**
   * Get all firewall rules for a VM, including inherited department rules.
   * Rules are sorted by priority (lower number = higher priority).
   * Department rules are applied first, then VM-specific rules.
   *
   * @param vmId - Machine UUID
   * @returns Array of firewall rules sorted by priority
   */
  async getFirewallRules (vmId: string): Promise<FirewallRuleRecord[]> {
    this.debug.log(`getFirewallRules: ${vmId}`)

    try {
      const machine = await this.prisma.machine.findUnique({
        where: { id: vmId },
        include: {
          firewallRuleSet: {
            include: {
              rules: true
            }
          },
          department: {
            include: {
              firewallRuleSet: {
                include: {
                  rules: true
                }
              }
            }
          }
        }
      })

      if (!machine) {
        throw new PrismaAdapterError(
          `Machine not found: ${vmId}`,
          PrismaAdapterErrorCode.MACHINE_NOT_FOUND,
          vmId
        )
      }

      const rules: FirewallRuleRecord[] = []

      // Add department rules first (if department has a firewall rule set)
      if (machine.department?.firewallRuleSet?.rules) {
        rules.push(...machine.department.firewallRuleSet.rules.map(r => this.mapToFirewallRuleRecord(r)))
      }

      // Add VM-specific rules
      if (machine.firewallRuleSet?.rules) {
        rules.push(...machine.firewallRuleSet.rules.map(r => this.mapToFirewallRuleRecord(r)))
      }

      // Sort by priority (lower number = higher priority)
      rules.sort((a, b) => a.priority - b.priority)

      this.debug.log('info', `Found ${rules.length} firewall rules for VM ${vmId}`)

      return rules
    } catch (error) {
      if (error instanceof PrismaAdapterError) {
        throw error
      }
      this.debug.log('error', `getFirewallRules failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to get firewall rules: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        vmId,
        error
      )
    }
  }

  /**
   * Returns the VM's firewall rules split by source: department-inherited rules
   * and VM-specific rules, kept separate (NOT merged/sorted). This is the
   * source-aware variant of {@link getFirewallRules}: callers that need the
   * terminal-posture merge with override semantics should pass the two arrays to
   * `NftablesService.mergeRules` (which honours `overridesDept`).
   *
   * Both arrays are returned unsorted by priority here; the merge/sort happens
   * downstream in NftablesService.
   *
   * Fail-closed: on a real DB error this throws (same as getFirewallRules) so a
   * VM is never brought up unfiltered.
   *
   * @param vmId - Machine UUID
   * @returns Department and VM rule arrays
   */
  async getFirewallRulesSplit (vmId: string): Promise<{
    departmentRules: FirewallRuleRecord[]
    vmRules: FirewallRuleRecord[]
  }> {
    this.debug.log(`getFirewallRulesSplit: ${vmId}`)

    try {
      const machine = await this.prisma.machine.findUnique({
        where: { id: vmId },
        include: {
          firewallRuleSet: {
            include: {
              rules: true
            }
          },
          department: {
            include: {
              firewallRuleSet: {
                include: {
                  rules: true
                }
              }
            }
          }
        }
      })

      if (!machine) {
        throw new PrismaAdapterError(
          `Machine not found: ${vmId}`,
          PrismaAdapterErrorCode.MACHINE_NOT_FOUND,
          vmId
        )
      }

      const departmentRules: FirewallRuleRecord[] =
        machine.department?.firewallRuleSet?.rules
          ? machine.department.firewallRuleSet.rules.map(r => this.mapToFirewallRuleRecord(r))
          : []

      const vmRules: FirewallRuleRecord[] =
        machine.firewallRuleSet?.rules
          ? machine.firewallRuleSet.rules.map(r => this.mapToFirewallRuleRecord(r))
          : []

      this.debug.log(
        'info',
        `Split firewall rules for VM ${vmId}: ${departmentRules.length} dept + ${vmRules.length} VM`
      )

      return { departmentRules, vmRules }
    } catch (error) {
      if (error instanceof PrismaAdapterError) {
        throw error
      }
      this.debug.log('error', `getFirewallRulesSplit failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to get split firewall rules: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        vmId,
        error
      )
    }
  }

  /**
   * Returns the VM's department firewall policy ('ALLOW_ALL' | 'BLOCK_ALL'), or
   * null if the VM has no department / the field is unavailable. Used to derive
   * the terminal nft posture: BLOCK_ALL => 'drop' (fail-closed), ALLOW_ALL =>
   * 'accept'. Without this, an ALLOW_ALL department's VMs would boot with the
   * fail-closed 'drop' default and be silently over-blocked.
   *
   * Fail-closed: on a real DB error this throws (like getFirewallRules) so the
   * caller aborts rather than guessing a posture.
   */
  async getDepartmentFirewallPolicy (vmId: string): Promise<string | null> {
    this.debug.log(`getDepartmentFirewallPolicy: ${vmId}`)
    try {
      const machine = await this.prisma.machine.findUnique({
        where: { id: vmId },
        include: { department: { select: { firewallPolicy: true } } }
      })
      const policy = (machine?.department as { firewallPolicy?: string } | null | undefined)?.firewallPolicy
      return policy ?? null
    } catch (error) {
      this.debug.log('error', `getDepartmentFirewallPolicy failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to get department firewall policy: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        vmId,
        error
      )
    }
  }

  /**
   * Get the firewall rule set ID for a VM.
   *
   * @param vmId - Machine UUID
   * @returns FirewallRuleSet ID or null if none assigned
   */
  async getFirewallRuleSetId (vmId: string): Promise<string | null> {
    this.debug.log(`getFirewallRuleSetId: ${vmId}`)

    try {
      const machine = await this.prisma.machine.findUnique({
        where: { id: vmId },
        select: { firewallRuleSetId: true }
      })

      if (!machine) {
        return null
      }

      return machine.firewallRuleSetId ?? null
    } catch (error) {
      this.debug.log('error', `getFirewallRuleSetId failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to get firewall rule set ID: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        vmId,
        error
      )
    }
  }

  // ===========================================================================
  // Helper Methods
  // ===========================================================================

  /**
   * Get the internal name of a machine.
   * The internal name is used for generating TAP device names and other identifiers.
   *
   * @param id - Machine UUID
   * @returns Internal name or null if machine not found
   */
  async getMachineInternalName (id: string): Promise<string | null> {
    this.debug.log(`getMachineInternalName: ${id}`)

    try {
      const machine = await this.prisma.machine.findUnique({
        where: { id },
        select: { internalName: true }
      })

      if (!machine) {
        return null
      }

      return machine.internalName ?? null
    } catch (error) {
      this.debug.log('error', `getMachineInternalName failed: ${String(error)}`)
      throw new PrismaAdapterError(
        `Failed to get machine internal name: ${String(error)}`,
        PrismaAdapterErrorCode.QUERY_FAILED,
        id,
        error
      )
    }
  }

  /**
   * Get the disk path for a machine based on its internal name.
   *
   * @param id - Machine UUID
   * @returns Full disk path or null if machine not found
   */
  async getMachineDiskPath (id: string): Promise<string | null> {
    const internalName = await this.getMachineInternalName(id)

    if (!internalName) {
      return null
    }

    return `${DEFAULT_DISK_PATH_PREFIX}/${internalName}${DEFAULT_DISK_EXTENSION}`
  }

  // ===========================================================================
  // Private Mapping Methods
  // ===========================================================================

  /**
   * Map a raw Prisma machine configuration to ExtendedMachineConfigurationRecord.
   * Ensures all fields from MachineConfigurationRecord are populated.
   */
  private mapToExtendedMachineConfiguration (
    config: PrismaMachineConfigurationRecord
  ): ExtendedMachineConfigurationRecord {
    return {
      // Base MachineConfigurationRecord fields
      qmpSocketPath: config.qmpSocketPath,
      qemuPid: config.qemuPid,
      tapDeviceName: config.tapDeviceName,
      // Extended fields
      graphicProtocol: config.graphicProtocol ?? null,
      graphicPort: config.graphicPort ?? null,
      graphicPassword: config.graphicPassword ?? null,
      graphicHost: config.graphicHost ?? null,
      assignedGpuBus: config.assignedGpuBus ?? null,
      // QEMU configuration fields
      bridge: config.bridge ?? null,
      machineType: config.machineType ?? null,
      cpuModel: config.cpuModel ?? null,
      diskBus: config.diskBus ?? null,
      diskCacheMode: config.diskCacheMode ?? null,
      networkModel: config.networkModel ?? null,
      networkQueues: config.networkQueues ?? null,
      memoryBalloon: config.memoryBalloon ?? null,
      // Multi-disk support — fail-closed on a corrupt blob (see parseDiskPaths).
      diskPaths: this.parseDiskPaths(config.diskPaths),
      // UEFI firmware configuration
      uefiFirmware: config.uefiFirmware ?? null,
      // Hugepages configuration
      hugepages: config.hugepages ?? null,
      // CPU pinning configuration (cgroups-based)
      cpuPinning: this.parseCpuPinning(config.cpuPinning),
      // NUMA-aware CPU pinning via numactl — now read via direct typed property
      // access. If a future change drops any of these columns from
      // MACHINE_CONFIG_SELECT (or from PrismaMachineConfigurationRecord), this
      // mapper fails to COMPILE rather than silently regressing to null.
      enableNumaCtlPinning: config.enableNumaCtlPinning ?? null,
      cpuPinningStrategy: config.cpuPinningStrategy ?? null,
      // Advanced device configuration
      tpmSocketPath: config.tpmSocketPath ?? null,
      guestAgentSocketPath: config.guestAgentSocketPath ?? null,
      infiniServiceSocketPath: config.infiniServiceSocketPath ?? null,
      virtioDriversIso: config.virtioDriversIso ?? null,
      enableAudio: config.enableAudio ?? null,
      enableUsbTablet: config.enableUsbTablet ?? null
    }
  }

  /**
   * Parse cpuPinning JSON field from Prisma.
   * Validates format and returns typed object or null.
   */
  private parseCpuPinning (raw: unknown): { cores: number[] } | null {
    if (raw === null || raw === undefined) return null
    if (typeof raw !== 'object') {
      // Present but malformed — surface it loudly rather than silently unpinning.
      this.debug.log('error', `Malformed cpuPinning JSON (not an object): ${String(raw)} — treating as unpinned`)
      return null
    }
    const obj = raw as Record<string, unknown>
    if (!Array.isArray(obj.cores) || !obj.cores.every(c => typeof c === 'number')) {
      this.debug.log('error', `Malformed cpuPinning.cores: ${JSON.stringify(obj.cores)} — treating as unpinned`)
      return null
    }
    return { cores: obj.cores as number[] }
  }

  /**
   * Parses the persisted diskPaths JSON. Distinguishes a legitimately-absent
   * value (null) from a PRESENT-BUT-CORRUPT one: the latter throws fail-closed
   * instead of being silently coerced to null, which would drop a multi-disk VM's
   * data disks (and the legacy fallback would then overwrite the recoverable blob).
   */
  private parseDiskPaths (raw: unknown): string[] | null {
    if (raw === null || raw === undefined) return null
    if (Array.isArray(raw) && raw.every(p => typeof p === 'string')) {
      return raw as string[]
    }
    this.debug.log('error', `Corrupt diskPaths JSON (expected string[]): ${JSON.stringify(raw)}`)
    throw new PrismaAdapterError(
      `Corrupt diskPaths configuration (expected an array of strings); refusing to silently drop disks`,
      PrismaAdapterErrorCode.QUERY_FAILED
    )
  }

  /**
   * Map a raw Prisma machine record to VMConfigRecord
   */
  private mapToVMConfigRecord (machine: PrismaMachineRecord): VMConfigRecord {
    return {
      id: machine.id,
      status: machine.status,
      name: machine.name ?? '',
      internalName: machine.internalName ?? '',
      os: machine.os ?? '',
      cpuCores: machine.cpuCores ?? 0,
      ramGB: machine.ramGB ?? 0,
      diskSizeGB: machine.diskSizeGB ?? 0,
      gpuPciAddress: machine.gpuPciAddress ?? null,
      version: machine.version ?? 1,
      configuration: machine.configuration
        ? this.mapToExtendedMachineConfiguration(machine.configuration)
        : null,
      firewallRuleSet: machine.firewallRuleSet
        ? this.mapToFirewallRuleSetRecord(machine.firewallRuleSet)
        : null,
      department: machine.department
        ? this.mapToDepartmentRecord(machine.department)
        : null
    }
  }

  /**
   * Map a raw Prisma firewall rule set to FirewallRuleSetRecord
   */
  private mapToFirewallRuleSetRecord (
    ruleSet: PrismaFirewallRuleSetRecord
  ): { id: string; name: string; internalName: string; priority: number; isActive: boolean; rules: FirewallRuleRecord[] } {
    return {
      id: ruleSet.id,
      name: ruleSet.name,
      internalName: ruleSet.internalName,
      priority: ruleSet.priority,
      isActive: ruleSet.isActive,
      rules: Array.isArray(ruleSet.rules)
        ? ruleSet.rules.map(r => this.mapToFirewallRuleRecord(r))
        : []
    }
  }

  /**
   * Map a raw Prisma department to DepartmentRecord
   */
  private mapToDepartmentRecord (
    dept: PrismaDepartmentRecord
  ): { id: string; name: string; firewallRuleSet: { id: string; name: string; internalName: string; priority: number; isActive: boolean; rules: FirewallRuleRecord[] } | null } {
    return {
      id: dept.id,
      name: dept.name,
      firewallRuleSet: dept.firewallRuleSet
        ? this.mapToFirewallRuleSetRecord(dept.firewallRuleSet)
        : null
    }
  }

  /**
   * Map a raw Prisma firewall rule to FirewallRuleRecord
   */
  private mapToFirewallRuleRecord (rule: PrismaFirewallRuleRecord): FirewallRuleRecord {
    return {
      id: rule.id,
      name: rule.name,
      description: rule.description,
      action: rule.action as 'ACCEPT' | 'DROP' | 'REJECT',
      direction: rule.direction as 'IN' | 'OUT' | 'INOUT',
      priority: rule.priority,
      protocol: rule.protocol,
      srcPortStart: rule.srcPortStart,
      srcPortEnd: rule.srcPortEnd,
      dstPortStart: rule.dstPortStart,
      dstPortEnd: rule.dstPortEnd,
      srcIpAddr: rule.srcIpAddr,
      srcIpMask: rule.srcIpMask,
      dstIpAddr: rule.dstIpAddr,
      dstIpMask: rule.dstIpMask,
      connectionState: rule.connectionState as FirewallRuleRecord['connectionState'],
      overridesDept: rule.overridesDept
    }
  }
}

/**
 * The full database facade that infinization's core (VMLifecycle + the sync
 * subsystems) actually depends on — every method it invokes on `this.prisma`.
 * Derived from PrismaAdapter via `Pick`, so these signatures can never drift
 * from the implementation (add a method here only when the core starts calling
 * it; remove the call and the Pick fails to compile).
 *
 * This is the injection seam (ADR-DB1 / multi-node Phase 1): a compute-node
 * agent injects a REMOTE implementation of this surface (an `RpcDatabaseAdapter`
 * proxying to the master over mTLS) so the node holds no Prisma connection,
 * while the master backend keeps injecting a concrete `PrismaAdapter` (the
 * single writer). `InfinizationDatabase` is a superset of the narrow
 * `DatabaseAdapter` port (it includes all of its methods), so it remains
 * assignable wherever the sync subsystems expect `DatabaseAdapter`.
 */
export type InfinizationDatabase = Pick<PrismaAdapter,
  | 'findMachine'
  | 'findMachineByInternalName'
  | 'findMachineWithConfig'
  | 'findRunningVMs'
  | 'findMachinesByStatuses'
  | 'updateMachineStatus'
  | 'updateMachineConfiguration'
  | 'transitionVMStatus'
  | 'clearMachineConfiguration'
  | 'clearVolatileMachineConfiguration'
  | 'getMachineInternalName'
  | 'getMachineDiskPath'
  | 'getFirewallRules'
  | 'getFirewallRulesSplit'
  | 'getDepartmentFirewallPolicy'
  | 'getFirewallRuleSetId'
>

