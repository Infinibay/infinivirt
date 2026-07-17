/**
 * Lifecycle Type Definitions
 *
 * This file contains TypeScript types for VM lifecycle operations.
 * Used by VMLifecycle and Infinization classes for VM creation, management, and status queries.
 */

import { UnattendedInstallConfig } from './unattended.types'
import { FirewallDefaultAction } from './firewall.types'
import type { PrismaClientLike, InfinizationDatabase } from '../db/PrismaAdapter'
import type { OverlaySelfIdentity } from './overlay.types'

// =============================================================================
// Configuration Types
// =============================================================================

/**
 * Display type for VM (SPICE or VNC)
 */
export type DisplayProtocol = 'spice' | 'vnc'

/**
 * Configuration for a single disk
 */
export interface DiskConfig {
  /** Disk size in gigabytes */
  sizeGB: number
  /** Disk format (default: 'qcow2') */
  format?: 'qcow2' | 'raw'
  /** Disk bus type (default: from diskBus config or 'virtio') */
  bus?: string
  /** Disk cache mode (default: from diskCacheMode config or 'writeback') */
  cache?: string
  /** Enable discard/TRIM support (default: true) */
  discard?: boolean
  /**
   * Optional absolute path to a backing qcow2 file. When set, the disk
   * is created as a thin linked clone (qcow2 backing chain) instead of a
   * fresh zeroed image. Size is inherited from the backing file; sizeGB
   * is ignored by qemu-img create when backingFile is present.
   *
   * The backing file must outlive every clone that references it —
   * modifying or deleting it corrupts all dependents. Treat it as
   * read-only after seal.
   */
  backingFile?: string
}

/**
 * Configuration for creating a new VM
 */
export interface VMCreateConfig {
  /** Database machine ID (UUID) - must match the machine.id in the database */
  vmId: string
  /** VM display name */
  name: string
  /** VM internal name (used for TAP device, disk, socket naming) */
  internalName: string
  /**
   * Operating system type (e.g., 'ubuntu', 'windows10', 'FreeDOS').
   *
   * This field is used to automatically apply OS-optimized driver presets
   * during VM creation. The OS string is pattern-matched to determine
   * the appropriate preset category:
   *
   * - **Windows**: 'windows', 'windows10', 'windows11', 'win10', etc.
   *   → Applies Windows preset (diskBus=virtio, cache=none, networkModel=virtio-net-pci)
   * - **Linux**: 'ubuntu', 'debian', 'fedora', 'centos', 'rhel', etc.
   *   → Applies Linux preset (diskBus=virtio, cache=writeback, networkModel=virtio-net-pci)
   * - **Legacy**: 'dos', 'freedos', 'freebsd', 'win98', etc.
   *   → Applies Legacy preset (diskBus=ide, cache=writethrough, networkModel=e1000)
   *
   * **Note**: Presets apply to disk and network MODEL configuration only.
   * - `networkQueues` is NOT affected by presets; it is auto-calculated as `min(cpuCores, 4)`
   * - `displayType` is a required field and is NOT affected by presets
   *
   * Preset values can be overridden by explicitly setting the corresponding
   * config fields (diskBus, diskCacheMode, networkModel).
   *
   * @see DriverPresets module for full preset definitions and OS patterns
   *
   * @example
   * // Windows VM with automatic optimizations
   * { os: 'Windows 11', ... }  // Uses Windows preset
   *
   * @example
   * // Linux VM with preset override
   * { os: 'ubuntu', diskCacheMode: 'none', ... }  // Overrides preset's 'writeback'
   */
  os: string
  /** Number of CPU cores */
  cpuCores: number
  /** RAM size in gigabytes */
  ramGB: number
  /**
   * Disk configurations for the VM.
   * Each disk will be created and attached in array order.
   * At least one disk is required.
   *
   * @example
   * disks: [
   *   { sizeGB: 50, format: 'qcow2', bus: 'virtio', cache: 'writeback' },
   *   { sizeGB: 100, format: 'qcow2', bus: 'virtio', cache: 'writeback' }
   * ]
   */
  disks: DiskConfig[]
  /** Network bridge name (e.g., 'virbr0') */
  bridge: string
  /**
   * Terminal firewall posture for this VM's chain (fail-closed by default).
   * Derive from the department policy: BLOCK_ALL => 'drop', ALLOW_ALL => 'accept'.
   * The terminal rule is installed UNCONDITIONALLY (even with zero explicit rules),
   * so a default-deny department with no allow rules is actually denied. Omit to
   * default to 'drop'.
   */
  firewallDefaultAction?: FirewallDefaultAction
  /**
   * Drop QEMU's privileges to this unprivileged user (`-runas`). Strongly
   * recommended when the backend runs as root, so a guest escape lands as an
   * unprivileged uid rather than root. Omit to leave QEMU as the backend's uid.
   */
  runAsUser?: string
  /**
   * Opt out of the QEMU seccomp sandbox (sandbox is ON by default). Only set for
   * a device that genuinely needs a blocked syscall family.
   */
  disableSandbox?: boolean
  /** Optional MAC address (auto-generated if not provided) */
  macAddress?: string
  /** Display type (spice or vnc) */
  displayType: DisplayProtocol
  /** Display port (required for SPICE, display number for VNC) */
  displayPort: number
  /** Display password (optional) */
  displayPassword?: string
  /** Display listen address (default: 0.0.0.0) */
  displayAddr?: string
  /** GPU PCI address for passthrough (optional) */
  gpuPciAddress?: string
  /** GPU ROM file path (optional) */
  gpuRomfile?: string
  /**
   * Opt-in infinigpu virtual GPU (docs/INTEGRATION.md §1/§2). When set, the VM gets
   * a vfio-user display device backed by a per-VM `infinigpu-device` server and the
   * SPICE/VNC console is skipped (infiniPixel is the remote display). The facade
   * fills in `socketPath` after it starts the server.
   */
  gpu?: InfinigpuVmOptions
  /** QEMU machine type (e.g., 'q35', 'pc') - defaults to 'q35' */
  machineType?: string
  /** CPU model (e.g., 'host', 'qemu64') - defaults to 'host' */
  cpuModel?: string
  /** Disk bus type (e.g., 'virtio', 'scsi', 'ide', 'sata') - defaults to 'virtio' */
  diskBus?: string
  /** Disk cache mode (e.g., 'writeback', 'writethrough', 'none', 'unsafe') - defaults to 'writeback' */
  diskCacheMode?: string
  /** Network model (e.g., 'virtio-net-pci', 'e1000') - defaults to 'virtio-net-pci' */
  networkModel?: string
  /**
   * Number of network queues for multi-queue networking.
   * Enables parallel packet processing for improved network performance.
   *
   * - If not specified, auto-calculated as `min(cpuCores, 4)`
   * - Set to 1 to disable multi-queue (single queue mode)
   * - Values > 1 enable multi-queue with vhost acceleration
   * - Recommended: leave unset for auto-calculation, or match CPU core count (max 4)
   *
   * **Note**: This field is NOT affected by OS driver presets. The auto-calculation
   * is always based on CPU cores, regardless of the `os` field. This ensures
   * optimal queue distribution for the VM's actual hardware allocation.
   *
   * @default Auto-calculated: min(cpuCores, 4)
   */
  networkQueues?: number
  /**
   * Enable memory balloon device for dynamic memory management.
   * Requires virtio-balloon driver in guest OS.
   * Default: false
   */
  memoryBalloon?: boolean
  /**
   * Enable hugepages for improved memory performance.
   *
   * Hugepages reduce TLB misses and improve memory access performance,
   * especially beneficial for VMs with large memory allocations (>4GB).
   *
   * **Host Requirements:**
   * - Hugepages must be configured in kernel boot parameters
   * - /dev/hugepages must be mounted (typically at /dev/hugepages)
   * - Sufficient hugepages must be allocated for the VM's memory size
   *
   * **Configuration Example:**
   * - Kernel boot param: `hugepagesz=2M hugepages=N` (N = total GB * 512)
   * - Verify: `cat /proc/meminfo | grep Huge`
   * - Check mount: `mount | grep hugepages`
   *
   * If the host system does not have hugepages properly configured,
   * the VM will fall back to standard memory allocation and a warning
   * will be logged.
   *
   * See README.md 'Hugepages for Memory Performance' section for host setup.
   *
   * Default: false
   *
   * @example true
   */
  hugepages?: boolean
  /**
   * Path to OVMF firmware file for UEFI boot.
   * If not specified, VM will use legacy BIOS boot.
   *
   * For UEFI Secure Boot, provide a Secure Boot-capable firmware file
   * (e.g., OVMF_CODE.secboot.fd). The firmware file itself determines
   * whether Secure Boot is available to the guest.
   *
   * Common paths:
   * - /usr/share/OVMF/OVMF_CODE.fd (standard UEFI)
   * - /usr/share/OVMF/OVMF_CODE.secboot.fd (with Secure Boot)
   *
   * If the specified file does not exist or is not readable at VM creation time,
   * the VM will fall back to BIOS boot and `uefiFirmware` will be stored as `null`.
   *
   * @example '/usr/share/OVMF/OVMF_CODE.fd'
   */
  uefiFirmware?: string
  /** ISO file path for installation (optional) */
  isoPath?: string
  /** VM UUID (optional, auto-generated if not provided) */
  uuid?: string
  /**
   * Optional unattended installation configuration.
   * When provided, a custom ISO will be generated with automated installation
   * configuration, and the VM will boot from it to perform unattended OS installation.
   *
   * @example
   * ```typescript
   * const config: VMCreateConfig = {
   *   // ... other config ...
   *   unattendedInstall: {
   *     os: 'ubuntu',
   *     username: 'admin',
   *     password: 'secure123',
   *     applications: [firefoxApp, chromeApp],
   *     scripts: [setupScript]
   *   }
   * }
   * ```
   */
  unattendedInstall?: UnattendedInstallConfig
  /**
   * CPU affinity configuration for pinning QEMU process to specific cores.
   *
   * Pins the VM's QEMU process to the specified CPU cores using Linux cgroups v2.
   * This can improve performance by reducing cache misses and ensuring consistent
   * CPU allocation for latency-sensitive workloads.
   *
   * **Host Requirements:**
   * - Linux kernel with cgroups v2 support (kernel 4.5+, typically enabled by default on modern distros)
   * - Mounted cgroups v2 hierarchy at /sys/fs/cgroup/
   * - Sufficient permissions to create cgroups and move processes
   *
   * **Format:** Array of CPU core indices (0-based)
   *
   * **Validation:**
   * - Core indices must be valid (0 to hostCpuCount-1)
   * - Duplicate cores are automatically deduplicated
   * - Empty array is treated as null (no pinning)
   *
   * If the host does not support cgroups v2 or pinning fails, the VM will
   * start without CPU affinity and a warning will be logged.
   *
   * @example [0, 1, 2] // Pin to cores 0, 1, and 2
   * @example [4, 5, 6, 7] // Pin to cores 4-7 (useful for NUMA nodes)
   */
  cpuPinning?: number[]

  /**
   * Enable NUMA-aware CPU pinning using numactl as a process wrapper.
   *
   * When enabled, the QEMU process will be started with `numactl` to:
   * - Pin CPU threads to specific physical cores (--physcpubind)
   * - Bind memory allocation to specific NUMA nodes (--membind)
   *
   * This provides better performance than cgroups-only pinning because memory
   * is allocated on the correct NUMA node from the start, reducing migration
   * overhead and improving cache locality.
   *
   * **Host Requirements:**
   * - numactl package installed (`apt install numactl`)
   * - Multi-core system (pinning on single-core has no benefit)
   *
   * **Interaction with cpuPinning:**
   * - If both `enableNumaCtlPinning` and `cpuPinning` are set, numactl pinning
   *   is applied at process launch, and cgroups pinning is applied after launch.
   * - For most use cases, use one or the other, not both.
   *
   * @default false
   */
  enableNumaCtlPinning?: boolean

  /**
   * Strategy for automatic CPU pinning when `enableNumaCtlPinning` is true.
   *
   * - **basic**: Sequential pinning across NUMA nodes with optimal distribution.
   *   Keeps vCPUs within the same NUMA node when possible to maximize memory locality.
   *   Best for most workloads.
   *
   * - **hybrid**: Randomized distribution across NUMA nodes.
   *   Provides better load balancing for mixed workloads that benefit from
   *   spreading across different NUMA nodes.
   *
   * @default 'basic'
   */
  cpuPinningStrategy?: 'basic' | 'hybrid'

  // ===========================================================================
  // Advanced Device Configuration
  // ===========================================================================

  /**
   * Path to TPM 2.0 socket for Trusted Platform Module emulation.
   *
   * Requires swtpm to be running and listening on this socket path.
   * TPM is required for Windows 11 and provides hardware security features.
   *
   * **Host Requirements:**
   * - swtpm package installed
   * - swtpm_setup for initializing TPM state
   * - Socket created before VM start
   *
   * @example '/var/run/infinization/tpm/vm-abc123.sock'
   */
  tpmSocketPath?: string

  /**
   * Path to QEMU Guest Agent socket for host-guest communication.
   *
   * The Guest Agent enables host-initiated commands like:
   * - File operations (read/write guest files)
   * - Process management
   * - Network configuration queries
   * - Graceful shutdown coordination
   *
   * **Guest Requirements:**
   * - qemu-guest-agent package installed in the VM
   * - Guest agent service running
   *
   * @example '/var/run/infinization/ga/vm-abc123.sock'
   */
  guestAgentSocketPath?: string

  /**
   * Path to InfiniService channel socket for custom host-guest communication.
   *
   * This virtio-serial channel is used by the InfiniService agent for:
   * - Application installation status
   * - Custom provisioning commands
   * - Health check coordination
   * - User session management
   *
   * **Guest Requirements:**
   * - InfiniService agent installed in the VM
   *
   * @example '/var/run/infinization/infini/vm-abc123.sock'
   */
  infiniServiceSocketPath?: string

  /**
   * Path to VirtIO drivers ISO for Windows VMs.
   *
   * Mounted as a secondary CD-ROM drive to provide VirtIO drivers
   * during Windows installation (disk, network, balloon, etc.).
   *
   * Common sources:
   * - https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/
   * - /usr/share/virtio-win/virtio-win.iso (packaged)
   *
   * @example '/var/lib/infinization/isos/virtio-win.iso'
   */
  virtioDriversIso?: string

  /**
   * Enable Intel HDA audio device for sound output.
   *
   * Adds an Intel High Definition Audio controller with a duplex codec.
   * Audio is routed through SPICE for remote desktop scenarios.
   *
   * **Requirements:**
   * - SPICE display type for remote audio
   * - Audio drivers in guest OS
   *
   * @default false
   */
  enableAudio?: boolean

  /**
   * Enable USB tablet device for absolute mouse positioning.
   *
   * USB tablet provides absolute cursor positioning, eliminating the need
   * to capture/release mouse in remote desktop scenarios. Recommended
   * for all VMs, especially Windows.
   *
   * @default true for Windows, false for others
   */
  enableUsbTablet?: boolean
}

/**
 * Result of VM creation
 */
export interface VMCreateResult {
  /** The VM identifier */
  vmId: string
  /** Created TAP device name */
  tapDevice: string
  /** QMP socket path */
  qmpSocketPath: string
  /** Display port number */
  displayPort: number
  /** QEMU process ID */
  pid: number
  /** Array of created disk image paths */
  diskPaths: string[]
  /** PID file path */
  pidFilePath: string
  /** Whether creation was successful */
  success: true
  /**
   * Path to the generated unattended installation ISO (if applicable).
   * This ISO will be automatically ejected and cleaned up after installation completes.
   */
  installationIsoPath?: string
  /**
   * Whether unattended installation is in progress.
   * If true, the VM is currently installing the OS automatically.
   */
  installingOS?: boolean
}

/**
 * Configuration options for starting a VM
 */
export interface VMStartConfig {
  /** Wait for boot to complete (default: false) */
  waitForBoot?: boolean
  /** Boot timeout in milliseconds (default: 60000) */
  bootTimeout?: number
  /**
   * Terminal firewall posture to (re)install on start (fail-closed by default).
   * Same semantics as VMCreateConfig.firewallDefaultAction. Omit to default to
   * 'drop'. The backend should thread the department policy here on every start.
   */
  firewallDefaultAction?: FirewallDefaultAction
  /**
   * Opt out of QEMU's seccomp sandbox on this start (default: sandbox ON). Mirrors
   * VMCreateConfig.disableSandbox so the operator's choice is uniform across the
   * lifecycle — otherwise a VM created with the sandbox disabled would re-enable it
   * on the next stop/start. Only for environments where the sandbox is incompatible
   * with the host (e.g. nested/rootless containers that SIGSYS a sandboxed syscall).
   */
  disableSandbox?: boolean
  /**
   * Opt-in infinigpu virtual GPU for this start. Mirrors VMCreateConfig.gpu so a
   * GPU VM re-attaches its device on every start (the reconstructed config is
   * DB-derived and would otherwise drop it). The backend threads department policy
   * here on every start; the facade fills in `socketPath`.
   */
  gpu?: InfinigpuVmOptions
}

/**
 * Opt-in infinigpu virtual-GPU options threaded through the VM lifecycle.
 */
export interface InfinigpuVmOptions {
  /**
   * Host UNIX socket the vfio-user device server listens on and QEMU connects to.
   * Derived + set by the Infinization facade (`${qmpSocketDir}/<vmId>.gpu.sock`);
   * callers leave it undefined.
   */
  socketPath?: string
  /**
   * infiniPixel WebSocket port for this VM's remote-display stream. Omit to leave
   * streaming disabled (the device server still renders; nothing is exposed).
   */
  pixelPort?: number
}

/**
 * Configuration options for stopping a VM
 */
export interface VMStopConfig {
  /** Use graceful shutdown via ACPI (default: true) */
  graceful?: boolean
  /** Timeout in milliseconds for graceful shutdown (default: 30000) */
  timeout?: number
  /** Force kill if graceful timeout expires (default: true) */
  force?: boolean
}

// =============================================================================
// Result Types
// =============================================================================

/**
 * Generic result for VM operations
 */
export interface VMOperationResult {
  /** Whether the operation was successful */
  success: boolean
  /** Human-readable message */
  message: string
  /** Error information if failed */
  error?: string
  /** VM identifier */
  vmId: string
  /** Timestamp of the operation */
  timestamp: Date
  /** Whether the operation was forced */
  forced?: boolean
}

/**
 * Result of a VM status query
 */
export interface VMStatusResult {
  /** The VM identifier */
  vmId: string
  /** Database status (running, off, suspended, etc.) */
  status: string
  /** QMP status (running, paused, shutdown, etc.) - null if not connected */
  qmpStatus: string | null
  /** QEMU process ID - null if not running */
  pid: number | null
  /** Uptime in seconds - null if not running */
  uptime: number | null
  /** Whether process is actually alive */
  processAlive: boolean
  /** Whether DB status and process state are consistent */
  consistent: boolean
  /** TAP device name */
  tapDevice: string | null
  /** QMP socket path */
  qmpSocketPath: string | null
}

// =============================================================================
// Error Types
// =============================================================================

/**
 * Error codes for lifecycle operations
 */
export enum LifecycleErrorCode {
  /** VM not found in database */
  VM_NOT_FOUND = 'VM_NOT_FOUND',
  /** VM is already running */
  ALREADY_RUNNING = 'ALREADY_RUNNING',
  /** VM is already stopped */
  ALREADY_STOPPED = 'ALREADY_STOPPED',
  /** VM creation failed */
  CREATE_FAILED = 'CREATE_FAILED',
  /** VM start failed */
  START_FAILED = 'START_FAILED',
  /** VM stop failed */
  STOP_FAILED = 'STOP_FAILED',
  /** Resource cleanup failed */
  CLEANUP_FAILED = 'CLEANUP_FAILED',
  /** Operation timed out */
  TIMEOUT = 'TIMEOUT',
  /** QMP communication error */
  QMP_ERROR = 'QMP_ERROR',
  /** Disk operation error */
  DISK_ERROR = 'DISK_ERROR',
  /** Network configuration error */
  NETWORK_ERROR = 'NETWORK_ERROR',
  /** Firewall configuration error */
  FIREWALL_ERROR = 'FIREWALL_ERROR',
  /** Invalid configuration provided */
  INVALID_CONFIG = 'INVALID_CONFIG',
  /** Process management error */
  PROCESS_ERROR = 'PROCESS_ERROR',
  /** Database operation error */
  DATABASE_ERROR = 'DATABASE_ERROR',
  /** VM is in an unexpected state */
  INVALID_STATE = 'INVALID_STATE',
  /** Concurrent modification detected (optimistic locking failure) */
  CONCURRENT_MODIFICATION = 'CONCURRENT_MODIFICATION',
  /** Required resource (port, socket, etc.) is unavailable */
  RESOURCE_UNAVAILABLE = 'RESOURCE_UNAVAILABLE'
}

/**
 * Custom error class for lifecycle operations
 */
export class LifecycleError extends Error {
  /** Error code for programmatic handling */
  public readonly code: LifecycleErrorCode

  /** VM identifier (if applicable) */
  public readonly vmId?: string

  /** Additional context for debugging */
  public readonly context?: Record<string, unknown>

  constructor (
    code: LifecycleErrorCode,
    message: string,
    vmId?: string,
    context?: Record<string, unknown>
  ) {
    super(message)
    this.name = 'LifecycleError'
    this.code = code
    this.vmId = vmId
    this.context = context

    // Maintains proper stack trace
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, LifecycleError)
    }
  }
}

/**
 * Type guard to check if an error is a LifecycleError
 */
export function isLifecycleError (error: unknown): error is LifecycleError {
  return error instanceof LifecycleError
}

/**
 * Factory function to create a LifecycleError
 */
export function createLifecycleError (
  code: LifecycleErrorCode,
  message: string,
  vmId?: string,
  context?: Record<string, unknown>
): LifecycleError {
  return new LifecycleError(code, message, vmId, context)
}

// =============================================================================
// Constants
// =============================================================================

/** Default timeout for graceful stop operations (30 seconds) */
export const DEFAULT_STOP_TIMEOUT = 30000

/** Default timeout for boot wait operations (60 seconds) */
export const DEFAULT_BOOT_TIMEOUT = 60000

/** Default timeout for QMP connection (5 seconds) */
export const DEFAULT_QMP_CONNECT_TIMEOUT = 5000

/** Default directory for QMP sockets */
export const DEFAULT_QMP_SOCKET_DIR = '/var/run/infinization'

/** Default directory for disk images */
export const DEFAULT_DISK_DIR = '/var/lib/infinization/disks'

/** Default directory for PID files */
export const DEFAULT_PIDFILE_DIR = '/var/run/infinization/pids'

/** Default network model for VMs */
export const DEFAULT_NETWORK_MODEL = 'virtio-net-pci'

/** Default disk format */
export const DEFAULT_DISK_FORMAT = 'qcow2'

/** Default disk bus */
export const DEFAULT_DISK_BUS = 'virtio'

/** Default disk cache mode */
export const DEFAULT_DISK_CACHE = 'writeback'

/** Delay between stop and start in restart operation (ms) */
export const RESTART_DELAY_MS = 2000

/** Poll interval for process exit checks (ms) */
export const PROCESS_EXIT_POLL_INTERVAL = 100

/**
 * Placeholder disk size used during VM start for reconstructed DiskConfig entries.
 * This value is not used for actual disk operations during start (disks already exist),
 * but must be positive to satisfy type constraints and validation requirements.
 * Set to 1 GB as the minimum valid value per validateCreateConfig() expectations.
 */
export const RUNTIME_DISK_SIZE_PLACEHOLDER_GB = 1

// =============================================================================
// Infinization Configuration Types
// =============================================================================

/**
 * Configuration for Infinization main class.
 *
 * Note: Pass your application's PrismaClient singleton for connection pooling.
 * Infinization does not create or manage its own Prisma instance.
 *
 * Some behaviour is also configurable via environment variables (host-wide
 * defaults that a typed field here overrides where one exists). See
 * `docs/CONFIGURATION.md` for the full catalogue — notably
 * `INFINIZATION_BRIDGE_CONNTRACK_MODE` (firewall conntrack posture; see
 * `bridgeConntrackMode` below), `INFINIZATION_QEMU_USER` (host-wide default for
 * the QEMU `-runas` privilege drop — the per-VM `runAsUser` takes precedence at
 * create, but start/restart falls back to this env var; see docs/CONFIGURATION.md),
 * and `INFINIBAY_BACKEND_SERVICES_PATH` (unattended-install
 * services path; overridable per-installer via `UnattendedInstallerOptions`).
 */
export interface InfinizationConfig {
  /**
   * Pre-configured Prisma client instance (the master backend, the single
   * writer). Infinization wraps it in a node-scoped PrismaAdapter. Provide EITHER
   * this OR `databaseAdapter` — exactly one is required.
   * Pass your application's singleton for shared connection pooling.
   */
  prismaClient?: PrismaClientLike
  /**
   * Alternative to `prismaClient`: inject a ready-made database facade. A
   * compute-node agent passes an `RpcDatabaseAdapter` here that proxies every DB
   * call to the master over mTLS, so the node holds NO Prisma connection
   * (multi-node ADR-DB1 / Phase 1). Provide EITHER this OR `prismaClient`.
   */
  databaseAdapter?: InfinizationDatabase
  /**
   * Optional owning node identity (the `Node.id` for this host).
   *
   * When set, infinization scopes its enumeration / orphan-mapping DB reads
   * (running-VM crash-detect, startup transient reconcile, orphan-from-pidfile
   * lookup) to `Machine.nodeId === nodeId`, so this host only ever sees and
   * acts on VMs assigned to it. This is the structural G0 fix that lets multiple
   * hosts share one control-plane DB without cross-killing each other's VMs.
   *
   * Omit on a single-host deployment to preserve host-agnostic behaviour. The
   * backend resolves this from the local `Node` record (see
   * `LocalNodeRegistrationService` / `INFINIBAY_NODE_NAME`).
   */
  nodeId?: string
  /** Optional backend EventManager for event emission */
  eventManager?: EventManagerLike
  /** Health monitor check interval in milliseconds (default: 30000) */
  healthMonitorInterval?: number
  /** Whether to auto-start health monitor (default: true) */
  autoStartHealthMonitor?: boolean
  /** Custom disk directory path */
  diskDir?: string
  /** Custom QMP socket directory path */
  qmpSocketDir?: string
  /** Custom PID file directory path */
  pidfileDir?: string
  /**
   * Bridge-family conntrack posture for the nftables firewall.
   *
   * - `'fail'` (default, RECOMMENDED): fail-closed. `initialize()` throws an
   *   actionable error on a host missing `nf_conntrack_bridge`/`br_netfilter`,
   *   and VM firewall chains install the stateful `ct state established,related`
   *   rule. Use this in production.
   * - `'degrade'`: run STATELESS — omit the conntrack rule on hosts lacking
   *   bridge conntrack so VMs still start. This WEAKENS the firewall (no
   *   established/related state tracking): a fail-open posture. Use only when you
   *   understand the trade-off.
   *
   * Overrides the `INFINIZATION_BRIDGE_CONNTRACK_MODE` env var when set.
   * Defaults to that env var (`'degrade'` ⇒ degrade), else `'fail'`.
   */
  bridgeConntrackMode?: 'fail' | 'degrade'
  /**
   * This host's department-overlay identity (07-networking.md §1). Set by the
   * node agent on an overlay-capable compute node — its VTEP address, the path to
   * its WireGuard private key (which never leaves the host), and the WG listen
   * port. When present, `ensureSegment`/`setPeers`/`destroySegment` can realize a
   * node-spanning L2 segment locally; when absent those verbs throw (the host is
   * not overlay-capable). Master-pushed per-segment data (vni/peers/gatewayCidr)
   * arrives as call arguments, never from the DB.
   */
  overlay?: OverlaySelfIdentity
}

/**
 * Minimal interface for backend EventManager integration.
 * Allows infinization to emit events to the backend without direct dependency.
 */
export interface EventManagerLike {
  /** Emit a CRUD event for a resource */
  emitCRUD?: (resource: string, action: string, id: string, data?: unknown) => void
  /** Emit a custom event */
  emit?: (event: string, data: unknown) => void
}

/**
 * Resources tracked by the active VMs map.
 * Note: QMP client and QEMU process handles are managed by VMLifecycle
 * and not stored here, as they may be recreated during restart operations.
 */
export interface ActiveVMResources {
  /** TAP device name */
  tapDevice?: string
  /** Creation timestamp */
  createdAt: Date
  /** VM internal name */
  internalName: string
}
