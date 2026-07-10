// Core classes
export { QemuCommandBuilder, QemuCommand, QemuCommandWithPinning } from './core/QemuCommandBuilder'
export { QemuProcess } from './core/QemuProcess'
export { QMPClient } from './core/QMPClient'
export { VMLifecycle } from './core/VMLifecycle'
export { Infinization } from './core/Infinization'

// CPU classes
export {
  CpuPinningAdapter,
  CpuPinningResult,
  NumaTopology,
  PinningStrategy
} from './cpu/CpuPinningAdapter'

// Network classes
export { TapDeviceManager } from './network/TapDeviceManager'
export { BridgeManager } from './network/BridgeManager'
export { MacAddressGenerator } from './network/MacAddressGenerator'
export { NftablesService } from './network/NftablesService'
export { FirewallRuleTranslator, FirewallTranslationError } from './network/FirewallRuleTranslator'
export { DepartmentNatService } from './network/DepartmentNatService'
export { OverlayManager } from './network/OverlayManager'

// Storage classes
export { QemuImgService } from './storage/QemuImgService'
export { SnapshotManager } from './storage/SnapshotManager'

// Display classes
export { SpiceConfig } from './display/SpiceConfig'
export { VncConfig } from './display/VncConfig'

// Sync classes
export { StateSync } from './sync/StateSync'
export { EventHandler } from './sync/EventHandler'
export { HealthMonitor } from './sync/HealthMonitor'

// Database classes
export { PrismaAdapter, type InfinizationDatabase } from './db/PrismaAdapter'

// Types - QEMU
export {
  MachineType,
  DiskBus,
  CacheMode,
  DisplayType,
  VgaType,
  BootDevice,
  MachineOptions,
  DiskOptions,
  NetworkOptions,
  SpiceOptions,
  VncOptions,
  QemuProcessOptions,
  // GPU Passthrough Types
  GpuPassthroughOptions,
  PciAddressValidationResult,
  PCI_ADDRESS_REGEX,
  validatePciAddress,
  normalizePciAddress
} from './types/qemu.types'

// Types - QMP
export {
  QMPGreeting,
  QMPVersion,
  QMPMessage,
  QMPResponse,
  QMPError,
  QMPEvent,
  QMPTimestamp,
  QMPEventType,
  QMPShutdownEventData,
  QMPDeviceDeletedEventData,
  QMPBlockJobCompletedEventData,
  QMPVMStatus,
  QMPStatusInfo,
  QMPCpuInfo,
  QMPBlockInfo,
  QMPBlockImageInfo,
  QMPBlockInsertedInfo,
  QMPVncInfo,
  QMPVncClientInfo,
  QMPSpiceInfo,
  QMPSpiceChannel,
  QMPMemorySizeInfo,
  QMPClientOptions,
  QMPSocketOptions
} from './types/qmp.types'

// Types - Network
export {
  TapDeviceConfig,
  TapDeviceInfo,
  BridgeConfig,
  BridgeInfo,
  NetworkDeviceError,
  MacAddress,
  NetworkDeviceState,
  NetworkErrorCode,
  QEMU_MAC_PREFIX,
  MAX_TAP_NAME_LENGTH,
  TAP_NAME_PREFIX
} from './types/network.types'

// Types - Department L2 overlay (07-networking.md §1)
export {
  OVERLAY_VXLAN_PREFIX,
  OVERLAY_WG_INTERFACE,
  VXLAN_DSTPORT
} from './types/overlay.types'
export type {
  OverlayPeer,
  OverlaySelfIdentity,
  OverlaySegmentSpec
} from './types/overlay.types'

// Types - Firewall
export {
  NftablesFamily,
  NftablesHookType,
  NftablesChainPolicy,
  NftablesErrorCode,
  NftablesTableConfig,
  NftablesChainConfig,
  NftablesRuleConfig,
  NftablesRuleTokens,
  FirewallRuleTranslation,
  VMFirewallConfig,
  FirewallRuleInput,
  ConnectionStateConfig,
  NftablesError,
  ChainListResult,
  FirewallApplyResult,
  INFINIZATION_TABLE_NAME,
  INFINIZATION_TABLE_FAMILY,
  DEFAULT_CHAIN_PRIORITY,
  NFTABLES_COMMENT_PREFIX,
  SUPPORTED_PROTOCOLS,
  CONNECTION_STATES,
  MAX_CHAIN_NAME_LENGTH,
  VM_CHAIN_PREFIX,
  FirewallDefaultAction,
  generateVMChainName
} from './types/firewall.types'

// Types - Storage
export {
  ImageFormat,
  StorageErrorCode,
  ImageInfo,
  SnapshotInfo,
  ImageCheckResult,
  CreateImageOptions,
  ConvertImageOptions,
  SnapshotCreateOptions,
  StorageError,
  StorageErrorInfo,
  isValidImageFormat,
  SUPPORTED_IMAGE_FORMATS,
  DEFAULT_CLUSTER_SIZE,
  MAX_SNAPSHOT_NAME_LENGTH
} from './types/storage.types'

// Types - Display
export {
  DisplayErrorCode,
  SpiceConfigOptions,
  VncConfigOptions,
  ValidationError,
  DisplayValidationResult,
  DisplayCommandArgs,
  DisplayError,
  VNC_BASE_PORT,
  VNC_MAX_PASSWORD_LENGTH,
  SPICE_MIN_PORT,
  SPICE_MAX_PORT,
  DEFAULT_SPICE_ADDR,
  DEFAULT_VNC_ADDR
} from './types/display.types'

// Types - Sync
export {
  // Database adapter interface
  DatabaseAdapter,
  MachineRecord,
  MachineConfigurationRecord,
  RunningVMRecord,
  // Status types
  DBVMStatus,
  StatusMapping,
  SyncResult,
  SyncError,
  SyncErrorCode,
  // Health monitor types
  HealthCheckResult,
  HealthCheckSummary,
  CrashEvent,
  OrphanEvent,
  // Event handler types
  EventHandlerConfig,
  VMEventData,
  // Constants
  DEFAULT_HEALTH_CHECK_INTERVAL,
  DEFAULT_SYNC_TIMEOUT,
  MAX_SYNC_RETRIES,
  // Type guards
  isValidDBStatus,
  isValidQMPStatus
} from './types/sync.types'

// Types - Database
export {
  // Error types
  PrismaAdapterErrorCode,
  PrismaAdapterError,
  // Configuration types
  MachineConfigUpdate,
  // Record types
  VMConfigRecord,
  DepartmentRecord,
  FirewallRuleSetRecord,
  FirewallRuleRecord,
  ExtendedMachineConfigurationRecord,
  // Type guards
  isPrismaAdapterError,
  // Constants
  DEFAULT_DISK_PATH_PREFIX,
  DEFAULT_QMP_SOCKET_PATH_PREFIX,
  DEFAULT_DISK_FORMAT,
  DEFAULT_DISK_EXTENSION
} from './types/db.types'

// Types - Lifecycle
export {
  // Configuration types
  DisplayProtocol,
  DiskConfig,
  VMCreateConfig,
  VMCreateResult,
  VMStartConfig,
  VMStopConfig,
  // Result types
  VMOperationResult,
  VMStatusResult,
  // Error types
  LifecycleErrorCode,
  LifecycleError,
  // Constants
  DEFAULT_STOP_TIMEOUT,
  DEFAULT_BOOT_TIMEOUT,
  DEFAULT_QMP_CONNECT_TIMEOUT,
  DEFAULT_QMP_SOCKET_DIR,
  DEFAULT_DISK_DIR,
  DEFAULT_PIDFILE_DIR,
  DEFAULT_NETWORK_MODEL,
  DEFAULT_DISK_BUS,
  DEFAULT_DISK_CACHE,
  RESTART_DELAY_MS,
  PROCESS_EXIT_POLL_INTERVAL,
  RUNTIME_DISK_SIZE_PLACEHOLDER_GB,
  // Infinization config
  InfinizationConfig,
  EventManagerLike,
  ActiveVMResources,
  // Helper functions
  isLifecycleError,
  createLifecycleError
} from './types/lifecycle.types'

// Types - VM (Consolidated)
// Provides a centralized hub for all VM-related types.
//
// ARCH-07: The `*FromHub` / `VM*` prefixed names below are compatibility
// aliases that re-export canonical types under extra names. Audit found ZERO
// consumers across backend/frontend/infiniservice/infinization, but they are
// public API of a published package (@infinibay/infinization) so they are kept
// for backwards compatibility and formally deprecated via @deprecated tags
// pointing to the canonical name. Slated for removal in the next major release.
export {
  /** @deprecated Use {@link DisplayProtocol} from lifecycle.types instead. */
  DisplayProtocol as VMDisplayProtocol,
  /** @deprecated Use {@link VMCreateConfig} from lifecycle.types instead. */
  VMCreateConfig as VMCreateConfigFromHub,
  /** @deprecated Use {@link VMCreateResult} from lifecycle.types instead. */
  VMCreateResult as VMCreateResultFromHub,
  /** @deprecated Use {@link VMStartConfig} from lifecycle.types instead. */
  VMStartConfig as VMStartConfigFromHub,
  /** @deprecated Use {@link VMStopConfig} from lifecycle.types instead. */
  VMStopConfig as VMStopConfigFromHub,
  /** @deprecated Use {@link VMOperationResult} from lifecycle.types instead. */
  VMOperationResult as VMOperationResultFromHub,
  /** @deprecated Use {@link VMStatusResult} from lifecycle.types instead. */
  VMStatusResult as VMStatusResultFromHub,
  // Re-exported from sync.types for convenience
  VMStatus,
  // Re-exported from qemu.types
  /** @deprecated Use {@link MachineOptions} from qemu.types instead. */
  MachineOptions as VMMachineOptions,
  // New consolidated types
  VMInfo,
  VMResourceConfig,
  VMNetworkInfo,
  VMDisplayInfo,
  VMHardwareConfig,
  VMOperation,
  VMOperationStatus,
  VMOperationHistory,
  // Type guards
  isValidVMStatus,
  isValidVMOperation,
  isValidVMInfo,
  // Constants
  DEFAULT_VM_CPU_CORES,
  DEFAULT_VM_RAM_GB,
  DEFAULT_VM_DISK_SIZE_GB,
  MIN_VM_CPU_CORES,
  MAX_VM_CPU_CORES,
  MIN_VM_RAM_GB,
  MAX_VM_RAM_GB,
  MIN_VM_DISK_SIZE_GB,
  MAX_VM_DISK_SIZE_GB
} from './types/vm.types'

// Types - Configuration (Consolidated)
// Provides a centralized hub for all configuration-related types.
//
// ARCH-07: The `Config*` prefixed names below are compatibility aliases that
// re-export canonical types under extra names. Audit found ZERO consumers
// across backend/frontend/infiniservice/infinization, but they are public API
// of a published package (@infinibay/infinization) so they are kept for
// backwards compatibility and formally deprecated via @deprecated tags pointing
// to the canonical name. Slated for removal in the next major release.
export {
  // Re-exported from qemu.types
  /** @deprecated Use {@link MachineType} from qemu.types instead. */
  MachineType as ConfigMachineType,
  /** @deprecated Use {@link DiskBus} from qemu.types instead. */
  DiskBus as ConfigDiskBus,
  /** @deprecated Use {@link CacheMode} from qemu.types instead. */
  CacheMode as ConfigCacheMode,
  /** @deprecated Use {@link DisplayType} from qemu.types instead. */
  DisplayType as ConfigDisplayType,
  /** @deprecated Use {@link VgaType} from qemu.types instead. */
  VgaType as ConfigVgaType,
  /** @deprecated Use {@link BootDevice} from qemu.types instead. */
  BootDevice as ConfigBootDevice,
  /** @deprecated Use {@link MachineOptions} from qemu.types instead. */
  MachineOptions as ConfigMachineOptions,
  /** @deprecated Use {@link DiskOptions} from qemu.types instead. */
  DiskOptions as ConfigDiskOptions,
  /** @deprecated Use {@link NetworkOptions} from qemu.types instead. */
  NetworkOptions as ConfigNetworkOptions,
  /** @deprecated Use {@link SpiceOptions} from qemu.types instead. */
  SpiceOptions as ConfigSpiceOptions,
  /** @deprecated Use {@link VncOptions} from qemu.types instead. */
  VncOptions as ConfigVncOptions,
  /** @deprecated Use {@link QemuProcessOptions} from qemu.types instead. */
  QemuProcessOptions as ConfigQemuProcessOptions,
  // Re-exported from display.types
  /** @deprecated Use {@link SpiceConfigOptions} from display.types instead. */
  SpiceConfigOptions as ConfigSpiceConfigOptions,
  /** @deprecated Use {@link VncConfigOptions} from display.types instead. */
  VncConfigOptions as ConfigVncConfigOptions,
  // Re-exported from network.types
  /** @deprecated Use {@link TapDeviceConfig} from network.types instead. */
  TapDeviceConfig as ConfigTapDeviceConfig,
  /** @deprecated Use {@link BridgeConfig} from network.types instead. */
  BridgeConfig as ConfigBridgeConfig,
  // Re-exported from storage.types
  /** @deprecated Use {@link CreateImageOptions} from storage.types instead. */
  CreateImageOptions as ConfigCreateImageOptions,
  /** @deprecated Use {@link ConvertImageOptions} from storage.types instead. */
  ConvertImageOptions as ConfigConvertImageOptions,
  /** @deprecated Use {@link SnapshotCreateOptions} from storage.types instead. */
  SnapshotCreateOptions as ConfigSnapshotCreateOptions,
  // Re-exported from firewall.types
  /** @deprecated Use {@link VMFirewallConfig} from firewall.types instead. */
  VMFirewallConfig as ConfigVMFirewallConfig,
  /** @deprecated Use {@link FirewallRuleInput} from firewall.types instead. */
  FirewallRuleInput as ConfigFirewallRuleInput,
  // Re-exported from lifecycle.types
  /** @deprecated Use {@link InfinizationConfig} from lifecycle.types instead. */
  InfinizationConfig as ConfigInfinizationConfig,
  // Re-exported from sync.types
  /** @deprecated Use {@link HealthMonitorConfig} from sync.types instead. */
  HealthMonitorConfig as ConfigHealthMonitorConfig,
  /** @deprecated Use {@link EventHandlerConfig} from sync.types instead. */
  EventHandlerConfig as ConfigEventHandlerConfig,
  // Helper types derived from existing types
  VMDisplayType,
  NetworkModel,
  StorageFormat,
  // New unified configuration types
  DisplayConfig,
  NetworkConfig,
  FirewallConfig,
  StorageConfig,
  QemuConfig,
  QemuMachineConfig,
  QemuCpuConfig,
  QemuMemoryConfig,
  QemuBootConfig,
  QemuProcessConfig,
  VMCompleteConfig,
  VMIdentityConfig,
  VMResourcesConfig,
  VMHardwarePassthroughConfig,
  USBDeviceConfig,
  PCIDeviceConfig,
  // Validation types
  ConfigValidationResult,
  ConfigValidationError,
  ConfigValidationWarning,
  // Defaults
  ConfigDefaults,
  // Type guards
  isValidDisplayConfig,
  isValidNetworkConfig,
  isValidStorageConfig,
  isValidVMCompleteConfig,
  isValidGpuPassthroughConfig
} from './types/config.types'

// =============================================================================
// Unattended Installation
// =============================================================================
export { UnattendedInstaller, UnattendedInstallerOptions } from './unattended/UnattendedInstaller'
export { InstallationMonitor } from './unattended/InstallationMonitor'

// Types - Unattended
export {
  // OS and phase types
  OSType,
  InstallationPhase,
  // Application types
  InstallCommandType,
  UnattendedApplication,
  ScriptShell,
  UnattendedScript,
  ScriptExecutionConfig,
  // Configuration types
  UnattendedInstallConfig,
  MonitorConfig,
  // Progress and result types
  InstallationProgress,
  InstallationResult,
  // Error types
  UnattendedErrorCode,
  UnattendedError,
  // Constants
  DEFAULT_INSTALLATION_TIMEOUT,
  OS_INSTALLATION_TIMEOUTS,
  CDROM_DEVICE_NAME,
  ISO_BOOT_ORDER,
  DEFAULT_MAX_RESETS,
  DEFAULT_CHECK_INTERVAL,
  DEFAULT_LOCALE,
  DEFAULT_TIMEZONE,
  // Helpers
  getInstallationTimeout,
  // Type guards
  isValidOSType,
  isValidInstallationPhase,
  isValidInstallConfig,
  isUnattendedError,
  createUnattendedError
} from './types/unattended.types'


// Types - Backup
export {
  // Enums
  BackupType,
  BackupStatus,
  BackupCompression,
  // Configuration types
  BackupConfig,
  BackupRestoreOptions,
  BackupSchedule,
  // Metadata & result types
  BackupDiskInfo,
  BackupMetadata,
  BackupResult,
  BackupRestoreResult,
  BackupProgress,
  // Error types
  BackupErrorCode,
  BackupErrorInfo,
  BackupError,
  // Constants
  DEFAULT_BACKUP_DIR,
  DEFAULT_BACKUP_TYPE,
  DEFAULT_BACKUP_COMPRESSION,
  DEFAULT_RETENTION_COUNT,
  MAX_CONCURRENT_BACKUPS,
  BACKUP_MANIFEST_FILENAME,
  // Type guards
  isValidBackupType,
  isValidBackupStatus,
  isBackupError
} from './types/backup.types'
// Backup classes
export { BackupScheduler, ScheduledJob, ScheduleAdapter, DiskPathResolver, BackupSchedulerOptions } from './backup/BackupScheduler'
export { BackupScheduleService, CreateScheduleInput, UpdateScheduleInput, BackupScheduleServiceOptions } from './backup/BackupScheduleService'
export { BackupService, BackupServiceOptions, BackupServiceEvents, IsVmRunningProbe, GuestAgentFactory, GuestQuiesce } from './backup/BackupService'

// Guest agent (needed by consumers wiring the live-backup quiesce probe)
export { GuestAgentClient, GuestAgentClientOptions } from './core/GuestAgentClient'

// System classes
export { CgroupsManager } from './system/CgroupsManager'

// Utilities
export { Debugger } from './utils/debug'
export { CommandExecutor } from './utils/commandExecutor'
export { KeyedMutex } from './utils/KeyedMutex'
