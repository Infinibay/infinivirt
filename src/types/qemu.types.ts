import { QMPSocketOptions } from './qmp.types'

// =============================================================================
// GPU Passthrough Types and Validation
// =============================================================================

/**
 * Regular expression for validating PCI addresses.
 * Matches both short format (01:00.0) and long format (0000:01:00.0).
 *
 * @example
 * ```typescript
 * PCI_ADDRESS_REGEX.test('01:00.0')       // true (short format)
 * PCI_ADDRESS_REGEX.test('0000:01:00.0')  // true (long format)
 * PCI_ADDRESS_REGEX.test('invalid')       // false
 * ```
 */
export const PCI_ADDRESS_REGEX = /^([0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$/

/**
 * Result of PCI address validation.
 */
export interface PciAddressValidationResult {
  /** Whether the address is valid */
  valid: boolean
  /** Error message if invalid */
  error?: string
}

/**
 * Validates a PCI address format.
 *
 * @param address - PCI address to validate (e.g., '01:00.0' or '0000:01:00.0')
 * @returns Validation result with valid flag and optional error message
 *
 * @example
 * ```typescript
 * const result = validatePciAddress('01:00.0')
 * if (!result.valid) {
 *   console.error(result.error)
 * }
 * ```
 */
export function validatePciAddress (address: string): PciAddressValidationResult {
  if (!address || typeof address !== 'string') {
    return {
      valid: false,
      error: 'PCI address must be a non-empty string'
    }
  }

  if (!PCI_ADDRESS_REGEX.test(address)) {
    return {
      valid: false,
      error: `Invalid PCI address format '${address}'. Expected format: 'XX:XX.X' (short) or 'XXXX:XX:XX.X' (long), where X is a hexadecimal digit`
    }
  }

  return { valid: true }
}

/**
 * Normalizes a PCI address to long format (domain:bus:slot.function).
 *
 * @param address - PCI address to normalize (e.g., '01:00.0')
 * @returns Normalized long format address (e.g., '0000:01:00.0')
 * @throws Error if the address format is invalid
 *
 * @example
 * ```typescript
 * normalizePciAddress('01:00.0')       // '0000:01:00.0'
 * normalizePciAddress('0000:01:00.0')  // '0000:01:00.0' (unchanged)
 * ```
 */
export function normalizePciAddress (address: string): string {
  const validation = validatePciAddress(address)
  if (!validation.valid) {
    throw new Error(validation.error)
  }

  // Already in long format (has domain prefix)
  if (address.length > 7 && address[4] === ':') {
    return address.toLowerCase()
  }

  // Short format - prepend default domain 0000
  return `0000:${address}`.toLowerCase()
}

/**
 * Options for GPU passthrough configuration.
 *
 * @example
 * ```typescript
 * const gpuOptions: GpuPassthroughOptions = {
 *   pciBus: '01:00.0',
 *   romfile: '/var/lib/vfio/gpu.rom',
 *   multifunction: true,
 *   audioFunction: '01:00.1'
 * }
 * ```
 */
export interface GpuPassthroughOptions {
  /** PCI address of the GPU (required) */
  pciBus: string
  /** Path to GPU ROM file (optional, some GPUs require custom ROM) */
  romfile?: string
  /** Enable multifunction support (default: false, set to true for GPU passthrough) */
  multifunction?: boolean
  /** PCI address of the GPU's audio function (optional, e.g., '01:00.1' for HDMI audio) */
  audioFunction?: string
}

// =============================================================================
// QEMU Types
// =============================================================================

/**
 * Machine type union for QEMU -machine option
 */
export type MachineType = 'q35' | 'pc'

/**
 * Disk bus type for QEMU -drive if= option
 */
export type DiskBus = 'virtio' | 'sata' | 'scsi' | 'ide'

/**
 * Cache mode for QEMU -drive cache= option
 */
export type CacheMode = 'none' | 'writeback' | 'writethrough' | 'directsync' | 'unsafe'

/**
 * Display type for graphics output
 */
export type DisplayType = 'spice' | 'vnc' | 'none'

/**
 * VGA type for QEMU -vga option
 */
export type VgaType = 'std' | 'qxl' | 'virtio' | 'cirrus' | 'none'

/**
 * Boot device for QEMU -boot order= option
 * c = hard disk, d = cdrom, n = network
 */
export type BootDevice = 'c' | 'd' | 'n'

/**
 * Options for QEMU -machine option
 */
export interface MachineOptions {
  accel?: string
  kernelIrqchip?: string
}

/**
 * Options for the infinigpu virtual GPU (a vfio-user PCI device served out-of-process by
 * the `infinigpu-device` server). Opt-in per VM — attached only when a department enables
 * GPU. See the infinigpu repo's docs/INTEGRATION.md.
 */
export interface InfinigpuDeviceOptions {
  /** UNIX socket the infinigpu-device server listens on (QEMU connects to it at boot). */
  socketPath: string
  /**
   * Guest RAM size in **bytes**. The device mmaps guest RAM zero-copy through a
   * `memory-backend-memfd`, so the machine's memory backend size must match `-m`.
   */
  guestRamBytes: number
}

/**
 * Options for disk configuration
 */
export interface DiskOptions {
  path: string
  format: 'qcow2' | 'raw'
  bus: DiskBus
  cache: CacheMode
  discard?: boolean
}

/**
 * Options for network configuration
 */
export interface NetworkOptions {
  tapName: string
  mac: string
  model: 'virtio-net-pci' | 'e1000'
  queues?: number
}

/**
 * Options for SPICE display
 */
export interface SpiceOptions {
  port: number
  addr: string
  password?: string
  disableTicketing?: boolean
  /**
   * Enable SPICE guest agent for copy/paste via virtio-serial.
   * Defaults to true. Set to false to disable guest agent devices.
   */
  enableAgent?: boolean
}

/**
 * Options for VNC display
 */
export interface VncOptions {
  display: number
  addr: string
  password?: boolean
}

/**
 * Options for QEMU process management
 */
export interface QemuProcessOptions {
  vmId: string
  name: string
  uuid?: string
  daemonize?: boolean
  pidfile?: string
  qmpSocket?: QMPSocketOptions
}
