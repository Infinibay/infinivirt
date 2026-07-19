import path from 'path'
import {
  MachineType,
  MachineOptions,
  DiskOptions,
  NetworkOptions,
  SpiceOptions,
  VncOptions,
  BootDevice,
  QemuProcessOptions,
  InfinigpuDeviceOptions,
  validatePciAddress
} from '../types/qemu.types'
import { SpiceConfig } from '../display/SpiceConfig'
import { VncConfig } from '../display/VncConfig'
import { CpuPinningAdapter, PinningStrategy, CpuPinningResult } from '../cpu/CpuPinningAdapter'
import { assertSafeOptionValue, assertSafePath, assertInEnum } from '../utils/qemuArgSafety'

/** Whitelists for per-disk enum fields — values that splice into the -drive
 *  comma-list (e.g. cache='none,readonly=on') must never be free-form. */
const ALLOWED_DISK_FORMATS: readonly string[] = ['qcow2', 'raw']
const ALLOWED_DISK_BUSES: readonly string[] = ['virtio', 'sata', 'scsi', 'ide']
const ALLOWED_DISK_CACHES: readonly string[] = ['none', 'writeback', 'writethrough', 'directsync', 'unsafe']

/**
 * Result of buildCommand() containing the binary and arguments separately
 */
export interface QemuCommand {
  command: string
  args: string[]
}

/**
 * Extended result of buildCommand() with CPU pinning wrapper support
 */
export interface QemuCommandWithPinning extends QemuCommand {
  /** Wrapper command (e.g., 'numactl') or null if no wrapper */
  wrapperCommand: string | null
  /** Arguments for the wrapper command */
  wrapperArgs: string[]
  /** Whether CPU pinning was applied */
  pinningApplied: boolean
  /** CPU cores used for pinning */
  pinnedCores: number[]
  /** NUMA nodes used for memory binding */
  numaNodes: number[]
}

/**
 * QemuCommandBuilder provides a fluent API for building QEMU command arrays.
 * It supports all essential QEMU options for VM management.
 */
export class QemuCommandBuilder {
  private static readonly ALLOWED_ROM_DIR = '/var/lib/infinization/roms/'

  private binary: string = 'qemu-system-x86_64'
  private args: string[] = []
  private daemonizeEnabled: boolean = false
  private pidfilePath: string | null = null

  // CPU pinning configuration
  private cpuPinningEnabled: boolean = false
  private cpuPinningStrategy: PinningStrategy = 'none'
  private cpuPinningVcpuCount: number = 0
  private cpuPinningAdapter: CpuPinningAdapter | null = null

  /**
   * Set the QEMU binary to use
   * @param binary - Path or name of the QEMU binary (default: qemu-system-x86_64)
   */
  setBinary (binary: string): this {
    this.binary = binary
    return this
  }

  /**
   * Get the configured binary name
   */
  getBinary (): string {
    return this.binary
  }

  /**
   * Check if daemonize is enabled
   */
  isDaemonizeEnabled (): boolean {
    return this.daemonizeEnabled
  }

  /**
   * Get the configured pidfile path
   */
  getPidfilePath (): string | null {
    return this.pidfilePath
  }

  /**
   * Validates that a ROM file path is within the allowed directory.
   * Prevents directory traversal attacks by normalizing the path.
   *
   * @param romfile - Path to ROM file
   * @returns The normalized absolute path
   * @throws Error if path is outside allowed directory
   */
  private static validateRomPath (romfile: string): string {
    // romfile is interpolated into the comma-delimited -device option, so a comma
    // would splice extra sub-options. Reject it (in addition to the dir confinement).
    assertSafePath(romfile, 'gpuRomfile')
    const normalizedPath = path.resolve(romfile)
    assertSafePath(normalizedPath, 'gpuRomfile')
    if (!normalizedPath.startsWith(QemuCommandBuilder.ALLOWED_ROM_DIR)) {
      throw new Error(
        `ROM file must be in ${QemuCommandBuilder.ALLOWED_ROM_DIR}. ` +
        `Attempted path: ${romfile}`
      )
    }
    return normalizedPath
  }

  /**
   * Enable KVM hardware acceleration
   */
  enableKvm (): this {
    this.args.push('-enable-kvm')
    return this
  }

  /**
   * Set machine type (q35 or pc)
   * @param type - Machine type
   * @param options - Optional machine options (accel, kernelIrqchip)
   */
  setMachine (type: MachineType, options?: MachineOptions): this {
    let machineArg = type
    if (options?.accel) {
      machineArg += `,accel=${options.accel}`
    }
    if (options?.kernelIrqchip) {
      machineArg += `,kernel-irqchip=${options.kernelIrqchip}`
    }
    this.args.push('-machine', machineArg)
    return this
  }

  /**
   * Set the emulated RTC base. Default 'utc' — QEMU's own default is already utc,
   * but we set it EXPLICITLY so the guest's hardware clock is UTC regardless of
   * host/QEMU defaults. Guests must be configured to read the RTC as UTC (Linux:
   * kickstart `timezone --utc` / Debian+Ubuntu default; Windows: registry
   * RealTimeIsUniversal=1). A skewed guest clock silently breaks the HMAC-signed
   * command channel (fail-closed on the agent's freshness window).
   * @param base - 'utc' (default) or 'localtime'
   */
  setRtc (base: 'utc' | 'localtime' = 'utc'): this {
    this.args.push('-rtc', `base=${base}`)
    return this
  }

  /**
   * Set CPU model and topology
   * @param model - CPU model (e.g., 'host')
   * @param cores - Number of CPU cores
   * @param threads - Threads per core (optional)
   * @param sockets - Number of sockets (optional)
   */
  setCpu (model: string, cores?: number, threads?: number, sockets?: number): this {
    // -cpu is a comma-delimited list (e.g. host,enforce=off,-vmx); reject any
    // value that could splice extra feature flags / sub-options.
    this.args.push('-cpu', assertSafeOptionValue(model, 'cpuModel'))
    if (cores !== undefined) {
      let smpArg = `cores=${cores}`
      if (threads !== undefined) {
        smpArg += `,threads=${threads}`
      }
      if (sockets !== undefined) {
        smpArg += `,sockets=${sockets}`
      }
      this.args.push('-smp', smpArg)
    }
    return this
  }

  /**
   * Set memory size in GB
   * @param sizeGB - Memory size in gigabytes
   */
  setMemory (sizeGB: number): this {
    this.args.push('-m', `${sizeGB}G`)
    return this
  }

  /**
   * Enable the QEMU seccomp sandbox (defense-in-depth).
   *
   * QEMU runs with broad host privileges and is directly reachable by a
   * (potentially compromised) guest. The seccomp sandbox blocks dangerous
   * syscalls so a QEMU exploit cannot trivially pivot to the host:
   *   - obsolete=deny          : block obsolete syscalls
   *   - elevateprivileges=deny : block setuid/setgid family
   *   - spawn=deny             : block fork/exec
   *   - resourcecontrol=deny   : block scheduler/affinity tampering
   * This mirrors the hardening libvirt applies by default.
   */
  enableSeccompSandbox (): this {
    this.args.push('-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny')
    return this
  }

  /**
   * Drop QEMU's privileges to an unprivileged user after startup (`-runas`).
   * Only emitted when a user is configured; on-prem deployments that run the
   * backend as root should set this so a guest escape lands as an unprivileged
   * uid rather than root.
   */
  setRunAs (user: string): this {
    this.args.push('-runas', assertSafeOptionValue(user, 'runAsUser'))
    return this
  }

  /**
   * Add multiple disk drives with proper indexing.
   * Each disk is added as a separate -drive argument with sequential index.
   *
   * @param disks - Array of disk configuration options
   * @returns this for method chaining
   *
   * @example
   * builder.addDisks([
   *   { path: '/path/disk1.qcow2', format: 'qcow2', bus: 'virtio', cache: 'writeback' },
   *   { path: '/path/disk2.qcow2', format: 'qcow2', bus: 'virtio', cache: 'writeback' }
   * ])
   * // Generates:
   * // -drive file=/path/disk1.qcow2,format=qcow2,if=virtio,cache=writeback,index=0,discard=unmap
   * // -drive file=/path/disk2.qcow2,format=qcow2,if=virtio,cache=writeback,index=1,discard=unmap
   */
  addDisks (disks: DiskOptions[]): this {
    disks.forEach((disk, index) => {
      // Validate every interpolated field against the comma/equals-splice attack.
      // A cache of `none,readonly=on` or bus of `none,snapshot=on` would otherwise
      // flip drive semantics (read-only / snapshot / unsafe-cache).
      const file = assertSafePath(disk.path, `disk[${index}].path`)
      const format = assertInEnum(disk.format, ALLOWED_DISK_FORMATS, `disk[${index}].format`)
      const bus = assertInEnum(disk.bus, ALLOWED_DISK_BUSES, `disk[${index}].bus`)
      const cache = assertInEnum(disk.cache, ALLOWED_DISK_CACHES, `disk[${index}].cache`)
      // file.locking=on makes qemu-img's lock a reliable backstop against a second
      // process (snapshot/convert) opening the same image while the VM runs.
      let driveArg = `file=${file},format=${format},if=${bus},cache=${cache},file.locking=on,index=${index}`
      if (disk.discard) {
        driveArg += ',discard=unmap'
      }
      this.args.push('-drive', driveArg)
    })
    return this
  }

  /**
   * Add a network interface using TAP device
   * @param options - Network configuration options
   */
  addNetwork (options: NetworkOptions): this {
    const safeTap = assertSafeOptionValue(options.tapName, 'network.tapName')
    let netdevArg = `tap,id=net0,ifname=${safeTap},script=no,downscript=no`
    if (options.queues !== undefined && options.queues > 1) {
      netdevArg += `,queues=${options.queues},vhost=on`
    }
    this.args.push('-netdev', netdevArg)

    const safeModel = assertSafeOptionValue(options.model, 'network.model')
    const safeMac = assertSafeOptionValue(options.mac, 'network.mac')
    let deviceArg = `${safeModel},netdev=net0,mac=${safeMac}`
    if (options.queues !== undefined && options.queues > 1) {
      deviceArg += `,mq=on,vectors=${options.queues * 2 + 2}`
    }
    this.args.push('-device', deviceArg)
    return this
  }

  /**
   * Add SPICE display with optional QXL memory configuration.
   *
   * @param options - SPICE configuration options or SpiceConfig instance
   * @param qxlMemoryMB - QXL video memory in MB (default: 16, use 64+ for 4K)
   *
   * @remarks
   * When using the legacy `SpiceOptions` object, the guest agent (virtio-serial for
   * copy/paste) is enabled by default. Set `enableAgent: false` to disable it.
   *
   * When using `SpiceConfig`, the guest agent behavior is controlled by the
   * `enableAgent` option passed to the SpiceConfig constructor (also defaults to true).
   *
   * **QXL Memory Sizing:**
   * - 16 MB: Default, suitable for 1920x1080 and below
   * - 32 MB: Recommended for 2560x1440
   * - 64 MB: Recommended for 4K (3840x2160) and above
   * - 128 MB: For multiple 4K displays or very high resolutions
   *
   * @example
   * ```typescript
   * // Using SpiceConfig (recommended)
   * const spiceConfig = new SpiceConfig({
   *   port: 5901,
   *   addr: '0.0.0.0',
   *   enableAgent: false  // Disable guest agent
   * })
   * builder.addSpice(spiceConfig)
   *
   * // Standard resolution
   * builder.addSpice(spiceConfig)
   *
   * // 4K resolution support
   * builder.addSpice(spiceConfig, 64)
   *
   * // Using legacy options
   * builder.addSpice({
   *   port: 5901,
   *   addr: '0.0.0.0',
   *   enableAgent: false  // Disable guest agent
   * })
   * ```
   */
  addSpice (options: SpiceOptions | SpiceConfig, qxlMemoryMB: number = 16): this {
    // Check if options is a SpiceConfig instance
    if (options instanceof SpiceConfig) {
      // Fail-closed: validate the config before emitting args (port range, addr,
      // password/ticketing consistency). Previously validate() was never called.
      const validation = options.validate()
      if (!validation.valid) {
        throw new Error(`Invalid SPICE configuration: ${validation.errors.join('; ')}`)
      }
      const { args } = options.generateArgs()
      this.args.push(...args)

      // Override -vga qxl with memory configuration if non-default
      if (qxlMemoryMB !== 16) {
        // Remove the -vga qxl that was added by generateArgs()
        const vgaIndex = this.args.lastIndexOf('-vga')
        if (vgaIndex !== -1) {
          this.args.splice(vgaIndex, 2) // Remove -vga and qxl
        }
        // Explicitly disable QEMU's default VGA to prevent dual VGA devices
        this.args.push('-vga', 'none')
        // Add QXL device with custom memory
        this.args.push('-device', `qxl-vga,vgamem_mb=${qxlMemoryMB}`)
      }

      // Add SPICE agent devices if enabled, using shared virtio-serial controller
      if (options.isAgentEnabled()) {
        this.ensureVirtioSerial()
        this.args.push('-device', 'virtserialport,chardev=spicechannel0,name=com.redhat.spice.0')
        this.args.push('-chardev', 'spicevmc,id=spicechannel0,name=vdagent')
      }
      return this
    }

    // Legacy options object handling
    let spiceArg = `port=${options.port},addr=${assertSafeOptionValue(options.addr, 'spice.addr')}`
    if (options.password) {
      // Reject a password that could splice sub-options (e.g. 'x,disable-ticketing=on')
      // which would turn a protected console into an open one. Prefer setting the
      // password over QMP (set_password) rather than on the command line.
      spiceArg += `,password=${assertSafeOptionValue(options.password, 'spice.password')}`
    } else if (options.disableTicketing) {
      spiceArg += ',disable-ticketing=on'
    }
    this.args.push('-spice', spiceArg)

    // Handle QXL memory for legacy options
    if (qxlMemoryMB !== 16) {
      this.args.push('-device', `qxl-vga,vgamem_mb=${qxlMemoryMB}`)
    } else {
      this.args.push('-vga', 'qxl')
    }

    // Add virtio-serial for guest agent (enabled by default), using shared controller
    const enableAgent = options.enableAgent ?? true
    if (enableAgent) {
      this.ensureVirtioSerial()
      this.args.push('-device', 'virtserialport,chardev=spicechannel0,name=com.redhat.spice.0')
      this.args.push('-chardev', 'spicevmc,id=spicechannel0,name=vdagent')
    }

    return this
  }

  /**
   * Add VNC display
   * @param options - VNC configuration options or VncConfig instance
   */
  addVnc (options: VncOptions | VncConfig): this {
    // Check if options is a VncConfig instance
    if (options instanceof VncConfig) {
      const { args } = options.generateArgs()
      this.args.push(...args)
      return this
    }

    // Legacy options object handling
    let vncArg = `${assertSafeOptionValue(options.addr, 'vnc.addr')}:${options.display}`
    if (options.password) {
      vncArg += ',password=on'
    }
    this.args.push('-vnc', vncArg)
    this.args.push('-vga', 'std')
    return this
  }

  /**
   * Add QMP socket for management
   * @param socketPath - Path to Unix socket
   */
  addQmp (socketPath: string): this {
    this.args.push('-qmp', `unix:${assertSafePath(socketPath, 'qmpSocketPath')},server,nowait`)
    return this
  }

  /**
   * Add CD-ROM drive
   * @param isoPath - Path to ISO file
   */
  addCdrom (isoPath: string): this {
    // QEMU expands -cdrom into a -drive internally; reject a comma/control char so
    // a config-supplied ISO path cannot splice drive sub-options.
    this.args.push('-cdrom', assertSafePath(isoPath, 'cdromIsoPath'))
    return this
  }

  /**
   * Add GPU passthrough via VFIO-PCI.
   *
   * Passes through a GPU to the VM for direct hardware access.
   * Automatically enables multifunction support for GPU passthrough.
   *
   * @param pciBus - PCI bus address (e.g., '01:00.0' or '0000:01:00.0')
   * @param romfile - Optional path to GPU ROM file (must be in /var/lib/infinization/roms/)
   * @returns this for method chaining
   * @throws Error if PCI address format is invalid
   *
   * @remarks
   * **Prerequisites:**
   * - IOMMU must be enabled in BIOS and kernel (intel_iommu=on or amd_iommu=on)
   * - vfio-pci kernel module must be loaded
   * - GPU must be bound to vfio-pci driver (not host driver)
   * - Use Q35 machine type for best compatibility
   *
   * **Important:**
   * - Host cannot use the GPU while it's passed through to VM
   * - UEFI firmware is recommended for GPU passthrough
   *
   * **Security:**
   * - ROM files must be located in /var/lib/infinization/roms/
   * - Path traversal attempts will be rejected
   *
   * @example
   * ```typescript
   * const builder = new QemuCommandBuilder()
   *   .enableKvm()
   *   .setMachine('q35')
   *   .addGpuPassthrough('01:00.0')
   *   .addGpuPassthrough('0000:02:00.0', '/var/lib/infinization/roms/gpu.rom')
   * ```
   */
  addGpuPassthrough (pciBus: string, romfile?: string): this {
    const validation = validatePciAddress(pciBus)
    if (!validation.valid) {
      throw new Error(`Invalid PCI address '${pciBus}': ${validation.error}`)
    }

    const safeRomfile = romfile ? QemuCommandBuilder.validateRomPath(romfile) : undefined

    let deviceArg = `vfio-pci,host=${pciBus},multifunction=on`
    if (safeRomfile) {
      deviceArg += `,romfile=${safeRomfile}`
    }
    this.args.push('-device', deviceArg)
    return this
  }

  /**
   * Attach an **infinigpu** virtual GPU: a vfio-user PCI device served out-of-process by
   * the `infinigpu-device` server (started separately, before QEMU). Unlike
   * {@link addGpuPassthrough} (which dedicates a whole physical GPU to one VM), infinigpu
   * lets many VMs share one GPU under the host broker — so this is the density path.
   *
   * **Opt-in only** — call this exclusively when a department has GPU enabled; existing
   * VMs that don't call it are completely unaffected. See the infinigpu repo's
   * `docs/INTEGRATION.md`.
   *
   * It (1) adds a `memory-backend-memfd` so the device can mmap guest RAM zero-copy
   * (`share=on` is mandatory), (2) makes the machine consume that backend, (3) forces
   * `-vga none` so our device is the guest's only display (fbcon binds fb0 to us), and
   * (4) adds the vfio-user device in **JSON** form.
   *
   * @remarks
   * - **`x-no-posted-writes=true` is mandatory**: the `vfio_user` v0.1.3 server always
   *   replies to `REGION_WRITE`, but QEMU posts MMIO writes by default → protocol desync
   *   the moment a guest driver writes a BAR.
   * - `x-pci-class-code=229376` = `0x038000` (Display-Other).
   * - Requires a QEMU built with the upstream `vfio-user-pci` client (QEMU ≥ 10.1).
   * - Don't combine with SPICE/VNC `qxl`/`std` VGA on the same VM — infinigpu is the display.
   */
  addInfinigpuDevice (options: InfinigpuDeviceOptions): this {
    const socket = assertSafePath(options.socketPath, 'infinigpuSocketPath')
    const size = Math.floor(options.guestRamBytes)
    if (!Number.isFinite(size) || size <= 0) {
      throw new Error('addInfinigpuDevice: guestRamBytes must be a positive integer (bytes)')
    }

    // 1. memfd-backed guest RAM the device can mmap zero-copy (share=on is mandatory).
    //    Fix E (opt-in, env INFINIGPU_NUMA_NODE=<node>): pin the guest RAM to the GPU's NUMA node
    //    (host-nodes + policy=bind) and pre-fault it (prealloc=on) so the per-submit command/frame
    //    DMA stays node-local and never pays a first-touch page fault. Unset → unchanged behavior.
    //    (Set it to the node of the GPU this VM uses; a proper per-VM mapping is future work.)
    let memfd = `memory-backend-memfd,id=mem0,share=on,size=${size}`
    const rawNumaNode = process.env.INFINIGPU_NUMA_NODE
    if (rawNumaNode !== undefined && /^\d+$/.test(rawNumaNode.trim())) {
      const node = parseInt(rawNumaNode.trim(), 10)
      memfd += `,prealloc=on,host-nodes=${node},policy=bind`
    }
    this.args.push('-object', memfd)

    // 2. the machine must consume that backend; augment the existing -machine (added by
    //    setMachine) or add a q35 one if the caller hasn't set the machine yet.
    const mi = this.args.indexOf('-machine')
    if (mi >= 0 && mi + 1 < this.args.length) {
      if (!/(^|,)memory-backend=/.test(this.args[mi + 1])) {
        this.args[mi + 1] += ',memory-backend=mem0'
      }
    } else {
      this.args.push('-machine', 'q35,accel=kvm,memory-backend=mem0')
    }

    // 3. no default VGA, so our device is the guest's only display.
    const vi = this.args.indexOf('-vga')
    if (vi >= 0 && vi + 1 < this.args.length) {
      this.args[vi + 1] = 'none'
    } else {
      this.args.push('-vga', 'none')
    }

    // 4. the vfio-user device — JSON form (socket is a SocketAddress union, so the flat
    //    comma form is rejected). See @remarks for why x-no-posted-writes is mandatory.
    const device = JSON.stringify({
      driver: 'vfio-user-pci',
      socket: { path: socket, type: 'unix' },
      'x-pci-class-code': 229376,
      'x-no-posted-writes': true
    })
    this.args.push('-device', device)
    return this
  }

  /**
   * Add GPU passthrough with integrated audio (HDMI/DisplayPort audio).
   *
   * Modern GPUs often have a separate audio function for HDMI/DisplayPort audio output.
   * This method passes through both the GPU and its audio device.
   *
   * @param gpuBus - PCI bus address of the GPU (e.g., '01:00.0')
   * @param audioBus - PCI bus address of the audio function (e.g., '01:00.1') - must differ from gpuBus
   * @param romfile - Optional path to GPU ROM file
   * @returns this for method chaining
   * @throws Error if any PCI address format is invalid
   * @throws Error if gpuBus and audioBus are the same address
   *
   * @remarks
   * Typical NVIDIA/AMD GPU configuration:
   * - GPU function: 01:00.0 (VGA controller)
   * - Audio function: 01:00.1 (Audio device)
   *
   * Use `lspci` to find the correct addresses for your GPU.
   *
   * @example
   * ```typescript
   * const builder = new QemuCommandBuilder()
   *   .enableKvm()
   *   .setMachine('q35')
   *   .addGpuWithAudio('01:00.0', '01:00.1')
   * ```
   */
  addGpuWithAudio (gpuBus: string, audioBus: string, romfile?: string): this {
    const gpuValidation = validatePciAddress(gpuBus)
    if (!gpuValidation.valid) {
      throw new Error(`Invalid GPU PCI address '${gpuBus}': ${gpuValidation.error}`)
    }

    const audioValidation = validatePciAddress(audioBus)
    if (!audioValidation.valid) {
      throw new Error(`Invalid audio PCI address '${audioBus}': ${audioValidation.error}`)
    }

    // Guard: GPU and audio PCI addresses must differ
    if (gpuBus === audioBus) {
      throw new Error(
        `GPU and audio PCI addresses must differ. ` +
        `Both were set to '${gpuBus}'. ` +
        `Typically, GPU is at xx:xx.0 and audio at xx:xx.1 (e.g., 01:00.0 and 01:00.1)`
      )
    }

    // Add GPU with multifunction enabled
    this.addGpuPassthrough(gpuBus, romfile)

    // Add audio device without multifunction
    this.args.push('-device', `vfio-pci,host=${audioBus}`)

    return this
  }

  /**
   * Add generic PCI device passthrough via VFIO-PCI.
   *
   * Passes through any PCI device to the VM. Unlike `addGpuPassthrough`,
   * this method does not enable multifunction by default.
   *
   * Useful for passing through USB controllers, network cards, storage
   * controllers, and other PCI devices.
   *
   * @param pciBus - PCI bus address (e.g., '04:00.0' or '0000:04:00.0')
   * @param romfile - Optional path to device ROM file (must be in /var/lib/infinization/roms/)
   * @returns this for method chaining
   * @throws Error if PCI address format is invalid
   *
   * @remarks
   * **Prerequisites:**
   * - IOMMU must be enabled
   * - Device must be bound to vfio-pci driver
   * - Check IOMMU groups to ensure isolation
   *
   * **Security:**
   * - ROM files must be located in /var/lib/infinization/roms/
   * - Path traversal attempts will be rejected
   *
   * @example
   * ```typescript
   * const builder = new QemuCommandBuilder()
   *   .enableKvm()
   *   .setMachine('q35')
   *   .addPciPassthrough('04:00.0')  // USB controller
   *   .addPciPassthrough('05:00.0')  // Network card
   * ```
   */
  addPciPassthrough (pciBus: string, romfile?: string): this {
    const validation = validatePciAddress(pciBus)
    if (!validation.valid) {
      throw new Error(`Invalid PCI address '${pciBus}': ${validation.error}`)
    }

    const safeRomfile = romfile ? QemuCommandBuilder.validateRomPath(romfile) : undefined

    let deviceArg = `vfio-pci,host=${pciBus}`
    if (safeRomfile) {
      deviceArg += `,romfile=${safeRomfile}`
    }
    this.args.push('-device', deviceArg)
    return this
  }

  /**
   * Add memory balloon device for dynamic memory management.
   *
   * The virtio-balloon device enables dynamic memory management, allowing the host
   * to reclaim memory from or grant memory to the guest at runtime.
   *
   * @returns this for method chaining
   *
   * @remarks
   * **Guest Requirements:**
   * - The guest OS must have the virtio-balloon driver installed
   * - Linux guests typically have this driver built-in
   * - Windows guests require virtio drivers to be installed
   *
   * **Runtime Control:**
   * - Use QMP `balloon` command to request memory size changes
   * - Use QMP `query-balloon` to check current balloon size
   *
   * **Recommended Use Cases:**
   * - Memory overcommitment scenarios
   * - Dynamic resource allocation based on workload
   * - Consolidation of VMs on a single host
   *
   * @example
   * ```typescript
   * const builder = new QemuCommandBuilder()
   *   .enableKvm()
   *   .setMachine('q35')
   *   .setMemory(8)
   *   .addMemoryBalloon()  // Enable dynamic memory management
   *   .addDisk({ ... })
   * ```
   */
  addMemoryBalloon (): this {
    this.args.push('-device', 'virtio-balloon-pci')
    return this
  }

  /**
   * Enable hugepages for improved memory performance.
   *
   * Hugepages reduce TLB misses and improve memory access performance for VMs
   * with large memory allocations. Requires host system to have hugepages
   * configured and mounted at /dev/hugepages.
   *
   * @returns this for method chaining
   *
   * @remarks
   * **Host Requirements:**
   * - Hugepages must be configured in kernel boot parameters
   * - /dev/hugepages must be mounted (typically via systemd)
   * - Sufficient hugepages must be allocated for the VM's memory size
   *
   * **Configuration:**
   * - Add to kernel boot params: `hugepagesz=2M hugepages=N` (where N = total GB * 512)
   * - Verify with: `cat /proc/meminfo | grep Huge`
   * - Check mount: `mount | grep hugepages`
   *
   * **Performance Impact:**
   * - Reduces TLB pressure for large memory VMs (>4GB)
   * - Improves memory-intensive workload performance
   * - Requires pre-allocation (memory not swappable)
   *
   * @example
   * ```typescript
   * const builder = new QemuCommandBuilder()
   *   .enableKvm()
   *   .setMachine('q35')
   *   .setMemory(16)
   *   .enableHugepages()  // Enable hugepages for 16GB VM
   *   .addDisk({ ... })
   * ```
   */
  enableHugepages (): this {
    this.args.push('-mem-prealloc')
    this.args.push('-mem-path', '/dev/hugepages')
    return this
  }

  /**
   * Set firmware for UEFI boot using OVMF.
   *
   * Configures the VM to boot with UEFI firmware instead of legacy BIOS.
   * Requires OVMF firmware files to be installed on the host system.
   *
   * @param firmwarePath - Path to OVMF code file (e.g., /usr/share/OVMF/OVMF_CODE.fd)
   * @returns this for method chaining
   *
   * @remarks
   * **OVMF Files Required:**
   * - Code file: Contains UEFI firmware code (read-only)
   * - Vars file: Contains UEFI variables (read-write, per-VM)
   *
   * **Secure Boot:**
   * For UEFI Secure Boot, callers must provide a Secure Boot-capable firmware file
   * (e.g., OVMF_CODE.secboot.fd instead of OVMF_CODE.fd). This method does not
   * modify QEMU arguments based on Secure Boot status - the firmware file itself
   * determines whether Secure Boot is available to the guest.
   *
   * **Host Requirements:**
   * - Install ovmf package: `apt install ovmf` (Debian/Ubuntu) or `dnf install edk2-ovmf` (Fedora/RHEL)
   * - Files typically located in /usr/share/OVMF/ or /usr/share/edk2/ovmf/
   *
   * @example
   * ```typescript
   * // Standard UEFI boot
   * builder.setFirmware('/usr/share/OVMF/OVMF_CODE.fd')
   *
   * // UEFI with Secure Boot (use secboot-capable firmware)
   * builder.setFirmware('/usr/share/OVMF/OVMF_CODE.secboot.fd')
   * ```
   */
  setFirmware (firmwarePath: string): this {
    // A firmware path with a comma (e.g. '/x.fd,readonly=off') would flip the
    // OVMF code drive to writable — reject it.
    const safe = assertSafePath(firmwarePath, 'firmwarePath')
    // Add OVMF code (read-only firmware)
    this.args.push('-drive', `if=pflash,format=raw,readonly=on,file=${safe}`)

    // Note: OVMF vars file (per-VM UEFI variables) should be passed via setUefiVars
    // to ensure each VM has its own vars file.

    return this
  }

  /**
   * Set UEFI variables file for per-VM UEFI settings persistence.
   *
   * This file stores UEFI variables (boot entries, secure boot state, etc.)
   * and should be unique to each VM. The file should be created by copying
   * a template file (e.g., /usr/share/OVMF/OVMF_VARS.fd) to the VM's directory.
   *
   * @param varsPath - Path to the VM-specific UEFI vars file
   * @returns this for method chaining
   *
   * @example
   * ```typescript
   * // Create UEFI boot with per-VM vars
   * builder
   *   .setFirmware('/usr/share/OVMF/OVMF_CODE.fd')
   *   .setUefiVars('/var/lib/infinization/vms/myvm/uefi-vars.fd')
   * ```
   */
  setUefiVars (varsPath: string): this {
    // Add OVMF vars (read-write per-VM variables)
    this.args.push('-drive', `if=pflash,format=raw,file=${assertSafePath(varsPath, 'uefiVarsPath')}`)
    return this
  }

  /**
   * Set boot order.
   *
   * @param devices - Persistent boot order (c=disk, d=cdrom, n=network). Applied
   *   on every boot EXCEPT the first when `opts.once` is given.
   * @param opts.once - One-time boot device for the FIRST boot only; QEMU reverts
   *   to `devices` on the next (guest-initiated) reboot. This is the correct way to
   *   boot an installer ISO: boot the CD ONCE, then the freshly-installed disk on
   *   the post-install reboot. Without it, `order=dc` boots the CD on EVERY reboot,
   *   so a finished install re-enters the installer forever — a boot/install loop
   *   that the reset detector eventually kills (InstallResetTracker).
   */
  setBootOrder (devices: BootDevice[], opts?: { once?: BootDevice }): this {
    const parts = [`order=${devices.join('')}`]
    if (opts?.once) parts.push(`once=${opts.once}`)
    this.args.push('-boot', parts.join(','))
    return this
  }

  // ===========================================================================
  // TPM Support
  // ===========================================================================

  /**
   * Add TPM 2.0 emulator device.
   *
   * Requires swtpm to be running. The socket path should point to the
   * swtpm control socket.
   *
   * @param socketPath - Path to swtpm socket (e.g., /var/lib/swtpm/vmid/swtpm-sock)
   * @returns this for method chaining
   *
   * @example
   * ```typescript
   * // Add TPM 2.0 with swtpm
   * builder.addTPM('/var/lib/swtpm/my-vm/swtpm-sock')
   * ```
   */
  addTPM (socketPath: string): this {
    // chardev for swtpm socket
    this.args.push('-chardev', `socket,id=chrtpm,path=${assertSafePath(socketPath, 'tpmSocketPath')}`)
    // TPM device backend
    this.args.push('-tpmdev', 'emulator,id=tpm0,chardev=chrtpm')
    // TPM TIS device
    this.args.push('-device', 'tpm-tis,tpmdev=tpm0')
    return this
  }

  // ===========================================================================
  // VirtIO Serial Channels
  // ===========================================================================

  private virtioSerialAdded: boolean = false
  private virtioSerialPortCount: number = 0

  /**
   * Ensures virtio-serial-pci controller is added (only once).
   * Called automatically by addVirtioChannel methods.
   */
  private ensureVirtioSerial (): void {
    if (!this.virtioSerialAdded) {
      this.args.push('-device', 'virtio-serial-pci,id=virtio-serial0')
      this.virtioSerialAdded = true
    }
  }

  /**
   * Add a VirtIO serial channel with Unix socket backend.
   *
   * This is the base method for adding virtio-serial channels like
   * QEMU Guest Agent, InfiniService, etc.
   *
   * @param channelName - The virtio channel name (e.g., 'org.qemu.guest_agent.0')
   * @param socketPath - Path to Unix socket for host communication
   * @param chardevId - Unique chardev identifier
   * @returns this for method chaining
   */
  addVirtioChannel (channelName: string, socketPath: string, chardevId: string): this {
    this.ensureVirtioSerial()

    const safePath = assertSafePath(socketPath, 'virtioChannel.socketPath')
    const safeId = assertSafeOptionValue(chardevId, 'virtioChannel.chardevId')
    const safeName = assertSafeOptionValue(channelName, 'virtioChannel.channelName')

    // Add chardev for socket communication
    this.args.push('-chardev', `socket,path=${safePath},server=on,wait=off,id=${safeId}`)

    // Add virtio serial port
    this.args.push('-device', `virtserialport,chardev=${safeId},name=${safeName}`)

    this.virtioSerialPortCount++
    return this
  }

  /**
   * Add QEMU Guest Agent channel.
   *
   * Enables communication with qemu-guest-agent inside the VM for:
   * - File operations (read/write files)
   * - Network configuration
   * - Process execution
   * - System commands (shutdown, suspend)
   *
   * @param socketPath - Path to guest agent socket
   * @returns this for method chaining
   *
   * @example
   * ```typescript
   * builder.addGuestAgentChannel('/var/run/qemu/vm1-ga.sock')
   * ```
   */
  addGuestAgentChannel (socketPath: string): this {
    return this.addVirtioChannel(
      'org.qemu.guest_agent.0',
      socketPath,
      'chagent0'
    )
  }

  /**
   * Add InfiniService channel for custom host-VM communication.
   *
   * Used for metrics collection, health monitoring, and management
   * operations specific to Infinibay.
   *
   * @param socketPath - Path to InfiniService socket
   * @returns this for method chaining
   *
   * @example
   * ```typescript
   * builder.addInfiniServiceChannel('/opt/infinibay/sockets/vm-123.socket')
   * ```
   */
  addInfiniServiceChannel (socketPath: string): this {
    return this.addVirtioChannel(
      'org.infinibay.agent',
      socketPath,
      'chinfini0'
    )
  }

  // ===========================================================================
  // Additional CD-ROM Support
  // ===========================================================================

  private cdromCount: number = 0

  /**
   * Add an additional CD-ROM drive.
   *
   * Useful for attaching VirtIO drivers ISO alongside the installation ISO.
   *
   * @param isoPath - Path to ISO file
   * @param index - Optional drive index (auto-incremented if not specified)
   * @returns this for method chaining
   *
   * @example
   * ```typescript
   * // Add installation ISO
   * builder.addCdrom('/path/to/install.iso')
   * // Add VirtIO drivers ISO
   * builder.addSecondCdrom('/path/to/virtio-win.iso')
   * ```
   */
  addSecondCdrom (isoPath: string): this {
    this.cdromCount++
    // Use SATA/AHCI for q35 machines which is more reliable than IDE index
    // This avoids conflicts with -cdrom which uses a fixed index
    const driveId = `cdrom${this.cdromCount}`
    // file=${isoPath} is in a comma-delimited -drive option — a comma in the ISO
    // path would splice sub-options (e.g. flip readonly off). Validate it.
    const safeIso = assertSafePath(isoPath, 'secondCdromIsoPath')
    this.args.push(
      '-drive', `file=${safeIso},if=none,media=cdrom,readonly=on,id=${driveId}`,
      '-device', `ide-cd,drive=${driveId}`
    )
    return this
  }

  // ===========================================================================
  // Audio Device Support
  // ===========================================================================

  /**
   * Add audio device for VM sound support.
   *
   * Uses Intel HDA with output to SPICE for remote audio.
   *
   * @returns this for method chaining
   */
  addAudioDevice (): this {
    // Intel HDA audio controller
    this.args.push('-device', 'intel-hda')
    // HDA output linked to SPICE audiodev
    this.args.push('-device', 'hda-duplex,audiodev=audio0')
    // Audio backend to SPICE
    this.args.push('-audiodev', 'spice,id=audio0')
    return this
  }

  // ===========================================================================
  // USB Support
  // ===========================================================================

  private usbControllerAdded: boolean = false

  /**
   * Ensures USB controller is added (only once).
   */
  private ensureUsbController (): void {
    if (!this.usbControllerAdded) {
      this.args.push('-device', 'qemu-xhci,id=usb')
      this.usbControllerAdded = true
    }
  }

  /**
   * Add USB tablet input device for better mouse synchronization.
   *
   * Provides absolute positioning which works better with SPICE/VNC
   * than relative mouse movement.
   *
   * @returns this for method chaining
   */
  addUsbTablet (): this {
    this.ensureUsbController()
    this.args.push('-device', 'usb-tablet')
    return this
  }

  /**
   * Add USB keyboard device.
   *
   * @returns this for method chaining
   */
  addUsbKeyboard (): this {
    this.ensureUsbController()
    this.args.push('-device', 'usb-kbd')
    return this
  }

  /**
   * Set process options (name, uuid, daemonize, pidfile)
   * @param options - Process configuration options
   */
  setProcessOptions (options: QemuProcessOptions): this {
    // -name is parsed as a comma-delimited option list (guest=...,debug-threads=...);
    // reject a name that could splice sub-options like 'x,debug-threads=on'.
    this.args.push('-name', assertSafeOptionValue(options.name, 'name'))
    if (options.uuid) {
      this.args.push('-uuid', assertSafeOptionValue(options.uuid, 'uuid'))
    }
    if (options.daemonize) {
      this.args.push('-daemonize')
      this.daemonizeEnabled = true
    }
    if (options.pidfile) {
      const safePidfile = assertSafePath(options.pidfile, 'pidfile')
      this.args.push('-pidfile', safePidfile)
      this.pidfilePath = safePidfile
    }
    return this
  }

  /**
   * Add a raw argument for advanced use cases
   * @param arg - Raw argument string
   */
  addRawArg (arg: string): this {
    this.args.push(arg)
    return this
  }

  // ===========================================================================
  // CPU Pinning Support
  // ===========================================================================

  /**
   * Enable CPU pinning with the specified strategy.
   *
   * When enabled, buildCommandWithPinning() will wrap the QEMU command with
   * `numactl` to pin vCPUs to specific physical cores and bind memory to
   * appropriate NUMA nodes.
   *
   * @param strategy - Pinning strategy: 'basic' (sequential) or 'hybrid' (randomized)
   * @param vcpuCount - Number of virtual CPUs for the VM
   * @returns this for method chaining
   *
   * @example
   * ```typescript
   * const builder = new QemuCommandBuilder()
   *   .enableKvm()
   *   .setMachine('q35')
   *   .setCpu('host', 4)
   *   .enableCpuPinning('basic', 4)
   *   .addDisk(...)
   *
   * const { wrapperCommand, wrapperArgs, command, args } = await builder.buildCommandWithPinning()
   * // wrapperCommand: 'numactl'
   * // wrapperArgs: ['--physcpubind=0,1,2,3', '--membind=0']
   * // command: 'qemu-system-x86_64'
   * // args: [...QEMU args...]
   * ```
   */
  enableCpuPinning (strategy: PinningStrategy, vcpuCount: number): this {
    if (strategy !== 'none' && vcpuCount > 0) {
      this.cpuPinningEnabled = true
      this.cpuPinningStrategy = strategy
      this.cpuPinningVcpuCount = vcpuCount
      this.cpuPinningAdapter = new CpuPinningAdapter()
    }
    return this
  }

  /**
   * Check if CPU pinning is enabled
   */
  isCpuPinningEnabled (): boolean {
    return this.cpuPinningEnabled
  }

  /**
   * Get the configured CPU pinning strategy
   */
  getCpuPinningStrategy (): PinningStrategy {
    return this.cpuPinningStrategy
  }

  /**
   * Build and return the command and arguments separately
   * @returns Object with command (binary) and args array
   */
  buildCommand (): QemuCommand {
    return {
      command: this.binary,
      args: [...this.args]
    }
  }

  /**
   * Build and return the command with CPU pinning wrapper (if enabled).
   *
   * This is the preferred method when CPU pinning is configured. It returns
   * both the QEMU command and the numactl wrapper configuration.
   *
   * @returns Promise resolving to QemuCommandWithPinning
   *
   * @example
   * ```typescript
   * const result = await builder.buildCommandWithPinning()
   * if (result.wrapperCommand) {
   *   // Execute: numactl --physcpubind=0,1,2,3 --membind=0 qemu-system-x86_64 [args...]
   *   spawn(result.wrapperCommand, [...result.wrapperArgs, result.command, ...result.args])
   * } else {
   *   // Execute: qemu-system-x86_64 [args...]
   *   spawn(result.command, result.args)
   * }
   * ```
   */
  async buildCommandWithPinning (): Promise<QemuCommandWithPinning> {
    const baseCommand = this.buildCommand()

    // If CPU pinning is not enabled, return without wrapper
    if (!this.cpuPinningEnabled || !this.cpuPinningAdapter) {
      return {
        ...baseCommand,
        wrapperCommand: null,
        wrapperArgs: [],
        pinningApplied: false,
        pinnedCores: [],
        numaNodes: []
      }
    }

    // Generate CPU pinning command wrapper
    const pinningResult = await this.cpuPinningAdapter.generatePinningCommand(
      this.cpuPinningVcpuCount,
      this.cpuPinningStrategy,
      baseCommand.command,
      baseCommand.args
    )

    return {
      command: baseCommand.command,
      args: baseCommand.args,
      wrapperCommand: pinningResult.wrapperCommand,
      wrapperArgs: pinningResult.wrapperArgs,
      pinningApplied: pinningResult.pinningApplied,
      pinnedCores: pinningResult.pinnedCores,
      numaNodes: pinningResult.numaNodes
    }
  }

  /**
   * Build and return only the arguments array (without the binary)
   * @returns Copy of the command arguments array
   */
  build (): string[] {
    return [...this.args]
  }
}

/**
 * IMPORTANT: This builder does NOT use the -no-shutdown flag.
 *
 * QEMU Default Behavior (without -no-shutdown):
 * - When guest OS performs ACPI shutdown (via system_powerdown or guest-initiated)
 * - QEMU automatically exits after guest completes shutdown sequence
 * - No explicit 'quit' command needed
 *
 * This is the recommended behavior for production VMs as it ensures:
 * 1. Clean resource cleanup by QEMU itself
 * 2. Proper exit codes reflecting shutdown success/failure
 * 3. No orphaned QEMU processes
 *
 * Reference: https://stackoverflow.com/questions/45026716/
 */
