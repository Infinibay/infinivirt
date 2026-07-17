/**
 * VMLifecycle - Orchestrates VM lifecycle operations
 *
 * This class coordinates all components required for VM operations:
 * - QemuProcess for QEMU process management
 * - QMPClient for VM control via QMP protocol
 * - TapDeviceManager for network device setup
 * - NftablesService for firewall management
 * - QemuImgService for disk operations
 * - PrismaAdapter for database operations
 * - EventHandler for event monitoring
 *
 * @example
 * ```typescript
 * const lifecycle = new VMLifecycle(prismaAdapter, eventHandler)
 *
 * const result = await lifecycle.create({
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
 * await lifecycle.stop(result.vmId, { graceful: true, timeout: 30000 })
 * ```
 */

import * as fs from 'fs'
import * as path from 'path'
import { QemuProcess } from './QemuProcess'
import { QMPClient } from './QMPClient'
import { QemuCommandBuilder } from './QemuCommandBuilder'
import { TapDeviceManager } from '../network/TapDeviceManager'
import { NftablesService } from '../network/NftablesService'
import { MacAddressGenerator } from '../network/MacAddressGenerator'
import { QemuImgService } from '../storage/QemuImgService'
import { SpiceConfig } from '../display/SpiceConfig'
import { VncConfig } from '../display/VncConfig'
import { SPICE_MIN_PORT, SPICE_MAX_PORT, DEFAULT_SPICE_ADDR, DEFAULT_VNC_ADDR, VNC_BASE_PORT, isLoopbackAddr, resolveBindAddress } from '../types/display.types'
import * as os from 'os'
import { assertSafeOptionValue } from '../utils/qemuArgSafety'
import type { InfinizationDatabase } from '../db/PrismaAdapter'
import { EventHandler } from '../sync/EventHandler'
import { Debugger } from '../utils/debug'
import { sleep } from '../utils/retry'
import {
  VMCreateConfig,
  VMCreateResult,
  VMStartConfig,
  VMStopConfig,
  VMOperationResult,
  VMStatusResult,
  LifecycleError,
  LifecycleErrorCode,
  EventManagerLike,
  DEFAULT_STOP_TIMEOUT,
  DEFAULT_BOOT_TIMEOUT,
  DEFAULT_QMP_CONNECT_TIMEOUT,
  DEFAULT_QMP_SOCKET_DIR,
  DEFAULT_DISK_DIR,
  DEFAULT_PIDFILE_DIR,
  DEFAULT_NETWORK_MODEL,
  DEFAULT_DISK_FORMAT,
  DEFAULT_DISK_BUS,
  DEFAULT_DISK_CACHE,
  RESTART_DELAY_MS,
  PROCESS_EXIT_POLL_INTERVAL,
  RUNTIME_DISK_SIZE_PLACEHOLDER_GB
} from '../types/lifecycle.types'
import { FirewallRuleInput, FirewallDefaultAction } from '../types/firewall.types'
import { PrismaAdapterError, PrismaAdapterErrorCode, isPrismaAdapterError } from '../types/db.types'
import {
  pidBelongsToVM as sharedPidBelongsToVM,
  forceKillProcess as sharedForceKillProcess,
  waitForProcessExit as sharedWaitForProcessExit,
  isProcessAlive as sharedIsProcessAlive
} from '../utils/processIdentity'
import { UnattendedInstaller } from '../unattended/UnattendedInstaller'
import { CgroupsManager } from '../system/CgroupsManager'
import { detectOSType, getDriverPreset } from '../config/DriverPresets'
import { KeyedMutex } from '../utils/KeyedMutex'

/**
 * Process-wide lock serializing display-port allocation through QEMU spawn.
 * findAvailableDisplayPort probes a port by binding+closing a socket, which frees
 * it long before QEMU actually binds it — so two concurrent creates can probe the
 * same free port and both hand it to QEMU (the loser gets EADDRINUSE and its
 * create fails). createLifecycle() builds a NEW VMLifecycle per call, so this must
 * be a module-level singleton (a per-instance field would never serialize).
 */
const displayPortLock = new KeyedMutex()
const DISPLAY_PORT_LOCK_KEY = 'display-port'

/**
 * Cleanup resources for partial failure recovery
 */
interface CleanupResources {
  tapDevice?: string
  vmId?: string
  /** VM internal name — required to identity-verify a pidfile PID before killing. */
  internalName?: string
  /** Which operation owns this cleanup. 'start' must be NON-destructive: a soft
   *  start failure must not de-provision an otherwise-healthy persistent VM. */
  origin?: 'create' | 'start'
  /** True when start() reused a persistent TAP (do NOT destroy it on failure). */
  tapWasReused?: boolean
  diskPaths?: string[]
  qmpSocketPath?: string
  pidFilePath?: string
  qemuProcess?: QemuProcess
  qmpClient?: QMPClient
  /** Path to installation ISO for cleanup */
  installationIsoPath?: string
  /** Path to guest agent socket for cleanup */
  guestAgentSocketPath?: string
  /** Path to infini service socket for cleanup */
  infiniServiceSocketPath?: string
}

/**
 * VMLifecycle orchestrates all VM operations by coordinating
 * QEMU processes, QMP communication, networking, storage, and firewall components.
 */
export class VMLifecycle {
  private readonly debug: Debugger
  private readonly prisma: InfinizationDatabase
  private readonly eventHandler: EventHandler
  private readonly eventManager?: EventManagerLike
  private readonly diskDir: string
  private readonly qmpSocketDir: string
  private readonly pidfileDir: string

  // Service instances (created per operation)
  private readonly tapManager: TapDeviceManager
  private readonly nftables: NftablesService
  private readonly qemuImg: QemuImgService
  private readonly cgroupsManager: CgroupsManager

  /**
   * Creates a new VMLifecycle instance
   *
   * @param prisma - PrismaAdapter for database operations
   * @param eventHandler - EventHandler for QMP event monitoring
   * @param eventManager - Optional backend EventManager for event emission
   * @param options - Optional configuration overrides
   */
  constructor (
    prisma: InfinizationDatabase,
    eventHandler: EventHandler,
    eventManager?: EventManagerLike,
    options?: {
      diskDir?: string
      qmpSocketDir?: string
      pidfileDir?: string
    }
  ) {
    this.debug = new Debugger('vm-lifecycle')
    this.prisma = prisma
    this.eventHandler = eventHandler
    this.eventManager = eventManager

    // Configure directories
    this.diskDir = options?.diskDir ?? DEFAULT_DISK_DIR
    this.qmpSocketDir = options?.qmpSocketDir ?? DEFAULT_QMP_SOCKET_DIR
    this.pidfileDir = options?.pidfileDir ?? DEFAULT_PIDFILE_DIR

    // Initialize service instances
    this.tapManager = new TapDeviceManager()
    this.nftables = new NftablesService()
    this.qemuImg = new QemuImgService()
    this.cgroupsManager = new CgroupsManager()

    this.debug.log('VMLifecycle initialized')
  }

  // ===========================================================================
  // Public Methods
  // ===========================================================================

  /**
   * Creates and starts a new VM.
   *
   * Creates disk image, TAP device, firewall chain, QEMU process,
   * connects QMP, updates database, and attaches event handler.
   *
   * Unattended installation is configured via the `unattendedInstall` field
   * in the config object. When provided, a custom ISO will be generated
   * with automated installation configuration.
   *
   * @param config - VM creation configuration (includes optional unattendedInstall)
   * @returns VMCreateResult with all created resource details
   * @throws LifecycleError on failure (with automatic cleanup)
   *
   * @example
   * ```typescript
   * // Without unattended installation
   * await lifecycle.create({ vmId: '...', name: 'vm1', ... })
   *
   * // With unattended installation
   * await lifecycle.create({
   *   vmId: '...',
   *   name: 'vm1',
   *   os: 'ubuntu',
   *   // ... other config
   *   unattendedInstall: {
   *     vmId: '...',
   *     os: 'ubuntu',  // Must match config.os
   *     username: 'admin',
   *     password: 'secure123'
   *   }
   * })
   * ```
   */
  async create (config: VMCreateConfig): Promise<VMCreateResult> {
    this.debug.log(`Creating VM: ${config.name} (${config.internalName}) [DB ID: ${config.vmId}]`)

    // Validate configuration
    this.validateCreateConfig(config)

    // Validate CPU pinning if provided (early validation before resource allocation)
    if (config.cpuPinning && config.cpuPinning.length > 0) {
      try {
        await this.cgroupsManager.validateCores(config.cpuPinning)
      } catch (error) {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_CONFIG,
          error instanceof Error ? error.message : String(error),
          config.vmId,
          { requestedCores: config.cpuPinning }
        )
      }
    }

    // vmId is the database machine.id, internalName is used for resource naming
    const vmId = config.vmId

    // Generate paths using internalName (not vmId) for filesystem resources
    const paths = this.generatePaths(config.internalName, config.disks.length)

    // Track resources for cleanup on failure
    const resources: CleanupResources = {
      vmId,
      origin: 'create',
      internalName: config.internalName,
      diskPaths: paths.diskPaths,
      qmpSocketPath: paths.qmpSocketPath,
      pidFilePath: paths.pidFilePath,
      guestAgentSocketPath: config.guestAgentSocketPath,
      infiniServiceSocketPath: config.infiniServiceSocketPath
    }

    try {
      // 1. Ensure directories exist
      await this.ensureDirectories()

      // 1a. Clean up orphan resources if they exist (from previous failed create or crash)
      // This handles cases where a VM with the same internalName was partially created
      if (fs.existsSync(paths.qmpSocketPath)) {
        this.debug.log('warn', `Found existing QMP socket: ${paths.qmpSocketPath}, removing orphan socket`)
        try {
          fs.unlinkSync(paths.qmpSocketPath)
          this.debug.log('info', `Removed orphan QMP socket: ${paths.qmpSocketPath}`)
        } catch (unlinkError) {
          this.debug.log('error', `Failed to remove orphan QMP socket: ${unlinkError instanceof Error ? unlinkError.message : String(unlinkError)}`)
        }
      }

      if (fs.existsSync(paths.pidFilePath)) {
        this.debug.log('warn', `Found existing PID file: ${paths.pidFilePath}, checking if process is alive`)
        try {
          const pidContent = fs.readFileSync(paths.pidFilePath, 'utf8').trim()
          const existingPid = parseInt(pidContent, 10)

          if (!isNaN(existingPid) && existingPid > 0) {
            // L153: Only treat the pidfile as a real conflict when the live PID is
            // actually THIS VM's QEMU. A bare process.kill(pid,0) false-positives on
            // a recycled PID (now an unrelated host process), aborting create with a
            // spurious CREATE_FAILED. Gate on identity; if it's not our QEMU, the
            // pidfile is stale/recycled — unlink it and proceed.
            if (this.isProcessAlive(existingPid) && this.pidBelongsToVM(existingPid, config.internalName)) {
              throw new LifecycleError(
                LifecycleErrorCode.CREATE_FAILED,
                `A QEMU process (PID ${existingPid}) is already running with internalName '${config.internalName}'. ` +
                `This may indicate a duplicate VM or orphaned process. ` +
                `If you are sure no QEMU process should be running, manually remove: ${paths.pidFilePath}`,
                vmId,
                { existingPid, pidFilePath: paths.pidFilePath, internalName: config.internalName }
              )
            }
            // Not alive, or alive but not our QEMU (recycled PID): treat as orphan.
            this.debug.log('info', `Stale/recycled pidfile PID ${existingPid} (not VM '${config.internalName}' QEMU), removing orphan PID file`)
            fs.unlinkSync(paths.pidFilePath)
            this.debug.log('info', `Removed orphan PID file: ${paths.pidFilePath}`)
          } else {
            this.debug.log('warn', `PID file contains invalid content: "${pidContent}", removing`)
            fs.unlinkSync(paths.pidFilePath)
          }
        } catch (readError) {
          if (readError instanceof LifecycleError) {
            throw readError
          }
          this.debug.log('warn', `Error reading PID file: ${readError instanceof Error ? readError.message : String(readError)}`)
          try {
            fs.unlinkSync(paths.pidFilePath)
            this.debug.log('info', `Removed unreadable PID file: ${paths.pidFilePath}`)
          } catch (unlinkError) {
            this.debug.log('error', `Failed to remove orphan PID file: ${unlinkError instanceof Error ? unlinkError.message : String(unlinkError)}`)
          }
        }
      }

      // 2. Create disk images
      this.debug.log(`Creating ${config.disks.length} disk image(s)`)
      for (let i = 0; i < config.disks.length; i++) {
        const diskConfig = config.disks[i]
        const diskPath = paths.diskPaths[i]

        if (diskConfig.backingFile) {
          this.debug.log(`Creating disk ${i}: ${diskPath} (thin clone of ${diskConfig.backingFile})`)
        } else {
          this.debug.log(`Creating disk ${i}: ${diskPath} (${diskConfig.sizeGB}GB)`)
        }
        await this.qemuImg.createImage({
          path: diskPath,
          sizeGB: diskConfig.sizeGB,
          format: diskConfig.format ?? DEFAULT_DISK_FORMAT,
          // Preallocation is ignored for thin clones (can't preallocate on a backing chain).
          preallocation: diskConfig.backingFile ? undefined : 'metadata',
          backingFile: diskConfig.backingFile
        })
      }

      // 3. Generate MAC address if not provided. A caller-supplied MAC is untrusted
      // input that flows into the QEMU `-device` option, so validate its format
      // before use — a malformed value could inject extra device sub-properties or
      // impersonate another VM's MAC. (Generated MACs are always well-formed.)
      let macAddress: string
      if (config.macAddress != null) {
        if (!MacAddressGenerator.validate(config.macAddress)) {
          throw new Error(`Invalid MAC address provided for VM ${vmId}: ${config.macAddress}`)
        }
        macAddress = config.macAddress
      } else {
        macAddress = MacAddressGenerator.generateFromVmId(vmId)
      }
      this.debug.log(`MAC address: ${macAddress}`)

      // 4. Create and configure TAP device
      // Note: tapManager.create() proactively cleans up orphaned TAP devices (persist on + no carrier)
      // before creating the new device, preventing network connectivity issues from stale devices
      this.debug.log(`Preparing network resources for VM: ${vmId}`)
      const tapDevice = await this.tapManager.create(vmId, config.bridge)
      resources.tapDevice = tapDevice
      await this.tapManager.configure(tapDevice, config.bridge)
      this.debug.log(`TAP device ${tapDevice} configured successfully for VM: ${vmId}`)

      // 5. Fetch and apply firewall rules.
      // ALWAYS apply (even with zero rules) so the terminal posture (fail-closed
      // 'drop' by default, or the department's policy) is installed. The previous
      // `if (rules.length > 0)` guard meant a default-deny department with no
      // explicit allow rules — or any transient fetch result — booted with NO
      // terminal drop, i.e. unrestricted L3 on the shared bridge.
      this.debug.log(`Configuring firewall for VM: ${vmId}`)
      await this.nftables.createVMChain(vmId, tapDevice)
      const firewallRules = await this.fetchFirewallRules(vmId)
      // Explicit config wins; otherwise use the department-policy-derived posture.
      const firewallDefaultAction: FirewallDefaultAction = config.firewallDefaultAction ?? firewallRules.defaultAction
      await this.nftables.applyRules(
        vmId,
        tapDevice,
        firewallRules.department,
        firewallRules.vm,
        firewallDefaultAction
      )

      // 6. Handle unattended installation ISO generation (if configured)
      let installationIsoPath: string | undefined
      let unattendedInstaller: UnattendedInstaller | undefined

      if (config.unattendedInstall) {
        // Validate that unattendedInstall.os matches config.os
        // This prevents generating the wrong ISO (e.g., Ubuntu ISO for a Windows VM)
        const vmOs = config.os.toLowerCase()
        const unattendedOs = config.unattendedInstall.os.toLowerCase()

        // Map VM OS names to unattended OS types for comparison
        const osMatches = (
          (vmOs === unattendedOs) ||
          (vmOs.includes('ubuntu') && unattendedOs === 'ubuntu') ||
          (vmOs.includes('windows') && (unattendedOs === 'windows10' || unattendedOs === 'windows11')) ||
          (vmOs.includes('fedora') && unattendedOs === 'fedora') ||
          ((vmOs.includes('redhat') || vmOs.includes('rhel')) && unattendedOs === 'fedora')
        )

        if (!osMatches) {
          throw new LifecycleError(
            LifecycleErrorCode.INVALID_CONFIG,
            `Unattended installation OS mismatch: VM os='${config.os}' but unattendedInstall.os='${config.unattendedInstall.os}'. ` +
            `These must match to ensure the correct installation ISO is generated.`,
            vmId,
            { vmOs: config.os, unattendedOs: config.unattendedInstall.os }
          )
        }

        this.debug.log('Generating unattended installation ISO')

        // Ensure the unattendedInstall config has the correct vmId
        const unattendedConfig = {
          ...config.unattendedInstall,
          vmId: config.unattendedInstall.vmId || vmId
        }

        unattendedInstaller = new UnattendedInstaller(unattendedConfig)
        installationIsoPath = await unattendedInstaller.generateInstallationISO()
        resources.installationIsoPath = installationIsoPath

        this.debug.log(`Installation ISO generated: ${installationIsoPath}`)
      }

      // 7. Apply OS-specific driver presets and build QEMU command
      // Detect OS type and apply driver preset with fallback chain:
      // explicit config → OS preset → hardcoded default
      //
      // Note: Presets apply to disk and network MODEL configuration only.
      // networkQueues uses CPU-based auto-calculation (not preset values).
      // displayProtocol in presets is advisory-only (displayType is required in config).
      const osType = detectOSType(config.os)
      const preset = getDriverPreset(osType)
      this.debug.log(`Applying driver preset for OS type: ${osType}`)

      // Apply preset values with fallback chain (disk/network model only)
      const presetMachineType = config.machineType ?? 'q35'
      const presetCpuModel = config.cpuModel ?? 'host'
      const presetDiskBus = config.diskBus ?? preset.diskBus
      const presetDiskCacheMode = config.diskCacheMode ?? preset.diskCacheMode
      const presetNetworkModel = config.networkModel ?? preset.networkModel
      // networkQueues: pass through explicit config or null for CPU-based auto-calculation
      // Preset networkQueues values are advisory-only and not applied automatically
      const presetNetworkQueues = config.networkQueues ?? null

      // Compute effective values using validation methods (same as start() does for restarts)
      const effectiveMachineType = this.validateMachineType(presetMachineType)
      const effectiveCpuModel = presetCpuModel
      const effectiveDiskBus = this.validateDiskBus(presetDiskBus)
      const effectiveDiskCacheMode = this.validateDiskCacheMode(presetDiskCacheMode)
      const effectiveNetworkModel = this.validateNetworkModel(presetNetworkModel)
      // Calculate network queues: explicit config takes precedence, otherwise auto-calculate from CPU cores
      const effectiveNetworkQueues = this.calculateNetworkQueues(config.cpuCores, presetNetworkQueues)
      const effectiveMemoryBalloon = config.memoryBalloon ?? false

      // Validate UEFI firmware at creation time - coerce invalid paths to BIOS mode (null)
      // This ensures the database always reflects the actual boot mode that will be used
      const effectiveUefiFirmware = this.validateUefiFirmware(config.uefiFirmware)

      // Validate hugepages at creation time - check availability and coerce to false if unavailable
      const effectiveHugepages = this.validateHugepages(config.hugepages)

      // H3: Mark the row TRANSIENT ('starting') BEFORE we spawn QEMU. Until now
      // the row stayed 'off' while QEMU was already live, so the HealthMonitor
      // orphan scan (lock-free, every 30s) could SIGKILL the just-created VM
      // because its alive PID had a non-running/non-transient DB row. Setting
      // 'starting' here puts the row in TRANSIENT_STATUSES for the whole create
      // window; the updateMachineStatus(vmId, 'running') on success clears it, and
      // the create-failure cleanup path lands on a terminal 'error' (and startup
      // reconcileTransientStates resets any dead 'starting' row), so a row is never
      // stranded. Mirrors start()'s 'off'->'starting' optimistic transition.
      await this.prisma.updateMachineStatus(vmId, 'starting')
      this.debug.log(`VM ${vmId} status set to 'starting' before QEMU spawn (H3 orphan-scan guard)`)

      // Heal the SPICE/VNC bind address BEFORE building the QEMU command. The
      // installer VM launches HERE in create() (not start()), so without this a
      // routable-but-non-local displayAddr — e.g. the backend passing APP_HOST=<LAN
      // IP>, or a value carried over from another host/container — is handed
      // straight to QEMU, which dies with `binding socket to <ip>:<port> failed`
      // because that IP is on no local interface in this netns. Mirror start()'s
      // self-heal: a non-local concrete IP falls back to 0.0.0.0 (always bindable;
      // the console stays authenticated via the QMP-delivered displayPassword and,
      // in the proxied deployment, is only reached through the per-session SPICE
      // proxy), while loopback/wildcard/still-local addresses pass through
      // unchanged. The healed value is also what we persist as graphicHost (below),
      // so a later start() reconstructs the same binding instead of re-healing.
      const configuredDisplayAddr = config.displayAddr ?? DEFAULT_SPICE_ADDR
      const localAddrs = new Set(
        Object.values(os.networkInterfaces())
          .flat()
          .filter((ni): ni is os.NetworkInterfaceInfo => ni != null)
          .map((ni) => ni.address)
      )
      const healedDisplayAddr = resolveBindAddress(configuredDisplayAddr, localAddrs, DEFAULT_SPICE_ADDR)
      if (healedDisplayAddr !== configuredDisplayAddr) {
        this.debug.log('warn', `VM ${vmId} display bind address '${configuredDisplayAddr}' is not bindable on this host; falling back to '${healedDisplayAddr}' (self-heal)`)
      }
      config.displayAddr = healedDisplayAddr

      // Serialize display-port allocation through QEMU spawn process-wide so two
      // concurrent creates cannot both probe the same free port and hand it to
      // QEMU. Only this brief region is locked (probe -> QEMU binds the port);
      // the rest of create() stays concurrent across VMs.
      const { effectiveDisplayPort, qemuProcess } = await displayPortLock.runExclusive(
        DISPLAY_PORT_LOCK_KEY,
        async () => {
          // Validate display port at creation time - ensure it's within valid range and available
          const validatedDisplayPort = this.validateDisplayPort(config.displayPort)
          const effectiveDisplayPort = await this.findAvailableDisplayPort(validatedDisplayPort)

          const qemuConfig = {
            machineType: effectiveMachineType,
            cpuModel: effectiveCpuModel,
            diskBus: effectiveDiskBus,
            diskCacheMode: effectiveDiskCacheMode,
            networkModel: effectiveNetworkModel,
            networkQueues: effectiveNetworkQueues,
            memoryBalloon: effectiveMemoryBalloon,
            uefiFirmware: effectiveUefiFirmware,
            hugepages: effectiveHugepages,
            displayPort: effectiveDisplayPort,
            enableNumaCtlPinning: config.enableNumaCtlPinning,
            cpuPinningStrategy: config.cpuPinningStrategy,
            // Host-hardening knobs (now reachable from the public create config).
            // MF-4: fall back to INFINIZATION_QEMU_USER so the -runas privilege
            // drop is applied uniformly. The explicit per-VM config wins; the env
            // only fills in when config.runAsUser is unset (?? short-circuits, so
            // there is no double-apply / conflict). Unset env => undefined =>
            // current behavior preserved.
            runAsUser: config.runAsUser ?? process.env.INFINIZATION_QEMU_USER,
            disableSandbox: config.disableSandbox
          }

          const commandBuilder = this.buildQemuCommand(
            config,
            paths.diskPaths,
            paths.qmpSocketPath,
            paths.pidFilePath,
            tapDevice,
            macAddress,
            qemuConfig
          )

          // 7a. Mount installation ISO if unattended installation is configured
          if (unattendedInstaller && installationIsoPath) {
            unattendedInstaller.mountInstallationMedia(commandBuilder, installationIsoPath)
            this.debug.log('Installation media mounted in QEMU command')
          }

          // 8. Create and start QEMU process (still holding the port lock so the
          //    probed port stays reserved until QEMU has actually bound it).
          this.debug.log(`Starting QEMU process for VM: ${vmId}`)
          const qemuProcess = new QemuProcess(vmId, commandBuilder)
          qemuProcess.setQmpSocketPath(paths.qmpSocketPath)
          qemuProcess.setPidFilePath(paths.pidFilePath)
          resources.qemuProcess = qemuProcess
          await qemuProcess.start()
          return { effectiveDisplayPort, qemuProcess }
        }
      )

      const pid = qemuProcess.getPid()
      if (!pid) {
        throw new LifecycleError(
          LifecycleErrorCode.PROCESS_ERROR,
          'QEMU process started but PID not available',
          vmId
        )
      }
      this.debug.log(`QEMU process started with PID: ${pid}`)

      // 8a. Verify TAP device connection (QEMU should have attached to the TAP device)
      this.debug.log(`Verifying TAP device connection: ${tapDevice}`)
      await this.verifyTapConnection(tapDevice, vmId, pid, config.bridge)
      this.debug.log(`TAP device ${tapDevice} has carrier - QEMU connected successfully`)

      // 8b. Apply CPU pinning if configured (best-effort, applyCpuPinning handles errors internally)
      if (config.cpuPinning && config.cpuPinning.length > 0) {
        this.debug.log(`Applying CPU pinning for VM ${vmId}: cores ${config.cpuPinning.join(',')}`)
        const pinResult = await this.cgroupsManager.applyCpuPinning(pid, config.cpuPinning)
        if (!pinResult.applied) {
          // Surface the divergence loudly (warn is unconditional) instead of
          // silently recording the requested cores as if honored.
          this.debug.log('warn', `CPU pinning REQUESTED but NOT applied for VM ${vmId} (cores ${config.cpuPinning.join(',')}): ${pinResult.reason ?? 'unknown'}`)
        }
      }

      // 9. Wait for QMP socket and connect
      this.debug.log(`Connecting to QMP socket: ${paths.qmpSocketPath}`)
      await this.waitForSocket(paths.qmpSocketPath)
      const qmpClient = new QMPClient(paths.qmpSocketPath, {
        connectTimeout: DEFAULT_QMP_CONNECT_TIMEOUT,
        reconnect: true,
        maxReconnectAttempts: 3
      })
      resources.qmpClient = qmpClient
      await qmpClient.connect()

      // 9a. Deliver the display password over QMP (never on the QEMU command line).
      await this.applyDisplayPassword(qmpClient, config.displayType, config.displayPassword)

      // 9. Verify VM status via QMP
      const status = await qmpClient.queryStatus()
      this.debug.log(`QMP status: ${status.status}`)

      // 10. Update database configuration
      await this.prisma.updateMachineConfiguration(vmId, {
        qmpSocketPath: paths.qmpSocketPath,
        qemuPid: pid,
        tapDeviceName: tapDevice,
        graphicProtocol: config.displayType,
        graphicPort: effectiveDisplayPort,
        graphicPassword: config.displayPassword ?? null,
        // Persist the effective (secure-by-default loopback) bind address so a
        // later start() reconstructs the same binding rather than '0.0.0.0'.
        graphicHost: config.displayAddr ?? DEFAULT_SPICE_ADDR,
        // Store effective QEMU driver configuration (validated values, matching runtime behavior)
        bridge: config.bridge,
        machineType: effectiveMachineType,
        cpuModel: effectiveCpuModel,
        diskBus: effectiveDiskBus,
        diskCacheMode: effectiveDiskCacheMode,
        networkModel: effectiveNetworkModel,
        networkQueues: effectiveNetworkQueues,
        memoryBalloon: effectiveMemoryBalloon,
        // Store disk paths for multi-disk support
        diskPaths: paths.diskPaths,
        // Store validated UEFI firmware (null if invalid/missing, normalized path if valid)
        uefiFirmware: effectiveUefiFirmware,
        // Store hugepages configuration (validated - true only if available on host)
        hugepages: effectiveHugepages,
        // Store CPU pinning configuration
        cpuPinning: config.cpuPinning && config.cpuPinning.length > 0
          ? { cores: config.cpuPinning }
          : null,
        // Store advanced device configuration
        tpmSocketPath: config.tpmSocketPath ?? null,
        guestAgentSocketPath: config.guestAgentSocketPath ?? null,
        infiniServiceSocketPath: config.infiniServiceSocketPath ?? null,
        virtioDriversIso: config.virtioDriversIso ?? null,
        enableAudio: config.enableAudio ?? false,
        enableUsbTablet: config.enableUsbTablet ?? config.os.toLowerCase().includes('windows')
      })

      // 11. Update database status
      await this.prisma.updateMachineStatus(vmId, 'running')

      // 11b. B3 (unattended-install race): if this VM is being created with an
      // unattended install, register it with the EventHandler BEFORE attaching so
      // there is no window in which a guest SHUTDOWN/POWERDOWN is treated as
      // terminal. While marked, the EventHandler defers all SHUTDOWN/POWERDOWN
      // reaping to the InstallationMonitor (which owns the completion heuristic).
      // The mark is cleared when the background monitor settles (below).
      const isInstallingOS = !!(unattendedInstaller && installationIsoPath)
      if (isInstallingOS) {
        this.eventHandler.markInstallInProgress(vmId)
      }

      // 12. Attach event handler for monitoring
      await this.eventHandler.attachToVM(vmId, qmpClient)

      // 13. Emit event to backend
      this.emitEvent('machines', 'create', vmId, { pid, tapDevice })

      // 14. Start unattended installation monitoring (if configured)
      if (unattendedInstaller && installationIsoPath && qmpClient) {
        this.debug.log('Starting unattended installation monitoring')

        // Monitor installation in background (don't await, let VM creation complete)
        // The caller can track installation via events or status checks
        unattendedInstaller.monitorInstallation(qmpClient, installationIsoPath)
          .then((result) => {
            if (result.success) {
              this.debug.log(`Unattended installation completed successfully for VM: ${vmId}`)
              this.emitEvent('machines', 'update', vmId, {
                type: 'installation_complete',
                duration: result.duration
              })
            } else {
              this.debug.log('error', `Unattended installation failed for VM: ${vmId}`)
              this.emitEvent('machines', 'update', vmId, {
                type: 'installation_failed',
                error: result.error?.message
              })
            }
          })
          .catch((err) => {
            this.debug.log('error', `Unattended installation monitoring error: ${err instanceof Error ? err.message : String(err)}`)
          })
          .finally(() => {
            // B3: install settled (success OR failure) — lift the guard so normal
            // terminal SHUTDOWN/POWERDOWN handling resumes for this VM. The
            // end-of-install shutdown was already consumed by InstallationMonitor;
            // from here on a guest power-off is a real power-off.
            this.eventHandler.clearInstallInProgress(vmId)
          })
      }

      this.debug.log(`VM created successfully: ${vmId}`)

      return {
        vmId,
        tapDevice,
        qmpSocketPath: paths.qmpSocketPath,
        displayPort: effectiveDisplayPort,
        pid,
        diskPaths: paths.diskPaths,
        pidFilePath: paths.pidFilePath,
        success: true,
        installationIsoPath,
        installingOS: isInstallingOS
      }
    } catch (error) {
      this.debug.log('error', `Failed to create VM: ${error instanceof Error ? error.message : String(error)}`)
      // B3: if we marked an install-in-progress but create() failed before the
      // background monitor's finally could clear it, lift the guard here so a
      // future re-create of the same vmId is not stuck deferring shutdowns.
      // Idempotent if never marked / already cleared.
      this.eventHandler.clearInstallInProgress(vmId)
      await this.cleanup(resources)
      throw this.wrapError(error, LifecycleErrorCode.CREATE_FAILED, vmId)
    }
  }

  /**
   * Starts an existing VM.
   *
   * Reconstructs QEMU command from persisted configuration,
   * spawns QEMU process, connects QMP, and updates database.
   *
   * @param vmId - VM identifier (database machine.id)
   * @param config - Optional start configuration
   * @returns VMOperationResult indicating success or failure
   */
  async start (vmId: string, config?: VMStartConfig): Promise<VMOperationResult> {
    this.debug.log(`Starting VM: ${vmId}`)
    const timestamp = new Date()

    // Track resources for cleanup on failure. origin='start' makes cleanup
    // NON-destructive (preserve the persistent TAP + config, reset to 'off').
    const resources: CleanupResources = { vmId, origin: 'start' }

    try {
      // 1. Fetch VM configuration from database (initial check)
      const initialVmConfig = await this.prisma.findMachineWithConfig(vmId)
      if (!initialVmConfig) {
        throw new LifecycleError(
          LifecycleErrorCode.VM_NOT_FOUND,
          `VM not found: ${vmId}`,
          vmId
        )
      }

      // 2. Check if already running. H7/H8 (VMLifecycle side): a bare liveness
      // check trusts a possibly-recycled DB PID — if that PID now belongs to an
      // unrelated host process we would short-circuit start() and report the VM
      // "already running" forever. Gate on identity so only THIS VM's live QEMU
      // counts as already-running; otherwise fall through to the dead-PID reset.
      if (initialVmConfig.status === 'running') {
        const pid = initialVmConfig.configuration?.qemuPid
        if (pid && this.isProcessAlive(pid) && this.pidBelongsToVM(pid, initialVmConfig.internalName)) {
          return {
            success: true,
            message: `VM ${vmId} is already running`,
            vmId,
            timestamp
          }
        }
        // Process is dead but DB says running - update status and continue
        // Use volatile clear to preserve tapDeviceName for potential reuse
        await this.prisma.updateMachineStatus(vmId, 'off')
        await this.prisma.clearVolatileMachineConfiguration(vmId)
        this.debug.log(`VM ${vmId} was marked running but process dead, resetting (TAP preserved)`)
      }

      // 2b. Recover from a stale 'starting' left by a previous crash. A successful
      // start never leaves the row in 'starting' once it returns, so reaching here
      // in 'starting' means the prior attempt died. Adopt a still-live QEMU as
      // running; otherwise reset to 'off' so the transition below can proceed
      // instead of dead-ending on the orphan-pidfile check.
      if (initialVmConfig.status === 'starting') {
        const stalePid = initialVmConfig.configuration?.qemuPid
        // Same identity gate as the 'running' branch: only adopt a still-live QEMU
        // that is actually THIS VM's process; a recycled foreign PID must NOT be
        // promoted to 'running'.
        if (stalePid && this.isProcessAlive(stalePid) && this.pidBelongsToVM(stalePid, initialVmConfig.internalName)) {
          await this.prisma.updateMachineStatus(vmId, 'running')
          this.debug.log(`VM ${vmId} was stale 'starting' but PID ${stalePid} is alive -> 'running'`)
          return { success: true, message: `VM ${vmId} is already running`, vmId, timestamp }
        }
        await this.prisma.updateMachineStatus(vmId, 'off')
        await this.prisma.clearVolatileMachineConfiguration(vmId)
        this.debug.log(`VM ${vmId} was stale 'starting' with no live PID, resetting to 'off' (TAP preserved)`)
      }

      // 3. Atomically transition status to 'starting' with optimistic locking.
      // Re-read AFTER any reset above so version/status are current.
      //
      // MF-3 (fail-closed): the DB status is the authoritative cross-service
      // gate. Only a row that is genuinely idle may boot QEMU — that is 'off',
      // plus 'error' as an explicit recovery-from-failed-start case. ANY other
      // status (a backend disk-op marker such as 'backing_up'/'restoring'/
      // 'snapshotting', or 'running'/'suspended'/'starting') means the qcow2 may
      // be live or being rewritten, so starting QEMU over it risks corruption.
      // We therefore ALWAYS attempt the transition with a startable status as the
      // expected base and treat any failure as a HARD refusal — never silently
      // skip the transition for a non-'off' status. The disk-op markers are
      // refused inherently because they are not in the startable set; we do not
      // hardcode the marker strings.
      let vmConfig = initialVmConfig
      let transitionBase = initialVmConfig
      if (initialVmConfig.status === 'running' || initialVmConfig.status === 'starting') {
        const refreshed = await this.prisma.findMachineWithConfig(vmId)
        if (refreshed) transitionBase = refreshed
      }
      // The startable set: 'off' (normal idle) and 'error' (recover a previously
      // failed start). Everything else — including every disk-op marker — is
      // refused below before any QEMU is spawned.
      const STARTABLE_STATUSES = ['off', 'error'] as const
      if (!STARTABLE_STATUSES.includes(transitionBase.status as typeof STARTABLE_STATUSES[number])) {
        this.debug.log('warn', `VM ${vmId} start refused: status '${transitionBase.status}' is not startable (disk op or already active)`)
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_STATE,
          `VM ${vmId} is not startable in its current state ('${transitionBase.status}')`,
          vmId,
          { currentStatus: transitionBase.status, startableStatuses: [...STARTABLE_STATUSES] }
        )
      }
      try {
        const transitionResult = await this.prisma.transitionVMStatus(
          vmId,
          transitionBase.status,
          'starting',
          transitionBase.version
        )
        vmConfig = transitionResult.vmConfig
        this.debug.log(`VM ${vmId} status transitioned '${transitionBase.status}' -> 'starting' (version: ${transitionResult.newVersion})`)
      } catch (error) {
        // The transition is authoritative: a row that is no longer in the
        // expected startable status (e.g. a backend just flipped it to a disk-op
        // marker between our read and the transaction), a version conflict, or a
        // 0-row race ALL mean another actor owns this row right now. Refuse hard
        // rather than proceeding — booting QEMU here could corrupt the qcow2.
        //
        // - VERSION_CONFLICT  -> optimistic-lock race / concurrent start.
        // - UPDATE_FAILED     -> status changed under us. If it carries the
        //   underlying deadlock prismaCode 'P2034' it is a concurrency conflict;
        //   otherwise the row's status simply is no longer startable.
        if (error instanceof PrismaAdapterError) {
          const isP2034Deadlock = error.code === PrismaAdapterErrorCode.UPDATE_FAILED &&
            (error.details as { prismaCode?: string } | undefined)?.prismaCode === 'P2034'
          if (error.code === PrismaAdapterErrorCode.VERSION_CONFLICT || isP2034Deadlock) {
            this.debug.log('warn', `VM ${vmId} start request rejected: concurrent modification detected`)
            throw new LifecycleError(
              LifecycleErrorCode.CONCURRENT_MODIFICATION,
              `VM ${vmId} is being modified by another process`,
              vmId,
              { originalError: error.message }
            )
          }
          if (error.code === PrismaAdapterErrorCode.UPDATE_FAILED) {
            // Status changed out from under us to a non-startable value.
            const currentStatus = (error.details as { currentStatus?: string } | undefined)?.currentStatus
            this.debug.log('warn', `VM ${vmId} start refused: status changed to '${currentStatus ?? 'unknown'}' before transition`)
            throw new LifecycleError(
              LifecycleErrorCode.INVALID_STATE,
              `VM ${vmId} is not startable in its current state${currentStatus ? ` ('${currentStatus}')` : ''}`,
              vmId,
              { currentStatus, originalError: error.message }
            )
          }
        }
        throw error
      }

      // 4. Validate required hardware configuration exists
      if (!vmConfig.cpuCores || !vmConfig.ramGB || !vmConfig.internalName) {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_CONFIG,
          `VM ${vmId} missing required hardware configuration (cpuCores, ramGB, or internalName)`,
          vmId,
          { cpuCores: vmConfig.cpuCores, ramGB: vmConfig.ramGB, internalName: vmConfig.internalName }
        )
      }
      // Record internalName so start()'s failure cleanup can identity-verify the
      // pidfile PID before signalling it.
      resources.internalName = vmConfig.internalName

      // 5. Get disk paths from database or generate from internalName (backward compatibility)
      let diskPaths: string[]
      if (vmConfig.configuration?.diskPaths && Array.isArray(vmConfig.configuration.diskPaths) && vmConfig.configuration.diskPaths.length > 0) {
        // Use stored disk paths (multi-disk VMs)
        diskPaths = vmConfig.configuration.diskPaths
        this.debug.log(`Using stored disk paths: ${diskPaths.join(', ')}`)
      } else {
        // Legacy single-disk VM - compute path from internalName
        const legacyPaths = this.generatePaths(vmConfig.internalName, 1)
        diskPaths = legacyPaths.diskPaths
        this.debug.log(`Using legacy single-disk path: ${diskPaths[0]}`)

        // Migrate legacy VM by persisting computed disk paths to database
        // This ensures future starts use the stored paths directly
        try {
          await this.prisma.updateMachineConfiguration(vmId, { diskPaths })
          this.debug.log(`Migrated legacy VM ${vmId}: stored disk paths in database`)
        } catch (migrationError) {
          // Log warning but don't block VM start if migration write fails
          this.debug.log('warn', `Failed to migrate legacy VM disk paths for ${vmId}: ${migrationError instanceof Error ? migrationError.message : String(migrationError)}`)
        }
      }

      const qmpSocketPath = path.join(this.qmpSocketDir, `${vmConfig.internalName}.sock`)
      const pidFilePath = path.join(this.pidfileDir, `${vmConfig.internalName}.pid`)

      // 5a. Orphan PID-file guard FIRST — BEFORE touching the QMP socket. If a live
      // QEMU still owns this VM's pidfile we refuse to start WITHOUT deleting its QMP
      // socket. The old order removed the socket first, which left a still-alive QEMU
      // unreachable via QMP (impossible to stop gracefully → a permanent orphan).
      // QEMU uses flock() on the PID file, so if a previous process crashed, the lock
      // is released but the file may remain. If a process is still alive, we should not
      // attempt to start a duplicate VM.
      if (fs.existsSync(pidFilePath)) {
        this.debug.log('warn', `Found existing PID file: ${pidFilePath}, checking if process is alive`)
        try {
          const pidContent = fs.readFileSync(pidFilePath, 'utf8').trim()
          const existingPid = parseInt(pidContent, 10)

          if (!isNaN(existingPid) && existingPid > 0) {
            // L57: Only a live PID that is actually THIS VM's QEMU is a real
            // conflict. A bare process.kill(pid,0) false-positives on a recycled
            // PID (now an unrelated host process), aborting start with a spurious
            // START_FAILED. Gate on identity; if it's not our QEMU, the pidfile is
            // stale/recycled — unlink and proceed.
            if (this.isProcessAlive(existingPid) && this.pidBelongsToVM(existingPid, vmConfig.internalName)) {
              throw new LifecycleError(
                LifecycleErrorCode.START_FAILED,
                `VM ${vmId} appears to have a running QEMU process (PID ${existingPid}) that is not tracked. ` +
                `This may indicate a previous crash or unclean shutdown. ` +
                `If you are sure no QEMU process is running for this VM, manually remove: ${pidFilePath}`,
                vmId,
                { existingPid, pidFilePath }
              )
            }
            // Not alive, or alive but not our QEMU (recycled PID): treat as orphan.
            this.debug.log('info', `Stale/recycled pidfile PID ${existingPid} (not VM '${vmConfig.internalName}' QEMU), removing orphan PID file`)
            fs.unlinkSync(pidFilePath)
            this.debug.log('info', `Removed orphan PID file: ${pidFilePath}`)
          } else {
            // Invalid PID content - safe to remove
            this.debug.log('warn', `PID file contains invalid content: "${pidContent}", removing`)
            fs.unlinkSync(pidFilePath)
          }
        } catch (readError) {
          if (readError instanceof LifecycleError) {
            throw readError
          }
          // Error reading PID file - try to remove it anyway
          this.debug.log('warn', `Error reading PID file: ${readError instanceof Error ? readError.message : String(readError)}`)
          try {
            fs.unlinkSync(pidFilePath)
            this.debug.log('info', `Removed unreadable PID file: ${pidFilePath}`)
          } catch (unlinkError) {
            this.debug.log('error', `Failed to remove orphan PID file: ${unlinkError instanceof Error ? unlinkError.message : String(unlinkError)}`)
          }
        }
      }

      // 5b. Orphan QMP socket cleanup — ONLY now that the PID-file guard above has
      // confirmed no live QEMU owns this VM. A stale socket left by a crashed/unclean
      // QEMU would make the new QEMU fail to bind; removing it here (after the guard)
      // guarantees we never delete the QMP socket of a still-running QEMU.
      if (fs.existsSync(qmpSocketPath)) {
        this.debug.log('warn', `Found existing QMP socket: ${qmpSocketPath}, removing orphan socket`)
        try {
          fs.unlinkSync(qmpSocketPath)
          this.debug.log('info', `Removed orphan QMP socket: ${qmpSocketPath}`)
        } catch (unlinkError) {
          this.debug.log('error', `Failed to remove orphan QMP socket: ${unlinkError instanceof Error ? unlinkError.message : String(unlinkError)}`)
        }
      }

      resources.diskPaths = diskPaths
      resources.qmpSocketPath = qmpSocketPath
      resources.pidFilePath = pidFilePath
      resources.guestAgentSocketPath = vmConfig.configuration?.guestAgentSocketPath ?? undefined

      // 5c. Ensure InfiniService socket path exists (generate if not in database)
      // This handles VMs created before the InfiniService socket feature was added,
      // or VMs where the socket path was cleared by the migration script.
      let infiniServiceSocketPath = vmConfig.configuration?.infiniServiceSocketPath
      if (!infiniServiceSocketPath) {
        infiniServiceSocketPath = path.join(this.qmpSocketDir, `${vmId}.socket`)
        this.debug.log('info', `Generated InfiniService socket path for VM ${vmId}: ${infiniServiceSocketPath}`)
        // Persist the generated path so future restarts use the same path
        await this.prisma.updateMachineConfiguration(vmId, { infiniServiceSocketPath })
      }
      resources.infiniServiceSocketPath = infiniServiceSocketPath

      // 6. Ensure directories exist
      await this.ensureDirectories()

      // 7. Verify all disks exist
      for (let i = 0; i < diskPaths.length; i++) {
        if (!fs.existsSync(diskPaths[i])) {
          throw new LifecycleError(
            LifecycleErrorCode.DISK_ERROR,
            `Disk image ${i} not found: ${diskPaths[i]}`,
            vmId,
            { diskPath: diskPaths[i], diskIndex: i }
          )
        }
      }

      // 8. Get display configuration
      const displayProtocol = (vmConfig.configuration?.graphicProtocol as 'spice' | 'vnc') ?? 'spice'
      const displayPassword = vmConfig.configuration?.graphicPassword ?? undefined
      // Resolve the bind address defensively. A concrete routable IP that was
      // persisted at create time (or frozen in by a backend cron) is UNBINDABLE
      // once that IP changes — container restart, DHCP renewal, host reboot, or
      // migration to another node. QEMU then dies with `failed to initialize
      // spice server` and the VM is stuck. resolveBindAddress() heals a stale
      // non-local IP to 0.0.0.0 (always bindable); loopback/wildcard/still-local
      // addresses pass through unchanged. Default to loopback (secure) when unset.
      const localAddrs = new Set(
        Object.values(os.networkInterfaces())
          .flat()
          .filter((ni): ni is os.NetworkInterfaceInfo => ni != null)
          .map((ni) => ni.address)
      )
      const configuredAddr = vmConfig.configuration?.graphicHost ?? DEFAULT_SPICE_ADDR
      const displayAddr = resolveBindAddress(configuredAddr, localAddrs, DEFAULT_SPICE_ADDR)
      if (displayAddr !== configuredAddr) {
        this.debug.log('warn', `VM ${vmId} display bind address '${configuredAddr}' is not bindable on this host; falling back to '${displayAddr}' (self-heal)`)
      }

      // 8a. Find an available display port (always start from SPICE_MIN_PORT).
      // This is an initial pick; the actual spawn re-probes the port UNDER the
      // displayPortLock and retries on EADDRINUSE (see step 14), closing the
      // probe->bind TOCTOU race that previously produced spurious START_FAILEDs
      // when many VMs in a pool started at once.
      let displayPort = await this.findAvailableDisplayPort(SPICE_MIN_PORT)

      // 8b. Update database with allocated port (for UI display). Also persist the
      // healed bind address so the DB stops carrying a stale, unbindable IP (keeps
      // future starts and any consumer of graphicHost consistent).
      this.debug.log('info', `Allocated display port: ${displayPort}`)
      await this.prisma.updateMachineConfiguration(
        vmId,
        displayAddr !== configuredAddr
          ? { graphicPort: displayPort, graphicHost: displayAddr }
          : { graphicPort: displayPort }
      )

      // 9. Generate MAC address deterministically from vmId
      const macAddress = MacAddressGenerator.generateFromVmId(vmId)
      this.debug.log(`MAC address: ${macAddress}`)

      // 10. Get network bridge from configuration with fallback to default
      const bridge = vmConfig.configuration?.bridge ?? 'virbr0'

      // 11. Create or reuse TAP device (persistent TAP support)
      // Check if a TAP device was preserved from a previous stop (persistent lifecycle)
      let tapDevice: string
      // L202: a reused persistent TAP must NOT be (re)attached to the bridge until
      // the fail-closed firewall posture is installed, so the device never sits on
      // the bridge with no terminal drop. Defer the bridge attach to after the
      // firewall is applied (below). The new-TAP branch's configure() also attaches
      // to the bridge, but it does so on a brand-new device that has no carrier
      // until QEMU connects (which only happens AFTER the firewall block).
      let deferredBridgeAttach: string | null = null
      const existingTapDevice = vmConfig.configuration?.tapDeviceName

      if (existingTapDevice && await this.tapManager.exists(existingTapDevice)) {
        // Reuse existing TAP device - bridge reattach deferred until after firewall.
        this.debug.log(`Reattaching TAP device ${existingTapDevice} for VM: ${vmId}`)

        // Check if TAP already has carrier (unexpected in start - could indicate stale QEMU)
        const hasCarrierBefore = await this.tapManager.hasCarrier(existingTapDevice)
        if (hasCarrierBefore) {
          this.debug.log('warn', `TAP device ${existingTapDevice} already has carrier, possible stale QEMU process`)
        }

        tapDevice = existingTapDevice
        resources.tapWasReused = true // never destroy a persistent reused TAP on failure
        // L149/L202: record the TAP for cleanup BEFORE the (deferred) bridge attach.
        resources.tapDevice = tapDevice
        deferredBridgeAttach = bridge
      } else {
        // Create new TAP device (first start or after host reboot)
        // Note: tapManager.create() proactively cleans up orphaned TAP devices
        this.debug.log(`Creating new TAP device for VM: ${vmId}`)
        tapDevice = await this.tapManager.create(vmId, bridge)
        // L149: record the freshly-created TAP IMMEDIATELY (before configure()/the
        // DB write), so cleanup destroys it if configure() or the write throws.
        // tapWasReused stays false here, keeping the new-branch TAP destroyable.
        resources.tapDevice = tapDevice
        await this.tapManager.configure(tapDevice, bridge)
        this.debug.log(`TAP device ${tapDevice} created and configured for VM: ${vmId}`)

        // Store TAP device name for persistence across stop/start cycles
        await this.prisma.updateMachineConfiguration(vmId, { tapDeviceName: tapDevice })
      }

      // 12. Setup firewall (persistent chain support)
      // Chain persists across stop/start - only jump rules are attached/detached
      this.debug.log(`Configuring firewall for VM: ${vmId}`)
      await this.nftables.ensureVMChain(vmId) // Idempotent - creates chain if not exists
      await this.nftables.attachJumpRules(vmId, tapDevice) // Connect TAP to persistent chain

      // ALWAYS (re)install the terminal posture on start, even with zero rules,
      // so a VM never boots without its fail-closed drop. applyRulesIfChanged
      // still skips the kernel write when nothing changed (the hash includes the
      // terminal action), so this stays cheap on a no-op restart.
      const firewallRules = await this.fetchFirewallRules(vmId)
      const startDefaultAction: FirewallDefaultAction = config?.firewallDefaultAction ?? firewallRules.defaultAction
      const { changed } = await this.nftables.applyRulesIfChanged(
        vmId,
        tapDevice,
        firewallRules.department,
        firewallRules.vm,
        startDefaultAction
      )
      if (!changed) {
        this.debug.log(`Firewall rules unchanged for VM ${vmId}, skipped re-apply`)
      }

      // L202: NOW that the VM chain + jump rules + terminal fail-closed drop are in
      // place, attach the reused TAP to the bridge. (The new-TAP branch already
      // attached via configure() on a carrier-less device.)
      if (deferredBridgeAttach) {
        await this.tapManager.attachToBridge(tapDevice, deferredBridgeAttach)
        this.debug.log(`TAP device ${tapDevice} reattached to bridge ${deferredBridgeAttach} (after firewall)`)
      }

      // 13. Build QEMU command from stored configuration
      // Create disk configs for each disk path. During start, disk size is not used for
      // actual operations (disks already exist), but must be positive for type consistency.
      // Use RUNTIME_DISK_SIZE_PLACEHOLDER_GB for all disks as a valid placeholder value.
      const diskConfigs = diskPaths.map(() => ({
        sizeGB: RUNTIME_DISK_SIZE_PLACEHOLDER_GB,
        format: 'qcow2' as const,
        bus: vmConfig.configuration?.diskBus ?? undefined,
        cache: vmConfig.configuration?.diskCacheMode ?? undefined
      }))

      const createConfig: VMCreateConfig = {
        vmId,
        name: vmConfig.name,
        internalName: vmConfig.internalName,
        os: vmConfig.os,
        cpuCores: vmConfig.cpuCores,
        ramGB: vmConfig.ramGB,
        disks: diskConfigs,
        bridge,
        macAddress,
        displayType: displayProtocol,
        displayPort,
        displayPassword,
        displayAddr,
        gpuPciAddress: vmConfig.gpuPciAddress ?? undefined,
        // Re-attach the infinigpu virtual GPU on start. The config above is
        // DB-derived and has no gpu field, so the backend threads department
        // policy via VMStartConfig.gpu on every start (mirrors disableSandbox).
        gpu: config?.gpu
        // Note: ISO not included for start - VM should boot from disk
      }

      // 13a. Compute effective QEMU configuration values (validated with defaults)
      const effectiveMachineType = this.validateMachineType(vmConfig.configuration?.machineType)
      const effectiveCpuModel = vmConfig.configuration?.cpuModel ?? 'host'
      const effectiveDiskBus = this.validateDiskBus(vmConfig.configuration?.diskBus)
      const effectiveDiskCacheMode = this.validateDiskCacheMode(vmConfig.configuration?.diskCacheMode)
      const effectiveNetworkModel = this.validateNetworkModel(vmConfig.configuration?.networkModel)
      const effectiveMemoryBalloon = vmConfig.configuration?.memoryBalloon ?? false

      // Base QEMU build options shared across spawn attempts (displayPort varies).
      const qemuBuildConfig = {
        machineType: effectiveMachineType,
        cpuModel: effectiveCpuModel,
        diskBus: effectiveDiskBus,
        diskCacheMode: effectiveDiskCacheMode,
        networkModel: effectiveNetworkModel,
        networkQueues: vmConfig.configuration?.networkQueues,
        memoryBalloon: effectiveMemoryBalloon,
        uefiFirmware: vmConfig.configuration?.uefiFirmware,
        hugepages: vmConfig.configuration?.hugepages,
        // Advanced device configuration from database
        tpmSocketPath: vmConfig.configuration?.tpmSocketPath,
        guestAgentSocketPath: vmConfig.configuration?.guestAgentSocketPath,
        // Use locally generated/stored infiniServiceSocketPath (includes fallback generation)
        infiniServiceSocketPath,
        virtioDriversIso: vmConfig.configuration?.virtioDriversIso,
        enableAudio: vmConfig.configuration?.enableAudio,
        enableUsbTablet: vmConfig.configuration?.enableUsbTablet,
        // CPU pinning configuration
        enableNumaCtlPinning: vmConfig.configuration?.enableNumaCtlPinning,
        cpuPinningStrategy: this.validateCpuPinningStrategy(vmConfig.configuration?.cpuPinningStrategy),
        // MF-4: the -runas privilege drop must survive every restart. create()
        // applies runAsUser, but start() rebuilds the command from DB config and
        // historically set neither runAsUser nor disableSandbox, so operator
        // stop/start, restartVM, and host-reboot recovery relaunched QEMU as
        // ROOT. Apply the same INFINIZATION_QEMU_USER fallback here so the drop is
        // uniform across the lifecycle. Unset env => undefined => current (root)
        // behavior preserved.
        runAsUser: process.env.INFINIZATION_QEMU_USER,
        // Honor an explicit sandbox opt-out on start too, so a VM created with the
        // sandbox disabled (VMCreateConfig.disableSandbox) does not silently
        // re-enable it on the next stop/start. Also fall back to the
        // INFINIZATION_DISABLE_SANDBOX env — mirroring the INFINIZATION_QEMU_USER
        // fallback above — so restart() and host-reboot recovery (which call
        // start() WITHOUT a config) still disable the sandbox on substrates that
        // SIGSYS a sandboxed QEMU (rootless/nested containers). Without this the
        // dev stack's `restartVM` relaunched QEMU sandboxed and died with SIGSYS
        // even though power-on (startVM) threaded the opt-out. Default keeps
        // seccomp ON — buildQemuCommand enables it unless disabled here.
        disableSandbox: config?.disableSandbox === true || process.env.INFINIZATION_DISABLE_SANDBOX === '1'
          ? true
          : undefined
      }

      // 14. Create and start QEMU process. Serialize the port re-probe + spawn
      // through displayPortLock so two concurrent starts cannot both bind the same
      // SPICE/VNC port; retry on EADDRINUSE with a freshly-allocated port.
      this.debug.log(`Starting QEMU process for VM: ${vmId}`)
      const qemuProcess = await displayPortLock.runExclusive(DISPLAY_PORT_LOCK_KEY, async () => {
        const MAX_PORT_ATTEMPTS = 5
        for (let attempt = 1; ; attempt++) {
          // Re-probe under the lock; the earlier pick may have been taken since.
          if (!(await this.isPortAvailable(displayPort))) {
            displayPort = await this.findAvailableDisplayPort(SPICE_MIN_PORT)
          }
          createConfig.displayPort = displayPort
          const commandBuilder = this.buildQemuCommand(
            createConfig, diskPaths, qmpSocketPath, pidFilePath, tapDevice, macAddress,
            { ...qemuBuildConfig, displayPort }
          )
          const proc = new QemuProcess(vmId, commandBuilder)
          proc.setQmpSocketPath(qmpSocketPath)
          proc.setPidFilePath(pidFilePath)
          resources.qemuProcess = proc
          try {
            await proc.start()
            return proc
          } catch (error) {
            const msg = error instanceof Error ? error.message : String(error)
            const portConflict = /address already in use|failed to bind|bind\(\)|could not set up host forwarding/i.test(msg)
            if (portConflict && attempt < MAX_PORT_ATTEMPTS) {
              this.debug.log('warn', `Display port ${displayPort} conflict on spawn (attempt ${attempt}); re-allocating`)
              displayPort = await this.findAvailableDisplayPort(displayPort + 1)
              continue
            }
            throw error
          }
        }
      })

      const pid = qemuProcess.getPid()
      if (!pid) {
        throw new LifecycleError(
          LifecycleErrorCode.PROCESS_ERROR,
          'QEMU process started but PID not available',
          vmId
        )
      }
      this.debug.log(`QEMU process started with PID: ${pid}`)

      // 14a. Verify TAP device connection (QEMU should have attached to the TAP device)
      this.debug.log(`Verifying TAP device connection: ${tapDevice}`)
      await this.verifyTapConnection(tapDevice, vmId, pid, bridge)
      this.debug.log(`TAP device ${tapDevice} has carrier - QEMU connected successfully`)

      // 14b. Apply CPU pinning if configured (best-effort, applyCpuPinning handles errors internally)
      if (vmConfig.configuration?.cpuPinning?.cores && vmConfig.configuration.cpuPinning.cores.length > 0) {
        const cores = vmConfig.configuration.cpuPinning.cores
        this.debug.log(`Applying CPU pinning for VM ${vmId}: cores ${cores.join(',')}`)
        const pinResult = await this.cgroupsManager.applyCpuPinning(pid, cores)
        if (!pinResult.applied) {
          this.debug.log('warn', `CPU pinning REQUESTED but NOT applied for VM ${vmId} (cores ${cores.join(',')}): ${pinResult.reason ?? 'unknown'}`)
        }
      }

      // 15. Wait for QMP socket and connect
      this.debug.log(`Connecting to QMP socket: ${qmpSocketPath}`)
      await this.waitForSocket(qmpSocketPath)
      const qmpClient = new QMPClient(qmpSocketPath, {
        connectTimeout: DEFAULT_QMP_CONNECT_TIMEOUT,
        reconnect: true,
        maxReconnectAttempts: 3
      })
      resources.qmpClient = qmpClient
      await qmpClient.connect()

      // 15a. Deliver the display password over QMP (never on the QEMU command line).
      await this.applyDisplayPassword(qmpClient, displayProtocol, displayPassword)

      // 16. Verify VM status via QMP
      const status = await qmpClient.queryStatus()
      this.debug.log(`QMP status: ${status.status}`)

      // 17. Update database configuration with runtime values
      await this.prisma.updateMachineConfiguration(vmId, {
        qmpSocketPath,
        qemuPid: pid,
        tapDeviceName: tapDevice,
        graphicProtocol: displayProtocol,
        graphicPort: displayPort,
        graphicPassword: displayPassword ?? null,
        graphicHost: displayAddr,
        // Persist effective QEMU configuration used for this boot
        bridge,
        machineType: effectiveMachineType,
        cpuModel: effectiveCpuModel,
        diskBus: effectiveDiskBus,
        diskCacheMode: effectiveDiskCacheMode,
        networkModel: effectiveNetworkModel,
        networkQueues: vmConfig.configuration?.networkQueues ?? null,
        memoryBalloon: effectiveMemoryBalloon,
        // Store disk paths for multi-disk support (also migrates legacy VMs)
        diskPaths,
        // Preserve existing CPU pinning configuration (don't overwrite with null)
        cpuPinning: vmConfig.configuration?.cpuPinning?.cores && vmConfig.configuration.cpuPinning.cores.length > 0
          ? { cores: vmConfig.configuration.cpuPinning.cores }
          : vmConfig.configuration?.cpuPinning ?? null
      })

      // 18. Update database status to 'running'
      await this.prisma.updateMachineStatus(vmId, 'running')

      // 19. Attach event handler for monitoring
      await this.eventHandler.attachToVM(vmId, qmpClient)

      // 20. Emit event to backend
      this.emitEvent('machines', 'power_on', vmId, { pid, tapDevice })

      this.debug.log(`VM started successfully: ${vmId}`)

      return {
        success: true,
        message: `VM ${vmId} started successfully`,
        vmId,
        timestamp
      }
    } catch (error) {
      this.debug.log('error', `Failed to start VM: ${error instanceof Error ? error.message : String(error)}`)
      await this.cleanup(resources)
      if (error instanceof LifecycleError) {
        throw error
      }
      throw this.wrapError(error, LifecycleErrorCode.START_FAILED, vmId)
    }
  }

  /**
   * Stops a running VM using ACPI graceful shutdown.
   *
   * ## ACPI Shutdown Flow
   *
   * This method implements graceful VM shutdown using the ACPI powerdown mechanism:
   *
   * 1. **Host sends system_powerdown via QMP** - The `powerdown()` command sends an
   *    ACPI power button press event to the guest OS
   * 2. **Guest OS receives ACPI event** - The guest initiates its normal shutdown
   *    sequence (running shutdown scripts, flushing buffers, closing applications)
   * 3. **Guest completes shutdown** - After the guest finishes, it signals completion
   * 4. **QEMU exits automatically** - Because our QEMU instances are NOT started with
   *    the `-no-shutdown` flag, QEMU automatically exits when the guest shuts down
   * 5. **VMLifecycle monitors process exit** - We poll the QEMU process status until
   *    it exits or the timeout expires
   * 6. **Force kill on timeout** - If the timeout expires and `force: true` (default),
   *    we send SIGKILL to terminate QEMU immediately
   * 7. **Resource cleanup** - Detach EventHandler, update DB, clear volatile config,
   *    detach TAP from bridge, detach firewall jump rules, cleanup cgroup scopes
   *
   * ## Why quit() is Never Called
   *
   * The QMP `quit` command is intentionally NOT used during normal shutdown because:
   *
   * - **ACPI shutdowns are graceful**: The guest OS can flush disk buffers, close files,
   *   run shutdown scripts (e.g., systemd services), and unmount filesystems safely
   * - **quit() is immediate**: It terminates QEMU instantly without guest cooperation,
   *   which can cause data loss or filesystem corruption
   * - **QEMU auto-exits**: After ACPI shutdown completes, QEMU exits naturally since
   *   we don't use the `-no-shutdown` flag - making `quit()` redundant
   * - **Socket race condition**: By the time we'd call quit(), the QMP socket may
   *   already be closed as QEMU is shutting down
   *
   * The `quit()` method exists in QMPClient for emergency scenarios but is not used
   * in the standard shutdown flow.
   *
   * ## Guest-Initiated vs Host-Initiated Shutdowns
   *
   * **Host-initiated** (this method):
   * - Triggered by user clicking PowerOff in UI, calling stopVM mutation
   * - VMLifecycle.stop() handles entire flow including cleanup
   * - Configurable timeout (default 30s, backend typically uses 120s)
   *
   * **Guest-initiated** (handled by EventHandler):
   * - Triggered by user shutting down from inside the VM
   * - EventHandler.terminateQEMUProcess() monitors exit and cleans up
   * - Fixed 30s monitoring timeout (no force-kill, investigation warranted)
   *
   * Both flows produce identical QEMU behavior (ACPI shutdown → auto-exit) and
   * perform the same resource cleanup. The EventHandler cleanup ensures VMs shut
   * down cleanly even when the user initiates shutdown from inside the guest OS.
   *
   * ## Timeout Behavior
   *
   * The timeout applies to waiting for QEMU process exit after ACPI powerdown:
   * - **Default**: 30 seconds (DEFAULT_STOP_TIMEOUT)
   * - **Backend override**: Typically 120 seconds for user-initiated operations
   * - **EventHandler monitoring**: Fixed 30 seconds for guest-initiated shutdowns
   *
   * If timeout expires and `force: true`:
   * - SIGKILL is sent to QEMU process
   * - VM is marked as stopped in database
   * - Cleanup proceeds normally
   * - Result includes `forced: true` flag
   *
   * ## PID Invariant
   *
   * **INVARIANT**: For running VMs, `qemuPid` must be present in the database.
   * This method relies on the stored PID to terminate QEMU processes. If `qemuPid`
   * is missing from the database but a QEMU process is actually running (stray process),
   * `stop()` cannot terminate it since we have no way to identify which process belongs
   * to this VM. Such stray processes may occur due to:
   * - Incomplete cleanup after a crash
   * - Database corruption or rollback
   * - Manual process manipulation outside the system
   *
   * Use `getStatus()` to detect and diagnose PID/process inconsistencies.
   *
   * @param vmId - VM identifier
   * @param config - Stop configuration (default: graceful with 30s timeout and force)
   * @returns VMOperationResult indicating success or failure
   *
   * @see QMPClient.powerdown() for the ACPI shutdown command
   * @see EventHandler.terminateQEMUProcess() for guest-initiated shutdown handling
   * @see destroyResources() for permanent VM deletion with resource destruction
   *
   * @example
   * ```typescript
   * // Graceful shutdown with 2 minute timeout (recommended for user-facing operations)
   * await lifecycle.stop(vmId, { graceful: true, timeout: 120000, force: true })
   *
   * // Quick shutdown for tests or automation
   * await lifecycle.stop(vmId, { graceful: true, timeout: 5000, force: true })
   *
   * // Force kill without attempting graceful (emergency use only)
   * await lifecycle.stop(vmId, { graceful: false, force: true })
   * ```
   */
  async stop (vmId: string, config?: VMStopConfig): Promise<VMOperationResult> {
    const stopConfig: Required<VMStopConfig> = {
      graceful: config?.graceful ?? true,
      timeout: config?.timeout ?? DEFAULT_STOP_TIMEOUT,
      force: config?.force ?? true
    }

    this.debug.log(`Stopping VM: ${vmId} (graceful: ${stopConfig.graceful}, timeout: ${stopConfig.timeout}ms)`)
    const timestamp = new Date()
    let forced = false

    try {
      // Fetch VM configuration
      const vmConfig = await this.prisma.findMachineWithConfig(vmId)
      if (!vmConfig) {
        throw new LifecycleError(
          LifecycleErrorCode.VM_NOT_FOUND,
          `VM not found: ${vmId}`,
          vmId
        )
      }

      const qmpSocketPath = vmConfig.configuration?.qmpSocketPath
      let pid = vmConfig.configuration?.qemuPid
      const tapDevice = vmConfig.configuration?.tapDeviceName

      // Log diagnostic info for debugging graceful shutdown issues
      this.debug.log('info', `Stop attempt - graceful: ${stopConfig.graceful}, qmpSocketPath: ${qmpSocketPath ?? 'NULL'}, pid: ${pid ?? 'NULL'}`)

      // Orphan-recovery: if the DB lost the PID (a backend restart between the QEMU
      // spawn and the qemuPid persist, a crash, or manual DB edits) a -daemonize'd
      // QEMU can still be running — serving SPICE, holding the TAP/disk. With no PID
      // every branch below no-ops and stop() falsely reports success, ORPHANING the
      // live process; and the delete path then removes the pidfile so the
      // pidfile-based HealthMonitor reaper can no longer see it either. Recover the
      // real PID from the deterministic pidfile (fail-closed /proc identity guard —
      // a recycled/foreign PID is never adopted) so the reap below actually happens.
      if (!pid || !this.isProcessAlive(pid)) {
        const recovered = this.recoverStalePidFromPidfile(vmConfig.internalName)
        if (recovered !== null) {
          this.debug.log('warn', `VM ${vmId}: DB qemuPid=${pid ?? 'NULL'} unusable but a live QEMU (PID ${recovered}) was recovered from its pidfile — stopping it instead of orphaning it`)
          pid = recovered
        }
      }

      if (stopConfig.graceful && !qmpSocketPath) {
        this.debug.log('warn', `VM ${vmId}: No QMP socket path in DB - graceful shutdown will not be attempted`)
      }

      // Check if already stopped
      // NOTE: When !pid, we assume the VM is already off or in an inconsistent state where
      // the PID was never recorded. We cannot detect or terminate stray QEMU processes
      // without a known PID. If a QEMU process is actually running but the PID is missing
      // from the database (due to crash, corruption, or manual intervention), this method
      // will report success but the stray process will remain. Use getStatus() to detect
      // such inconsistencies by checking for processes without corresponding DB PIDs.
      if (vmConfig.status === 'off') {
        if (!pid || !this.isProcessAlive(pid)) {
          return {
            success: true,
            message: `VM ${vmId} is already stopped`,
            vmId,
            timestamp
          }
        }
        // Process is alive but DB says off - continue with stop
      }

      // Early check: If process is already dead, skip QMP operations entirely
      // This handles the case where guest-initiated shutdown has already completed
      if (pid && !this.isProcessAlive(pid)) {
        this.debug.log('info', `QEMU process (PID ${pid}) already terminated for VM ${vmId} - skipping QMP operations`)
        // Process is dead, jump directly to cleanup (no graceful shutdown needed)
        // This path is reached when guest initiated shutdown and QEMU exited before stop() was called
      } else if (stopConfig.graceful && qmpSocketPath && pid) {
        // Process is alive, try graceful shutdown via QMP
        // Verify socket exists before attempting connection
        const socketExists = fs.existsSync(qmpSocketPath)
        this.debug.log('info', `QMP socket ${qmpSocketPath} exists: ${socketExists}`)

        if (!socketExists) {
          this.debug.log('warn', `QMP socket ${qmpSocketPath} does not exist - cannot send ACPI powerdown`)
          // Fall through to force kill if enabled
          if (stopConfig.force && this.isProcessAlive(pid)) {
            this.debug.log('warn', `Falling back to force kill for VM ${vmId} (socket missing)`)
            await this.forceKillProcess(pid, vmConfig.internalName)
            forced = true
          } else {
            throw new LifecycleError(
              LifecycleErrorCode.STOP_FAILED,
              `QMP socket ${qmpSocketPath} does not exist and force is disabled`,
              vmId
            )
          }
        } else {
          // Socket exists, attempt graceful shutdown
          // Try to use existing QMP connection from EventHandler first (QEMU only accepts one connection)
          const existingQmpClient = this.eventHandler.getQMPClient(vmId)

          if (existingQmpClient) {
            // Use existing connection
            this.debug.log('info', `Using existing QMP connection for VM ${vmId}`)
            try {
              // ACPI powerdown - guest will shutdown gracefully, QEMU exits automatically
              await existingQmpClient.powerdown()
              this.debug.log('info', `Sent system_powerdown (ACPI) to VM ${vmId} - waiting for guest OS to shutdown and QEMU to exit automatically`)

              // Wait for natural QEMU exit (no quit command needed - see class documentation)
              // QEMU will automatically exit when guest completes shutdown (no -no-shutdown flag).
              // Timeout protects against hung guests or ACPI-unsupported OSes.
              this.debug.log('info', `Waiting up to ${stopConfig.timeout}ms for QEMU process ${pid} to exit after ACPI shutdown`)
              const exited = await this.waitForProcessExit(pid, stopConfig.timeout)

              if (!exited && stopConfig.force) {
                // Timeout protection: guest may not support ACPI or be hung
                this.debug.log('warn', `ACPI shutdown timed out after ${stopConfig.timeout}ms - guest may not support ACPI or is hung. Force killing VM ${vmId}`)
                await this.forceKillProcess(pid, vmConfig.internalName)
                forced = true
              }
            } catch (qmpError) {
              const errorMsg = qmpError instanceof Error ? qmpError.message : String(qmpError)
              this.debug.log('error', `QMP powerdown failed for VM ${vmId}: ${errorMsg}`)
              if (stopConfig.force && pid && this.isProcessAlive(pid)) {
                this.debug.log('warn', `Falling back to force kill for VM ${vmId}`)
                await this.forceKillProcess(pid, vmConfig.internalName)
                forced = true
              }
            }
          } else {
            // No existing connection, create a new one
            this.debug.log('info', `No existing QMP connection for VM ${vmId}, creating new connection`)
            try {
              const qmpClient = new QMPClient(qmpSocketPath, {
                connectTimeout: DEFAULT_QMP_CONNECT_TIMEOUT
              })

              try {
                await qmpClient.connect()
                // ACPI powerdown - guest will shutdown gracefully, QEMU exits automatically
                this.debug.log('info', `QMP connected to ${qmpSocketPath}, sending system_powerdown (ACPI)`)
                await qmpClient.powerdown()
                this.debug.log('info', `Sent system_powerdown (ACPI) to VM ${vmId} - waiting for guest OS to shutdown and QEMU to exit automatically`)

                // Wait for natural QEMU exit (no quit command needed - see class documentation)
                // QEMU will automatically exit when guest completes shutdown (no -no-shutdown flag).
                // Timeout protects against hung guests or ACPI-unsupported OSes.
                this.debug.log('info', `Waiting up to ${stopConfig.timeout}ms for QEMU process ${pid} to exit after ACPI shutdown`)
                const exited = await this.waitForProcessExit(pid, stopConfig.timeout)

                if (!exited && stopConfig.force) {
                  // Timeout protection: guest may not support ACPI or be hung
                  this.debug.log('warn', `ACPI shutdown timed out after ${stopConfig.timeout}ms - guest may not support ACPI or is hung. Force killing VM ${vmId}`)
                  await this.forceKillProcess(pid, vmConfig.internalName)
                  forced = true
                }
              } finally {
                await qmpClient.disconnect()
              }
            } catch (qmpError) {
              // QMP failed, try force kill if enabled
              const errorMsg = qmpError instanceof Error ? qmpError.message : String(qmpError)
              this.debug.log('error', `QMP powerdown failed for VM ${vmId}: ${errorMsg}`)
              if (stopConfig.force && pid && this.isProcessAlive(pid)) {
                this.debug.log('warn', `Falling back to force kill for VM ${vmId}`)
                await this.forceKillProcess(pid, vmConfig.internalName)
                forced = true
              }
            }
          }
        }
      } else if (pid && this.isProcessAlive(pid)) {
        // No graceful shutdown, just force kill
        if (stopConfig.force) {
          await this.forceKillProcess(pid, vmConfig.internalName)
          forced = true
        } else {
          throw new LifecycleError(
            LifecycleErrorCode.STOP_FAILED,
            'Cannot stop VM without graceful or force option',
            vmId
          )
        }
      }

      // Detach event handler before DB updates
      // This stops QMP event processing so that any late events don't trigger
      // StateSync updates after we've manually set the status to 'off'
      await this.eventHandler.detachFromVM(vmId)

      // Update database status to 'off'
      // NOTE ON STATE SYNC: By setting status to 'off' and clearing configuration,
      // HealthMonitor will ignore this VM since:
      // 1. findRunningVMs() only returns VMs with status='running'
      // 2. clearMachineConfiguration() removes qemuPid, so even if status update
      //    is delayed, HealthMonitor won't find a PID to check
      // EventHandler is detached above, so no QMP events will trigger status changes.
      //
      // onlyIfNotIn closes two races. (1) InstallResetTracker: that detector
      // force-stops a boot/install-looping VM (calling into this stop()) and then
      // marks the row 'error'; this stop()'s own 'off' write can otherwise land
      // AFTER that 'error' and silently downgrade it, hiding the failure. (2) The
      // backend status-as-lock markers (audit C2/C3): a stop() that races a
      // cross-node migration ('moving'), a delete ('deleting'), a pool rebuild
      // ('rebuilding'), or a disk op (backing_up/restoring/snapshotting/capturing)
      // must NOT reset the row to 'off' — doing so silently RELEASES that lock,
      // letting a concurrent power-on/reclaim corrupt the disk or split-brain the
      // VM. A VM parked in any of these claim states keeps it; only genuine QEMU
      // power states fall through to 'off'.
      await this.prisma.updateMachineStatus(vmId, 'off', {
        onlyIfNotIn: [
          'error',
          'moving', 'deleting', 'rebuilding',
          'backing_up', 'restoring', 'snapshotting', 'capturing'
        ]
      })

      // Clear volatile machine configuration (qmpSocketPath, qemuPid)
      // Note: tapDeviceName is preserved for persistent TAP device reuse on restart
      // This ensures HealthMonitor won't attempt to check a stale PID
      await this.prisma.clearVolatileMachineConfiguration(vmId)

      // Detach TAP device from bridge (persistent - not destroyed)
      // The TAP device persists for reuse when VM restarts
      if (tapDevice) {
        try {
          await this.tapManager.detachFromBridge(tapDevice)
        } catch (tapError) {
          this.debug.log('warn', `Failed to detach TAP device: ${tapError instanceof Error ? tapError.message : String(tapError)}`)
        }
      }

      // Detach jump rules from nftables (chain and rules persist)
      // Only the routing from TAP to chain is removed; firewall rules survive stop/start
      try {
        await this.nftables.detachJumpRules(vmId)
      } catch (fwError) {
        this.debug.log('warn', `Failed to detach firewall jump rules: ${fwError instanceof Error ? fwError.message : String(fwError)}`)
      }

      // Cleanup empty cgroup scopes if CPU pinning was used
      // Note: Scopes are named by PID, so we do opportunistic cleanup of any empty scopes
      if (vmConfig.configuration?.cpuPinning?.cores) {
        try {
          const cleanedCount = await this.cgroupsManager.cleanupEmptyScopes()
          if (cleanedCount > 0) {
            this.debug.log(`Cleaned up ${cleanedCount} empty cgroup scope(s)`)
          }
        } catch (error) {
          // Log but don't fail stop operation
          this.debug.log('warn', `Failed to cleanup cgroup scopes: ${error instanceof Error ? error.message : String(error)}`)
        }
      }

      // Emit event
      this.emitEvent('machines', 'power_off', vmId, { forced })

      this.debug.log(`VM stopped: ${vmId}${forced ? ' (forced)' : ''}`)

      return {
        success: true,
        message: `VM ${vmId} stopped successfully${forced ? ' (forced)' : ''}`,
        vmId,
        timestamp,
        forced
      }
    } catch (error) {
      if (error instanceof LifecycleError) {
        throw error
      }
      throw this.wrapError(error, LifecycleErrorCode.STOP_FAILED, vmId)
    }
  }

  /**
   * Permanently destroys VM network resources (TAP device and firewall chain).
   * Call this when deleting a VM completely, NOT during normal stop/start cycles.
   *
   * This method:
   * 1. Stops the VM if running (with force)
   * 2. Destroys the TAP device permanently
   * 3. Removes the nftables firewall chain and all rules
   * 4. Clears all machine configuration from database (including tapDeviceName)
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async destroyResources (vmId: string): Promise<VMOperationResult> {
    this.debug.log(`Destroying resources for VM: ${vmId}`)
    const timestamp = new Date()

    try {
      // Fetch VM configuration
      const vmConfig = await this.prisma.findMachineWithConfig(vmId)
      if (!vmConfig) {
        // VM doesn't exist in DB, just return success
        return {
          success: true,
          message: `VM ${vmId} not found, nothing to destroy`,
          vmId,
          timestamp
        }
      }

      // Stop VM if running.
      // RE-ENTRANCY: keep this at the lifecycle level (this.stop). The facade
      // (Infinization.destroyVM) already holds the per-vmId mutex; calling the
      // facade stopVM here would re-acquire the same key and self-deadlock.
      if (vmConfig.status === 'running') {
        this.debug.log(`VM ${vmId} is running, stopping first`)
        await this.stop(vmId, { graceful: false, timeout: 5000, force: true })
      } else {
        // stop() only runs for status==='running'. But a VM parked in 'off'/'error'/
        // 'installing' (e.g. an install-loop the tracker marked 'error', or a state
        // lost on a backend restart) can still have a live -daemonize'd QEMU serving
        // SPICE. Deleting it must reap that orphan too, so recover it from the pidfile
        // and force-kill (identity-checked, fail-closed) rather than leaving it running
        // after the DB record and disk are gone.
        const orphanPid = this.recoverStalePidFromPidfile(vmConfig.internalName)
        if (orphanPid !== null) {
          this.debug.log('warn', `VM ${vmId}: status='${vmConfig.status}' (not running) but a live QEMU (PID ${orphanPid}) was found via its pidfile during delete — force-killing the orphan`)
          await this.forceKillProcess(orphanPid, vmConfig.internalName)
        }
      }

      const tapDevice = vmConfig.configuration?.tapDeviceName

      // Destroy TAP device permanently
      if (tapDevice) {
        try {
          await this.tapManager.destroy(tapDevice)
          this.debug.log(`TAP device destroyed: ${tapDevice}`)
        } catch (tapError) {
          this.debug.log('warn', `Failed to destroy TAP device: ${tapError instanceof Error ? tapError.message : String(tapError)}`)
        }
      }

      // Remove firewall chain permanently (including all rules)
      try {
        await this.nftables.removeVMChain(vmId)
        this.debug.log(`Firewall chain removed for VM: ${vmId}`)
      } catch (fwError) {
        this.debug.log('warn', `Failed to remove firewall chain: ${fwError instanceof Error ? fwError.message : String(fwError)}`)
      }

      // Clear ALL machine configuration (including tapDeviceName)
      await this.prisma.clearMachineConfiguration(vmId)

      this.debug.log(`Resources destroyed for VM: ${vmId}`)

      return {
        success: true,
        message: `VM ${vmId} resources destroyed successfully`,
        vmId,
        timestamp
      }
    } catch (error) {
      if (error instanceof LifecycleError) {
        throw error
      }
      throw this.wrapError(error, LifecycleErrorCode.STOP_FAILED, vmId)
    }
  }

  /**
   * Restarts a VM by stopping and starting it.
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async restart (vmId: string): Promise<VMOperationResult> {
    this.debug.log(`Restarting VM: ${vmId}`)
    const timestamp = new Date()

    try {
      // RE-ENTRANCY: these self-calls MUST stay at the lifecycle level
      // (this.stop / this.start). The facade (Infinization.restartVM) holds the
      // per-vmId mutex for the whole restart; routing back through the facade
      // methods here would re-acquire the same key and self-deadlock.
      // Stop the VM
      const stopResult = await this.stop(vmId, {
        graceful: true,
        timeout: DEFAULT_STOP_TIMEOUT,
        force: true
      })

      if (!stopResult.success) {
        return {
          success: false,
          message: `Failed to stop VM during restart: ${stopResult.error}`,
          error: stopResult.error,
          vmId,
          timestamp
        }
      }

      // Wait before starting
      await this.sleep(RESTART_DELAY_MS)

      // Start the VM
      const startResult = await this.start(vmId)

      if (!startResult.success) {
        return {
          success: false,
          message: `VM stopped but failed to start: ${startResult.error}`,
          error: startResult.error,
          vmId,
          timestamp
        }
      }

      return {
        success: true,
        message: `VM ${vmId} restarted successfully`,
        vmId,
        timestamp
      }
    } catch (error) {
      throw this.wrapError(error, LifecycleErrorCode.STOP_FAILED, vmId)
    }
  }

  /**
   * Suspends (pauses) a running VM.
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async suspend (vmId: string): Promise<VMOperationResult> {
    this.debug.log(`Suspending VM: ${vmId}`)
    const timestamp = new Date()

    try {
      const vmConfig = await this.prisma.findMachineWithConfig(vmId)
      if (!vmConfig) {
        throw new LifecycleError(
          LifecycleErrorCode.VM_NOT_FOUND,
          `VM not found: ${vmId}`,
          vmId
        )
      }

      if (vmConfig.status !== 'running') {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_STATE,
          `Cannot suspend VM in state: ${vmConfig.status}`,
          vmId
        )
      }

      const qmpSocketPath = vmConfig.configuration?.qmpSocketPath
      if (!qmpSocketPath) {
        throw new LifecycleError(
          LifecycleErrorCode.QMP_ERROR,
          'QMP socket path not found',
          vmId
        )
      }

      // Reuse the EventHandler's live QMP connection (single-client socket).
      await this.withQMPClient(vmId, qmpSocketPath, (client) => client.stop())
      await this.prisma.updateMachineStatus(vmId, 'suspended')
      this.emitEvent('machines', 'suspend', vmId)

      return {
        success: true,
        message: `VM ${vmId} suspended`,
        vmId,
        timestamp
      }
    } catch (error) {
      if (error instanceof LifecycleError) {
        throw error
      }
      throw this.wrapError(error, LifecycleErrorCode.QMP_ERROR, vmId)
    }
  }

  /**
   * Resumes a suspended VM.
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async resume (vmId: string): Promise<VMOperationResult> {
    this.debug.log(`Resuming VM: ${vmId}`)
    const timestamp = new Date()

    try {
      const vmConfig = await this.prisma.findMachineWithConfig(vmId)
      if (!vmConfig) {
        throw new LifecycleError(
          LifecycleErrorCode.VM_NOT_FOUND,
          `VM not found: ${vmId}`,
          vmId
        )
      }

      if (vmConfig.status !== 'suspended' && vmConfig.status !== 'paused') {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_STATE,
          `Cannot resume VM in state: ${vmConfig.status}`,
          vmId
        )
      }

      const qmpSocketPath = vmConfig.configuration?.qmpSocketPath
      if (!qmpSocketPath) {
        throw new LifecycleError(
          LifecycleErrorCode.QMP_ERROR,
          'QMP socket path not found',
          vmId
        )
      }

      // Reuse the EventHandler's live QMP connection (single-client socket).
      await this.withQMPClient(vmId, qmpSocketPath, (client) => client.cont())
      await this.prisma.updateMachineStatus(vmId, 'running')
      this.emitEvent('machines', 'resume', vmId)

      return {
        success: true,
        message: `VM ${vmId} resumed`,
        vmId,
        timestamp
      }
    } catch (error) {
      if (error instanceof LifecycleError) {
        throw error
      }
      throw this.wrapError(error, LifecycleErrorCode.QMP_ERROR, vmId)
    }
  }

  /**
   * Resets a VM (hardware reset).
   *
   * @param vmId - VM identifier
   * @returns VMOperationResult indicating success or failure
   */
  async reset (vmId: string): Promise<VMOperationResult> {
    this.debug.log(`Resetting VM: ${vmId}`)
    const timestamp = new Date()

    try {
      const vmConfig = await this.prisma.findMachineWithConfig(vmId)
      if (!vmConfig) {
        throw new LifecycleError(
          LifecycleErrorCode.VM_NOT_FOUND,
          `VM not found: ${vmId}`,
          vmId
        )
      }

      if (vmConfig.status !== 'running') {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_STATE,
          `Cannot reset VM in state: ${vmConfig.status}`,
          vmId
        )
      }

      const qmpSocketPath = vmConfig.configuration?.qmpSocketPath
      if (!qmpSocketPath) {
        throw new LifecycleError(
          LifecycleErrorCode.QMP_ERROR,
          'QMP socket path not found',
          vmId
        )
      }

      // Reuse the EventHandler's live QMP connection (single-client socket).
      await this.withQMPClient(vmId, qmpSocketPath, (client) => client.reset())
      this.emitEvent('machines', 'update', vmId, { type: 'hardware' })

      return {
        success: true,
        message: `VM ${vmId} reset`,
        vmId,
        timestamp
      }
    } catch (error) {
      if (error instanceof LifecycleError) {
        throw error
      }
      throw this.wrapError(error, LifecycleErrorCode.QMP_ERROR, vmId)
    }
  }

  /**
   * Gets detailed status of a VM.
   *
   * @param vmId - VM identifier
   * @returns VMStatusResult with detailed status information
   */
  async getStatus (vmId: string): Promise<VMStatusResult> {
    this.debug.log(`Getting status for VM: ${vmId}`)

    try {
      const vmConfig = await this.prisma.findMachineWithConfig(vmId)
      if (!vmConfig) {
        throw new LifecycleError(
          LifecycleErrorCode.VM_NOT_FOUND,
          `VM not found: ${vmId}`,
          vmId
        )
      }

      const pid = vmConfig.configuration?.qemuPid ?? null
      const processAlive = pid ? this.isProcessAlive(pid) : false
      const qmpSocketPath = vmConfig.configuration?.qmpSocketPath ?? null
      const tapDevice = vmConfig.configuration?.tapDeviceName ?? null

      // Determine consistency
      const dbSaysRunning = vmConfig.status === 'running'
      const consistent = dbSaysRunning === processAlive

      // Warn about potential stray QEMU process: DB says VM is running but no PID is stored.
      // This indicates the PID was never recorded or was lost (crash, corruption, manual intervention).
      // A QEMU process may be running without our ability to track or terminate it via stop().
      // This is a diagnostic aid - the system cannot automatically recover from this state.
      if (dbSaysRunning && !pid) {
        this.debug.log('warn', `VM ${vmId}: Database shows status='running' but no qemuPid stored. ` +
          `A stray QEMU process may exist that cannot be tracked or terminated via stop(). ` +
          `Manual intervention may be required (check for orphaned qemu-system-* processes).`)
      }

      // Warn about inconsistent state where DB says running but process is dead
      if (!consistent && dbSaysRunning && pid && !processAlive) {
        this.debug.log('warn', `VM ${vmId}: Database shows status='running' with PID ${pid} but process is not alive. ` +
          `State inconsistency detected - VM may have crashed or been terminated externally.`)
      }

      let qmpStatus: string | null = null
      let uptime: number | null = null

      // Query QMP status if process is alive.
      // Reuse the EventHandler's live QMP connection — opening a second client
      // on the single-client socket would hang until timeout and leave qmpStatus
      // null (masking the real run-state) for every monitored VM.
      if (processAlive && qmpSocketPath) {
        try {
          const status = await this.withQMPClient(vmId, qmpSocketPath, (client) => client.queryStatus())
          qmpStatus = status.status
          // QMP doesn't provide direct uptime, would need to track start time
        } catch {
          // QMP query failed, but process is alive
          this.debug.log('warn', `Failed to query QMP status for VM: ${vmId}`)
        }
      }

      return {
        vmId,
        status: vmConfig.status,
        qmpStatus,
        pid,
        uptime,
        processAlive,
        consistent,
        tapDevice,
        qmpSocketPath
      }
    } catch (error) {
      if (error instanceof LifecycleError) {
        throw error
      }
      throw this.wrapError(error, LifecycleErrorCode.DATABASE_ERROR, vmId)
    }
  }

  // ===========================================================================
  // Private Helper Methods
  // ===========================================================================

  /**
   * Runs an operation against the VM's QMP socket, reusing the EventHandler's
   * existing connection when the VM is attached.
   *
   * QEMU's QMP socket accepts only ONE client at a time. While EventHandler
   * holds the connection (true for every monitored/running VM), opening a
   * second QMPClient connects at the socket level but QEMU never sends the
   * greeting, so connect() blocks until connectTimeout and the operation fails.
   * That is why suspend/resume/reset/getStatus historically broke on running
   * VMs. We therefore borrow the live client when present and only open — and
   * close — a transient one when the VM is not attached. A BORROWED client is
   * never disconnected here: it belongs to EventHandler.
   */
  private async withQMPClient<T> (
    vmId: string,
    qmpSocketPath: string,
    fn: (client: QMPClient) => Promise<T>
  ): Promise<T> {
    const borrowed = this.eventHandler.getQMPClient(vmId)
    if (borrowed) {
      this.debug.log('info', `Reusing existing QMP connection for VM ${vmId}`)
      return await fn(borrowed)
    }

    const client = new QMPClient(qmpSocketPath, {
      connectTimeout: DEFAULT_QMP_CONNECT_TIMEOUT
    })
    await client.connect()
    try {
      return await fn(client)
    } finally {
      await client.disconnect()
    }
  }

  /**
   * Validates VM creation configuration
   */
  private validateCreateConfig (config: VMCreateConfig): void {
    const errors: string[] = []

    if (!config.vmId || config.vmId.trim().length === 0) {
      errors.push('VM database ID (vmId) is required')
    }
    if (!config.name || config.name.trim().length === 0) {
      errors.push('VM name is required')
    }
    if (!config.internalName || config.internalName.trim().length === 0) {
      errors.push('VM internal name is required')
    }
    if (!config.os || config.os.trim().length === 0) {
      errors.push('OS type is required')
    }
    if (!config.cpuCores || config.cpuCores < 1) {
      errors.push('CPU cores must be at least 1')
    }
    if (!config.ramGB || config.ramGB < 0.5) {
      errors.push('RAM must be at least 0.5 GB')
    }
    // Validate disks array
    if (!config.disks || !Array.isArray(config.disks) || config.disks.length === 0) {
      errors.push('At least one disk configuration is required')
    } else {
      config.disks.forEach((disk, index) => {
        if (!disk.sizeGB || disk.sizeGB < 1) {
          errors.push(`Disk ${index}: size must be at least 1 GB`)
        }
      })
    }
    if (!config.bridge || config.bridge.trim().length === 0) {
      errors.push('Network bridge is required')
    }
    if (!config.displayType || !['spice', 'vnc'].includes(config.displayType)) {
      errors.push('Display type must be "spice" or "vnc"')
    }
    if (config.displayPort === undefined || config.displayPort < 0) {
      errors.push('Display port is required and must be non-negative')
    }

    // Validate CPU pinning strategy if provided
    if (config.cpuPinningStrategy !== undefined) {
      const validStrategies = ['basic', 'hybrid'] as const
      if (!validStrategies.includes(config.cpuPinningStrategy)) {
        errors.push(`Invalid cpuPinningStrategy: '${config.cpuPinningStrategy}'. Must be 'basic' or 'hybrid'`)
      }
    }

    if (errors.length > 0) {
      throw new LifecycleError(
        LifecycleErrorCode.INVALID_CONFIG,
        `Invalid VM configuration: ${errors.join(', ')}`,
        config.vmId,
        { errors }
      )
    }
  }

  /**
   * Generates file paths for VM resources
   *
   * @param internalName - VM internal name
   * @param diskCount - Number of disks (default: 1)
   * @returns Object with disk paths array, QMP socket path, and PID file path
   */
  private generatePaths (internalName: string, diskCount: number = 1): {
    diskPaths: string[]
    qmpSocketPath: string
    pidFilePath: string
  } {
    const diskPaths: string[] = []
    for (let i = 0; i < diskCount; i++) {
      // First disk has no suffix, subsequent disks have -disk1, -disk2, etc.
      const suffix = i === 0 ? '' : `-disk${i}`
      diskPaths.push(path.join(this.diskDir, `${internalName}${suffix}.qcow2`))
    }

    return {
      diskPaths,
      qmpSocketPath: path.join(this.qmpSocketDir, `${internalName}.sock`),
      pidFilePath: path.join(this.pidfileDir, `${internalName}.pid`)
    }
  }

  /**
   * Ensures required directories exist
   */
  private async ensureDirectories (): Promise<void> {
    const dirs = [
      this.diskDir,
      this.qmpSocketDir,
      this.pidfileDir
    ]
    for (const dir of dirs) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true })
        this.debug.log(`Created directory: ${dir}`)
      }
    }
  }

  /**
   * Fetches firewall rules for a VM, split by source (department vs VM-specific).
   *
   * Uses {@link PrismaAdapter.getFirewallRulesSplit} to query department-inherited
   * rules and VM-specific rules separately, preserving the `overridesDept`
   * override semantics that {@link NftablesService.mergeRules} applies downstream.
   * Previously all rules were lumped into the `department` bucket, which defeated
   * VM-rule overrides of department rules; the split query fixes that.
   */
  private async fetchFirewallRules (vmId: string): Promise<{
    department: FirewallRuleInput[]
    vm: FirewallRuleInput[]
    /** Terminal posture derived from the department policy (fail-closed 'drop'). */
    defaultAction: FirewallDefaultAction
  }> {
    try {
      const { departmentRules, vmRules } = await this.prisma.getFirewallRulesSplit(vmId)
      // Derive the terminal posture from the department's policy so an ALLOW_ALL
      // department is not over-blocked by the fail-closed 'drop' default. Anything
      // other than an explicit ALLOW_ALL maps to 'drop' (fail-closed).
      const policy = await this.prisma.getDepartmentFirewallPolicy(vmId)
      const defaultAction: FirewallDefaultAction = policy === 'ALLOW_ALL' ? 'accept' : 'drop'
      return {
        department: departmentRules,
        vm: vmRules,
        defaultAction
      }
    } catch (error) {
      // FAIL-CLOSED: only a genuine "this machine has no firewall config" is a
      // safe empty result. A real DB error (outage, deadlock) must NOT be
      // swallowed into empty rules — that previously let the VM boot with NO
      // terminal drop (unrestricted L3). Re-throw so create()/start() abort and
      // the VM is never brought up unfiltered. The terminal drop is still
      // installed unconditionally for the legitimately-empty case (see callers).
      if (isPrismaAdapterError(error) && error.code === PrismaAdapterErrorCode.MACHINE_NOT_FOUND) {
        this.debug.log('warn', `No firewall config found for VM ${vmId}; applying default-deny terminal posture only`)
        return { department: [], vm: [], defaultAction: 'drop' }
      }
      this.debug.log('error', `Failed to fetch firewall rules for VM ${vmId} (failing closed): ${error instanceof Error ? error.message : String(error)}`)
      throw error
    }
  }

  // ===========================================================================
  // QEMU Configuration Validation Helpers
  // ===========================================================================

  /** Allowed machine types for QEMU */
  private static readonly VALID_MACHINE_TYPES = ['q35', 'pc'] as const
  /** Allowed disk bus types */
  private static readonly VALID_DISK_BUS_TYPES = ['virtio', 'scsi', 'ide', 'sata'] as const
  /** Allowed disk cache modes */
  private static readonly VALID_DISK_CACHE_MODES = ['writeback', 'writethrough', 'none', 'unsafe'] as const
  /** Allowed network models */
  private static readonly VALID_NETWORK_MODELS = ['virtio-net-pci', 'e1000'] as const
  /** Allowed CPU pinning strategies */
  private static readonly VALID_CPU_PINNING_STRATEGIES = ['basic', 'hybrid'] as const

  /**
   * Validates machine type and returns a valid value, logging a warning if invalid.
   */
  private validateMachineType (value: string | null | undefined): 'q35' | 'pc' {
    const defaultValue: 'q35' | 'pc' = 'q35'
    if (!value) return defaultValue

    if (VMLifecycle.VALID_MACHINE_TYPES.includes(value as typeof VMLifecycle.VALID_MACHINE_TYPES[number])) {
      return value as 'q35' | 'pc'
    }

    this.debug.log('warn', `Invalid machineType '${value}', using default '${defaultValue}'`)
    return defaultValue
  }

  /**
   * Validates disk bus type and returns a valid value, logging a warning if invalid.
   */
  private validateDiskBus (value: string | null | undefined): 'virtio' | 'scsi' | 'ide' | 'sata' {
    const defaultValue = DEFAULT_DISK_BUS as 'virtio' | 'scsi' | 'ide' | 'sata'
    if (!value) return defaultValue

    if (VMLifecycle.VALID_DISK_BUS_TYPES.includes(value as typeof VMLifecycle.VALID_DISK_BUS_TYPES[number])) {
      return value as 'virtio' | 'scsi' | 'ide' | 'sata'
    }

    this.debug.log('warn', `Invalid diskBus '${value}', using default '${defaultValue}'`)
    return defaultValue
  }

  /**
   * Validates disk cache mode and returns a valid value, logging a warning if invalid.
   */
  private validateDiskCacheMode (value: string | null | undefined): 'writeback' | 'writethrough' | 'none' | 'unsafe' {
    const defaultValue = DEFAULT_DISK_CACHE as 'writeback' | 'writethrough' | 'none' | 'unsafe'
    if (!value) return defaultValue

    if (VMLifecycle.VALID_DISK_CACHE_MODES.includes(value as typeof VMLifecycle.VALID_DISK_CACHE_MODES[number])) {
      return value as 'writeback' | 'writethrough' | 'none' | 'unsafe'
    }

    this.debug.log('warn', `Invalid diskCacheMode '${value}', using default '${defaultValue}'`)
    return defaultValue
  }

  /**
   * Validates network model and returns a valid value, logging a warning if invalid.
   */
  private validateNetworkModel (value: string | null | undefined): 'virtio-net-pci' | 'e1000' {
    const defaultValue = DEFAULT_NETWORK_MODEL as 'virtio-net-pci' | 'e1000'
    if (!value) return defaultValue

    if (VMLifecycle.VALID_NETWORK_MODELS.includes(value as typeof VMLifecycle.VALID_NETWORK_MODELS[number])) {
      return value as 'virtio-net-pci' | 'e1000'
    }

    this.debug.log('warn', `Invalid networkModel '${value}', using default '${defaultValue}'`)
    return defaultValue
  }

  /**
   * Validates CPU pinning strategy and returns a valid value, logging a warning if invalid.
   *
   * @remarks
   * This method provides defensive validation against corrupt database values.
   * If the stored strategy is not 'basic' or 'hybrid', it returns 'basic' as the default.
   */
  private validateCpuPinningStrategy (value: string | null | undefined): 'basic' | 'hybrid' | undefined {
    if (value === null || value === undefined) return undefined

    if (VMLifecycle.VALID_CPU_PINNING_STRATEGIES.includes(value as typeof VMLifecycle.VALID_CPU_PINNING_STRATEGIES[number])) {
      return value as 'basic' | 'hybrid'
    }

    this.debug.log('warn', `Invalid cpuPinningStrategy '${value}', using default 'basic'`)
    return 'basic'
  }

  /**
   * Validates display port and returns a valid value, logging a warning if invalid.
   *
   * @param port - The port to validate (from database or config)
   * @returns A valid port number within SPICE_MIN_PORT-SPICE_MAX_PORT range, or SPICE_MIN_PORT as default
   *
   * @remarks
   * This method provides defensive validation against corrupt database values.
   * If the stored port is NULL, undefined, not an integer, or outside the valid
   * range (5900-65535), it returns the default port (5900) and logs a warning.
   */
  private validateDisplayPort (port: number | null | undefined): number {
    const defaultPort = SPICE_MIN_PORT

    // Handle NULL or undefined
    if (port === null || port === undefined) {
      return defaultPort
    }

    // Check if it's a valid integer
    if (!Number.isInteger(port)) {
      this.debug.log('warn', `Invalid displayPort '${port}' (not an integer), using default '${defaultPort}'`)
      return defaultPort
    }

    // Check if it's within valid range
    if (port < SPICE_MIN_PORT || port > SPICE_MAX_PORT) {
      this.debug.log('warn', `Invalid displayPort '${port}' (out of range ${SPICE_MIN_PORT}-${SPICE_MAX_PORT}), using default '${defaultPort}'`)
      return defaultPort
    }

    return port
  }

  /**
   * Checks if a TCP port is available for binding.
   *
   * @param port - The port number to check
   * @returns Promise resolving to true if port is available, false if in use
   *
   * @remarks
   * Creates a temporary TCP server to test port availability.
   * This is more reliable than checking /proc/net/tcp as it accounts
   * for ports in TIME_WAIT state and handles race conditions better.
   */
  private isPortAvailable (port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const net = require('net')
      const server = net.createServer()

      server.once('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
          resolve(false)
        } else {
          // Other errors (e.g., network issues) - assume port is unavailable
          this.debug.log('warn', `Port availability check failed for ${port}: ${err.message}`)
          resolve(false)
        }
      })

      server.once('listening', () => {
        server.close(() => {
          resolve(true)
        })
      })

      // Try to bind to all interfaces (0.0.0.0) to match SPICE/VNC behavior
      server.listen(port, '0.0.0.0')
    })
  }

  /**
   * Finds an available display port starting from the given port.
   *
   * @param startPort - The port to start searching from (default: SPICE_MIN_PORT)
   * @param maxAttempts - Maximum number of ports to try (default: 100)
   * @returns Promise resolving to an available port number
   * @throws LifecycleError if no available port is found within the range
   *
   * @remarks
   * Searches sequentially from startPort up to startPort + maxAttempts.
   * This is used during VM creation and start to find a free display port
   * when the preferred port is already in use by another VM or process.
   */
  private async findAvailableDisplayPort (startPort: number = SPICE_MIN_PORT, maxAttempts: number = 100): Promise<number> {
    const endPort = Math.min(startPort + maxAttempts, SPICE_MAX_PORT)

    for (let port = startPort; port <= endPort; port++) {
      if (await this.isPortAvailable(port)) {
        if (port !== startPort) {
          this.debug.log('info', `Display port ${startPort} was in use, allocated port ${port} instead`)
        }
        return port
      }
    }

    throw new LifecycleError(
      LifecycleErrorCode.RESOURCE_UNAVAILABLE,
      `No available display ports in range ${startPort}-${endPort}. All ports are in use.`,
      undefined,
      { startPort, endPort, attemptsChecked: maxAttempts }
    )
  }

  /** Maximum supported network queues */
  private static readonly MAX_NETWORK_QUEUES = 4

  /**
   * Calculates optimal network queue count based on CPU cores.
   * Multi-queue networking improves performance by parallelizing packet processing.
   *
   * @param cpuCores - Number of VM CPU cores
   * @param configuredQueues - Explicitly configured queue count (nullable)
   * @returns Queue count (1-4, where 1 = single queue, >1 = multi-queue with vhost)
   *
   * @remarks
   * **Behavior:**
   * - If `configuredQueues` is explicitly set (non-null), use that value (clamped to 1-4)
   * - Otherwise, auto-calculate as `min(cpuCores, 4)`
   * - Returns 1 for single-core VMs (no multi-queue benefit)
   * - Caps at 4 queues to avoid excessive overhead
   *
   * **Note on OS Presets:**
   * Network queue count is NOT derived from OS driver presets. While presets define
   * recommended queue counts for documentation purposes, this method always uses
   * CPU-based auto-calculation when no explicit value is provided. This ensures
   * optimal queue distribution based on the VM's actual hardware allocation.
   */
  private calculateNetworkQueues (cpuCores: number, configuredQueues: number | null | undefined): number {
    // Explicit configuration takes precedence
    if (configuredQueues !== null && configuredQueues !== undefined) {
      // Warn if configured value exceeds maximum
      if (configuredQueues > VMLifecycle.MAX_NETWORK_QUEUES) {
        this.debug.log('warn', `Configured networkQueues (${configuredQueues}) exceeds maximum (${VMLifecycle.MAX_NETWORK_QUEUES}), clamping to ${VMLifecycle.MAX_NETWORK_QUEUES}`)
      }
      // Clamp to valid range: 1 to MAX_NETWORK_QUEUES
      return Math.max(1, Math.min(configuredQueues, VMLifecycle.MAX_NETWORK_QUEUES))
    }

    // Auto-calculate: min(cpuCores, 4)
    return Math.min(cpuCores, VMLifecycle.MAX_NETWORK_QUEUES)
  }

  /**
   * Validates UEFI firmware path and checks file existence.
   * Returns the validated path or null if firmware should not be used.
   */
  private validateUefiFirmware (firmwarePath: string | null | undefined): string | null {
    if (!firmwarePath) return null

    // Normalize path
    const normalizedPath = path.resolve(firmwarePath)

    // Check if file exists
    if (!fs.existsSync(normalizedPath)) {
      this.debug.log('warn', `UEFI firmware file not found: ${normalizedPath}. Falling back to BIOS boot.`)
      return null
    }

    // Validate it's a readable file
    try {
      fs.accessSync(normalizedPath, fs.constants.R_OK)
    } catch {
      this.debug.log('warn', `UEFI firmware file not readable: ${normalizedPath}. Falling back to BIOS boot.`)
      return null
    }

    return normalizedPath
  }

  /**
   * Validates that hugepages are available on the host system.
   * Checks if /dev/hugepages is mounted as hugetlbfs and accessible.
   *
   * @param enabled - Whether hugepages should be enabled
   * @returns true if hugepages should be used, false otherwise
   *
   * @remarks
   * - Returns false if enabled is false/null/undefined
   * - Checks if /dev/hugepages directory exists
   * - Verifies directory is readable/writable
   * - Verifies /dev/hugepages is actually mounted as hugetlbfs via /proc/mounts
   * - Logs warning and returns false on validation failure (graceful degradation)
   * - Does not throw errors to avoid blocking VM start
   */
  private validateHugepages (enabled: boolean | null | undefined): boolean {
    if (!enabled) return false

    const hugepagesPath = '/dev/hugepages'

    // Check if directory exists
    if (!fs.existsSync(hugepagesPath)) {
      this.debug.log('warn', `Hugepages requested but ${hugepagesPath} does not exist. Ensure hugepages are configured in kernel. Falling back to standard memory.`)
      return false
    }

    // Check if directory is accessible (readable and writable)
    try {
      fs.accessSync(hugepagesPath, fs.constants.R_OK | fs.constants.W_OK)
    } catch {
      this.debug.log('warn', `Hugepages requested but ${hugepagesPath} is not accessible. Check permissions and mount status. Falling back to standard memory.`)
      return false
    }

    // Verify that /dev/hugepages is actually mounted as hugetlbfs
    // by reading /proc/mounts and checking for a matching entry
    try {
      const mounts = fs.readFileSync('/proc/mounts', 'utf8')
      // Each line in /proc/mounts: device mountpoint fstype options dump pass
      // We look for a line where mountpoint is /dev/hugepages and fstype is hugetlbfs
      const isHugetlbfsMounted = mounts.split('\n').some(line => {
        const parts = line.split(/\s+/)
        // parts[1] = mountpoint, parts[2] = filesystem type
        return parts[1] === hugepagesPath && parts[2] === 'hugetlbfs'
      })

      if (!isHugetlbfsMounted) {
        this.debug.log('warn', `Hugepages requested but ${hugepagesPath} is not mounted as hugetlbfs. Run 'mount -t hugetlbfs hugetlbfs ${hugepagesPath}' or add to /etc/fstab. Falling back to standard memory.`)
        return false
      }
    } catch {
      this.debug.log('warn', `Hugepages requested but unable to read /proc/mounts to verify hugetlbfs mount. Falling back to standard memory.`)
      return false
    }

    // Validation passed
    return true
  }

  /**
   * Sets up per-VM UEFI variables file
   *
   * Creates a copy of the OVMF_VARS template file for each VM to store
   * persistent UEFI settings (boot entries, secure boot state, etc.).
   *
   * @param vmId - The VM identifier used for naming the vars file
   * @param firmwarePath - Path to OVMF_CODE firmware (used to find matching OVMF_VARS)
   * @returns Path to the VM-specific vars file, or null if setup failed
   *
   * @remarks
   * Common OVMF_VARS locations:
   * - /usr/share/OVMF/OVMF_VARS.fd (Debian/Ubuntu)
   * - /usr/share/edk2/ovmf/OVMF_VARS.fd (Fedora/RHEL)
   * - /usr/share/OVMF/OVMF_VARS.ms.fd (Microsoft-signed for Secure Boot)
   */
  private setupUefiVars (vmId: string, firmwarePath: string): string | null {
    try {
      // Determine the OVMF_VARS template path based on the OVMF_CODE path
      // E.g., /usr/share/OVMF/OVMF_CODE_4M.fd -> /usr/share/OVMF/OVMF_VARS_4M.fd
      const firmwareDir = path.dirname(firmwarePath)
      const firmwareBasename = path.basename(firmwarePath)

      // Build template paths based on firmware variant (4M or legacy)
      const is4M = firmwareBasename.includes('_4M')
      const varsSuffix = is4M ? '_4M' : ''

      const templatePaths = [
        path.join(firmwareDir, `OVMF_VARS${varsSuffix}.fd`),
        path.join(firmwareDir, `OVMF_VARS${varsSuffix}.ms.fd`),
        `/usr/share/OVMF/OVMF_VARS${varsSuffix}.fd`,
        `/usr/share/edk2/ovmf/OVMF_VARS${varsSuffix}.fd`,
        // Fallback to legacy paths if 4M variant not found
        path.join(firmwareDir, 'OVMF_VARS.fd'),
        '/usr/share/OVMF/OVMF_VARS.fd',
        '/usr/share/edk2/ovmf/OVMF_VARS.fd'
      ]

      // Find the first existing template
      let templatePath: string | null = null
      for (const candidate of templatePaths) {
        if (fs.existsSync(candidate)) {
          templatePath = candidate
          break
        }
      }

      if (!templatePath) {
        this.debug.log('warn', 'UEFI vars template not found. UEFI settings will not persist between reboots.')
        return null
      }

      // Create the per-VM vars file path
      const varsFilename = `uefi-vars-${vmId}.fd`
      const varsPath = path.join(this.diskDir, varsFilename)

      // Copy template if vars file doesn't exist
      if (!fs.existsSync(varsPath)) {
        this.debug.log('info', `Creating UEFI vars file from template: ${templatePath}`)
        fs.copyFileSync(templatePath, varsPath)
        // Ensure the vars file is writable
        fs.chmodSync(varsPath, 0o644)
      }

      return varsPath
    } catch (error) {
      this.debug.log('warn', `Failed to setup UEFI vars file: ${error}. UEFI settings will not persist.`)
      return null
    }
  }

  /**
   * Delivers the display (SPICE/VNC) password to QEMU over QMP after connect,
   * instead of placing it on the command line where it would be visible in `ps`
   * and /proc/<pid>/cmdline to every local user. The display was started with
   * authentication required (ticketing on / password=on); this call provisions
   * the secret. Without it a password-protected console rejects every client.
   *
   * Fail-closed: if the password cannot be set, the launch fails rather than
   * leaving an unreachable or (worse) unintentionally-open console.
   */
  private async applyDisplayPassword (
    qmpClient: QMPClient,
    displayType: string,
    password?: string
  ): Promise<void> {
    if (!password) return
    const protocol = displayType === 'vnc' ? 'vnc' : 'spice'
    try {
      await qmpClient.execute('set_password', { protocol, password, connected: 'keep' })
      this.debug.log('info', `Display password provisioned over QMP (${protocol})`)
    } catch (error) {
      throw new Error(`Failed to set ${protocol} display password via QMP: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  /**
   * Builds QEMU command line
   *
   * @param config - VM creation configuration
   * @param diskPaths - Array of disk image paths
   * @param qmpSocketPath - QMP socket path
   * @param pidFilePath - PID file path
   * @param tapDevice - TAP network device name
   * @param macAddress - VM MAC address
   * @param qemuConfig - Optional QEMU configuration overrides from database
   */
  private buildQemuCommand (
    config: VMCreateConfig,
    diskPaths: string[],
    qmpSocketPath: string,
    pidFilePath: string,
    tapDevice: string,
    macAddress: string,
    qemuConfig?: {
      machineType?: string | null
      cpuModel?: string | null
      diskBus?: string | null
      diskCacheMode?: string | null
      networkModel?: string | null
      networkQueues?: number | null
      memoryBalloon?: boolean | null
      uefiFirmware?: string | null
      hugepages?: boolean | null
      displayPort?: number | null
      tpmSocketPath?: string | null
      guestAgentSocketPath?: string | null
      infiniServiceSocketPath?: string | null
      virtioDriversIso?: string | null
      enableAudio?: boolean | null
      enableUsbTablet?: boolean | null
      enableNumaCtlPinning?: boolean | null
      cpuPinningStrategy?: 'basic' | 'hybrid' | null
      /** Opt out of the seccomp sandbox (default: sandbox enabled). */
      disableSandbox?: boolean | null
      /** Unprivileged user to drop QEMU privileges to via -runas. */
      runAsUser?: string | null
    }
  ): QemuCommandBuilder {
    const builder = new QemuCommandBuilder()

    // Optional host override for the QEMU binary — applied ONLY to infinigpu GPU
    // VMs (config.gpu). GPU VMs need a QEMU built with the upstream vfio-user-pci
    // client (>= 10.1.1); non-GPU VMs deliberately keep the stock
    // `qemu-system-x86_64` so a vfio-user QEMU that is absent or ABI-incompatible
    // with this host/runtime can never break the existing (non-GPU) fleet.
    const qemuBinaryOverride = process.env.INFINIZATION_QEMU_BINARY
    if (config.gpu?.socketPath && qemuBinaryOverride && qemuBinaryOverride.trim() !== '') {
      builder.setBinary(qemuBinaryOverride.trim())
    }

    // Defense-in-depth: enable the QEMU seccomp sandbox by default so a guest that
    // compromises QEMU cannot trivially pivot to the (root) host. Opt-out via
    // qemuConfig.disableSandbox for the rare device that genuinely needs spawn.
    if (qemuConfig?.disableSandbox !== true) {
      builder.enableSeccompSandbox()
    }
    // If an unprivileged QEMU user is configured, drop privileges to it.
    if (qemuConfig?.runAsUser) {
      builder.setRunAs(qemuConfig.runAsUser)
    }

    // Validate and get effective configuration values
    const effectiveMachineType = this.validateMachineType(qemuConfig?.machineType)
    const effectiveCpuModel = qemuConfig?.cpuModel ?? 'host'
    const effectiveDiskBus = this.validateDiskBus(qemuConfig?.diskBus)
    const effectiveDiskCacheMode = this.validateDiskCacheMode(qemuConfig?.diskCacheMode)
    const effectiveNetworkModel = this.validateNetworkModel(qemuConfig?.networkModel)
    const effectiveNetworkQueues = this.calculateNetworkQueues(
      config.cpuCores,
      qemuConfig?.networkQueues
    )

    // Base configuration
    builder
      .enableKvm()
      .setMachine(effectiveMachineType)
      .setRtc('utc')
      .setCpu(effectiveCpuModel, config.cpuCores)
      .setMemory(config.ramGB)

    // Validate diskPaths and disks array lengths match
    if (diskPaths.length !== config.disks.length) {
      throw new LifecycleError(
        LifecycleErrorCode.INVALID_CONFIG,
        `Disk paths count (${diskPaths.length}) does not match disk configs count (${config.disks.length})`,
        config.vmId,
        { diskPathsLength: diskPaths.length, disksLength: config.disks.length }
      )
    }

    // Disks - build DiskOptions array from config and paths
    const diskOptions = config.disks.map((diskConfig, index) => ({
      path: diskPaths[index],
      format: (diskConfig.format ?? DEFAULT_DISK_FORMAT) as 'qcow2' | 'raw',
      bus: (diskConfig.bus ?? effectiveDiskBus) as 'virtio' | 'scsi' | 'ide' | 'sata',
      cache: (diskConfig.cache ?? effectiveDiskCacheMode) as 'writeback' | 'writethrough' | 'none' | 'unsafe',
      discard: diskConfig.discard ?? true
    }))
    builder.addDisks(diskOptions)

    // Network
    builder.addNetwork({
      tapName: tapDevice,
      mac: macAddress,
      model: effectiveNetworkModel,
      queues: effectiveNetworkQueues
    })

    // Memory balloon for dynamic memory management
    if (qemuConfig?.memoryBalloon === true) {
      builder.addMemoryBalloon()
    }

    // UEFI firmware configuration
    const validatedFirmware = this.validateUefiFirmware(qemuConfig?.uefiFirmware)
    if (validatedFirmware) {
      builder.setFirmware(validatedFirmware)
      this.debug.log('info', `UEFI firmware enabled: ${validatedFirmware}`)

      // Create per-VM UEFI vars file for persistent UEFI settings
      const uefiVarsPath = this.setupUefiVars(config.vmId, validatedFirmware)
      if (uefiVarsPath) {
        builder.setUefiVars(uefiVarsPath)
        this.debug.log('info', `UEFI vars file: ${uefiVarsPath}`)
      }
    }
    // If no firmware specified or validation failed, QEMU defaults to BIOS boot

    // Hugepages configuration for improved memory performance
    const shouldUseHugepages = this.validateHugepages(qemuConfig?.hugepages)
    if (shouldUseHugepages) {
      builder.enableHugepages()
      this.debug.log('info', 'Hugepages enabled for VM memory allocation')
    }
    // If hugepages not enabled or validation failed, QEMU uses standard memory allocation

    // Display configuration with optimizations
    // Disable SPICE agent (vdagent) if Guest Agent is configured, as Guest Agent provides
    // superior functionality and both share the virtio-serial controller
    const hasGuestAgent = !!(config.guestAgentSocketPath ?? qemuConfig?.guestAgentSocketPath)
    // Use validated display port from qemuConfig if available, otherwise validate from config
    const effectiveDisplayPort = this.validateDisplayPort(qemuConfig?.displayPort ?? config.displayPort)

    // Secure-by-default display binding.
    const effectiveDisplayAddr = config.displayAddr ?? (config.displayType === 'spice' ? DEFAULT_SPICE_ADDR : DEFAULT_VNC_ADDR)
    const hasDisplayPassword = !!config.displayPassword
    if (hasDisplayPassword) {
      // The password is delivered over QMP (set_password) after connect, never on
      // the QEMU command line. Still validate it so it cannot break QMP/argv.
      assertSafeOptionValue(config.displayPassword as string, 'displayPassword')
    }
    // FAIL-CLOSED: never expose an unauthenticated console off-host. A non-loopback
    // bind with no password would have been an open remote desktop for any host
    // that can route to the hypervisor.
    if (!config.gpu?.socketPath && !isLoopbackAddr(effectiveDisplayAddr) && !hasDisplayPassword) {
      throw new LifecycleError(
        LifecycleErrorCode.INVALID_CONFIG,
        `Refusing to start an unauthenticated ${config.displayType} display on non-loopback address '${effectiveDisplayAddr}'. Set a displayPassword or bind to loopback.`,
        config.vmId
      )
    }

    if (config.gpu?.socketPath) {
      // infinigpu is the guest's SOLE display (addInfinigpuDevice forces -vga none);
      // skip the SPICE/VNC console entirely — the remote display is infiniPixel.
      this.debug.log('infinigpu virtual GPU enabled; skipping SPICE/VNC console device')
    } else if (config.displayType === 'spice') {
      const spiceConfig = new SpiceConfig({
        port: effectiveDisplayPort,
        addr: effectiveDisplayAddr,
        // Password is NEVER placed on the command line (it would leak via ps /
        // /proc/<pid>/cmdline). When a password is configured we require a ticket
        // and set it over QMP after connect; otherwise (loopback-only) we allow
        // ticketing to be disabled so a local console still works.
        password: undefined,
        disableTicketing: !hasDisplayPassword,
        enableAgent: !hasGuestAgent,

        // ===== Performance Optimizations =====
        // Use auto_glz for best compression/performance balance
        imageCompression: 'auto_glz',
        // Auto JPEG compression for WAN scenarios
        jpegWanCompression: 'auto',
        // Auto zlib-glz compression for WAN scenarios
        zlibGlzWanCompression: 'auto',
        // Smart video streaming detection (filter mode)
        streamingVideo: 'filter',
        // Enable playback compression (CELT algorithm)
        playbackCompression: 'on',

        // GL acceleration disabled by default (requires recent QEMU/SPICE)
        // Can be enabled via qemuConfig if needed
        gl: false,

        // Agent features enabled by default
        disableCopyPaste: false,
        disableAgentFileXfer: false,
        seamlessMigration: false
      })

      // Determine QXL memory based on expected resolution
      // Default 16MB for standard resolutions, can be overridden via config
      const qxlMemoryMB = 16

      builder.addSpice(spiceConfig, qxlMemoryMB)
      this.debug.log(`SPICE display configured with optimizations: compression=auto_glz, streaming=filter, qxl_mem=${qxlMemoryMB}MB`)
    } else {
      // VncConfig expects a DISPLAY NUMBER (0-99), not a TCP port. effectiveDisplay
      // Port is a real port (5900-65535); convert it. Previously the raw port was
      // passed straight through and VncConfig rejected it (>99) — so VNC could
      // never launch a single VM.
      const vncDisplayNumber = effectiveDisplayPort - VNC_BASE_PORT
      if (vncDisplayNumber < 0 || vncDisplayNumber > 99) {
        throw new LifecycleError(
          LifecycleErrorCode.INVALID_CONFIG,
          `VNC display port ${effectiveDisplayPort} maps to display number ${vncDisplayNumber}, outside the valid 0-99 range`,
          config.vmId
        )
      }
      const vncConfig = new VncConfig({
        display: vncDisplayNumber,
        addr: effectiveDisplayAddr,
        // password=on tells QEMU to require auth; the secret itself is delivered
        // over QMP (set_password) after connect — see applyDisplayPassword().
        password: hasDisplayPassword
      })
      builder.addVnc(vncConfig)
    }

    // QMP socket
    builder.addQmp(qmpSocketPath)

    // ISO if provided
    if (config.isoPath) {
      builder.addCdrom(config.isoPath)
      // Boot the CD ONCE, then the disk on every subsequent (guest-initiated)
      // reboot. A plain order=dc re-enters the installer after it finishes and
      // reboots — a boot/install loop. See setBootOrder / mountInstallationMedia.
      builder.setBootOrder(['c'], { once: 'd' })
    } else {
      builder.setBootOrder(['c']) // Disk only
    }

    // GPU passthrough if configured
    if (config.gpuPciAddress) {
      // Validate ROM file path early to provide clear error message
      if (config.gpuRomfile) {
        const ALLOWED_ROM_DIR = '/var/lib/infinization/roms/'
        const normalizedRomPath = path.resolve(config.gpuRomfile)
        if (!normalizedRomPath.startsWith(ALLOWED_ROM_DIR)) {
          throw new LifecycleError(
            LifecycleErrorCode.INVALID_CONFIG,
            `GPU ROM file must be located in ${ALLOWED_ROM_DIR}. ` +
            `Configured path '${config.gpuRomfile}' resolves to '${normalizedRomPath}' which is outside the allowed directory.`
          )
        }
      }
      builder.addGpuPassthrough(config.gpuPciAddress, config.gpuRomfile)
    }

    // infinigpu virtual GPU (opt-in). Becomes the guest's SOLE display device —
    // addInfinigpuDevice forces -vga none — so the SPICE/VNC console above is
    // skipped when this is set. The socket is served by the per-VM
    // InfinigpuDeviceServer the facade started before QEMU connects.
    if (config.gpu?.socketPath) {
      builder.addInfinigpuDevice({
        socketPath: config.gpu.socketPath,
        guestRamBytes: config.ramGB * 1024 ** 3
      })
      this.debug.log(`infinigpu virtual GPU attached (socket ${config.gpu.socketPath})`)
    }

    // ===========================================================================
    // Advanced Device Configuration
    // ===========================================================================

    // TPM 2.0 device (required for Windows 11)
    const tpmSocketPath = config.tpmSocketPath ?? qemuConfig?.tpmSocketPath
    if (tpmSocketPath) {
      if (fs.existsSync(tpmSocketPath) || this.isSocketListening(tpmSocketPath)) {
        builder.addTPM(tpmSocketPath)
        this.debug.log('info', `TPM 2.0 enabled via socket: ${tpmSocketPath}`)
      } else {
        this.debug.log('warn', `TPM socket not found: ${tpmSocketPath}. TPM will not be available.`)
      }
    }

    // QEMU Guest Agent channel
    const guestAgentSocketPath = config.guestAgentSocketPath ?? qemuConfig?.guestAgentSocketPath
    if (guestAgentSocketPath) {
      builder.addGuestAgentChannel(guestAgentSocketPath)
      this.debug.log('info', `Guest Agent channel enabled: ${guestAgentSocketPath}`)
    }

    // InfiniService custom channel
    const infiniServiceSocketPath = config.infiniServiceSocketPath ?? qemuConfig?.infiniServiceSocketPath
    if (infiniServiceSocketPath) {
      builder.addInfiniServiceChannel(infiniServiceSocketPath)
      this.debug.log('info', `InfiniService channel enabled: ${infiniServiceSocketPath}`)
    }

    // VirtIO drivers ISO (secondary CD-ROM for Windows)
    const virtioDriversIso = config.virtioDriversIso ?? qemuConfig?.virtioDriversIso
    if (virtioDriversIso) {
      if (fs.existsSync(virtioDriversIso)) {
        builder.addSecondCdrom(virtioDriversIso)
        this.debug.log('info', `VirtIO drivers ISO mounted: ${virtioDriversIso}`)
      } else {
        this.debug.log('warn', `VirtIO drivers ISO not found: ${virtioDriversIso}`)
      }
    }

    // Audio device (Intel HDA)
    const enableAudio = config.enableAudio ?? qemuConfig?.enableAudio ?? false
    if (enableAudio) {
      builder.addAudioDevice()
      this.debug.log('info', 'Intel HDA audio device enabled')
    }

    // USB tablet for absolute mouse positioning
    // Default to true for Windows VMs
    const isWindowsOS = config.os.toLowerCase().includes('windows')
    const enableUsbTablet = config.enableUsbTablet ?? qemuConfig?.enableUsbTablet ?? isWindowsOS
    if (enableUsbTablet) {
      builder.addUsbTablet()
      this.debug.log('info', 'USB tablet device enabled for absolute mouse positioning')
    }

    // ===========================================================================
    // CPU Pinning (numactl wrapper)
    // ===========================================================================

    // Enable NUMA-aware CPU pinning if configured
    // This wraps the QEMU process with numactl for CPU affinity and memory binding
    const enableNumaCtlPinning = config.enableNumaCtlPinning ?? qemuConfig?.enableNumaCtlPinning ?? false
    if (enableNumaCtlPinning) {
      const pinningStrategy = config.cpuPinningStrategy ?? qemuConfig?.cpuPinningStrategy ?? 'basic'
      builder.enableCpuPinning(pinningStrategy, config.cpuCores)
      this.debug.log(`NUMA-aware CPU pinning enabled: strategy=${pinningStrategy}, vCPUs=${config.cpuCores}`)
    }

    // Process options
    builder.setProcessOptions({
      vmId: config.internalName,
      name: config.name,
      uuid: config.uuid,
      daemonize: true,
      pidfile: pidFilePath
    })

    return builder
  }

  /**
   * Waits for a socket file to appear
   */
  private async waitForSocket (socketPath: string, timeout: number = 5000): Promise<void> {
    const startTime = Date.now()
    const pollInterval = 100

    while (Date.now() - startTime < timeout) {
      if (fs.existsSync(socketPath)) {
        return
      }
      await this.sleep(pollInterval)
    }

    throw new LifecycleError(
      LifecycleErrorCode.TIMEOUT,
      `Socket not available after ${timeout}ms: ${socketPath}`
    )
  }

  /**
   * Waits for a process to exit
   */
  private async waitForProcessExit (pid: number, timeout: number): Promise<boolean> {
    return sharedWaitForProcessExit(pid, timeout, PROCESS_EXIT_POLL_INTERVAL)
  }

  /**
   * Recover a still-running VM's QEMU PID from its on-disk pidfile when the DB copy
   * (qemuPid) was lost — e.g. a backend restart between the QEMU spawn and the
   * qemuPid persist, a crash, or a manual DB edit. Reads {pidfileDir}/{internalName}.pid
   * and adopts the PID ONLY if it is alive AND /proc confirms it is this VM's
   * qemu-system (internalName token), mirroring the daemonized-adopt guard used at
   * start(). Fails SAFE: a missing/unparseable pidfile, a dead PID, or a
   * recycled/foreign PID all return null, so the caller treats the VM as stopped
   * rather than signalling an unrelated process.
   */
  private recoverStalePidFromPidfile (internalName: string): number | null {
    const pidFilePath = path.join(this.pidfileDir, `${internalName}.pid`)
    let content: string
    try {
      content = fs.readFileSync(pidFilePath, 'utf8').trim()
    } catch {
      // No pidfile on disk → the VM is genuinely stopped. Correct no-op.
      return null
    }
    const pid = parseInt(content, 10)
    if (isNaN(pid) || pid <= 0) {
      this.debug.log('warn', `Pidfile ${pidFilePath} did not contain a valid PID ("${content}") — not recovering`)
      return null
    }
    if (!this.isProcessAlive(pid)) {
      // Stale pidfile pointing at a dead PID — nothing to stop.
      return null
    }
    // Fail-closed identity guard: only adopt a live PID whose /proc cmdline is this
    // VM's qemu-system. A recycled PID (now an unrelated host process) or a different
    // VM's QEMU is rejected — we must never signal it.
    if (!this.pidBelongsToVM(pid, internalName)) {
      this.debug.log('warn', `Pidfile ${pidFilePath} PID ${pid} is alive but not confirmed to be this VM's QEMU — not recovering (PID-reuse guard)`)
      return null
    }
    return pid
  }

  /**
   * Checks if a process is alive (delegates to the shared zombie-aware,
   * EPERM=>alive implementation so liveness is identical everywhere).
   */
  private isProcessAlive (pid: number): boolean {
    return sharedIsProcessAlive(pid)
  }

  /**
   * Checks if a socket file exists and is likely a valid socket
   * (useful for checking if swtpm has created a TPM socket)
   */
  private isSocketListening (socketPath: string): boolean {
    try {
      const stats = fs.statSync(socketPath)
      return stats.isSocket()
    } catch {
      return false
    }
  }

  /**
   * Verifies that the live process at `pid` is actually this VM's QEMU process
   * before we send it a destructive signal. Guards against PID reuse: a stale
   * PID read from the DB may now belong to an unrelated host process.
   *
   * Identification: the QEMU cmdline always contains `qemu-system` plus a token
   * unique to this VM — its internalName, which is embedded in both the -qmp
   * socket path and the -pidfile path on the command line.
   *
   * Linux-only (reads /proc). On other platforms /proc is unavailable so we
   * cannot verify and conservatively return true to preserve existing behavior.
   * If the process is already gone (ENOENT) we return false so the caller skips
   * the kill. Any other read error also returns false (fail closed: never
   * SIGKILL a PID we could not positively identify).
   */
  private pidBelongsToVM (pid: number, token: string): boolean {
    // Delegates to the single shared implementation (see utils/processIdentity)
    // so identity semantics are identical across VMLifecycle, HealthMonitor and
    // EventHandler.
    return sharedPidBelongsToVM(pid, token)
  }

  /**
   * Force kills a process, but only after verifying (on Linux) that the PID
   * still belongs to this VM's QEMU. This prevents SIGKILL-ing an unrelated
   * host process when the DB-recorded PID has been reused.
   *
   * @param pid - The PID to kill
   * @param token - VM identifying token (internalName) expected in the QEMU cmdline
   * @returns true if a kill was actually attempted, false if it was skipped
   */
  private async forceKillProcess (pid: number, token: string): Promise<boolean> {
    // Delegates to the shared identity-checked SIGTERM->SIGKILL escalation.
    // Returns whether a signal was actually sent (identity verified), preserving
    // this method's prior boolean contract for existing callers.
    const result = await sharedForceKillProcess(pid, token)
    if (result.skipped) {
      this.debug.log('warn', `Skipping force kill of PID ${pid}: not confirmed to be this VM's QEMU process (token='${token}')`)
    } else if (!result.confirmedGone) {
      this.debug.log('warn', `Force kill of PID ${pid} did not confirm exit`)
    }
    return result.signalled
  }

  /**
   * Cleans up resources on failure.
   *
   * The cleanup sequence is carefully ordered to handle "Device or resource busy" errors:
   *
   * 1. Disconnect QMP client (stops VM control communication)
   * 2. Force kill QEMU process (releases VM resources)
   * 3. Wait 500ms for QEMU to fully release network/device resources
   * 4. Bring down TAP device (deactivates network interface)
   * 5. Wait 200ms for kernel to process interface state change
   * 6. Remove firewall chain (must happen BEFORE TAP deletion to avoid busy errors)
   * 7. Wait 200ms for nftables to release TAP device references
   * 8. Destroy TAP device (can now be deleted safely)
   * 9. Clear DB configuration and update status
   * 10. Remove socket files and temporary files
   *
   * Key insight: nftables chains reference TAP devices by name (iifname/oifname).
   * If we try to delete the TAP device while nftables still has active rules
   * referencing it, the kernel returns "Device or resource busy".
   */
  private async cleanup (resources: CleanupResources): Promise<void> {
    this.debug.log('Cleaning up resources after failure')

    // Step 1: Disconnect QMP client
    if (resources.qmpClient) {
      try {
        this.debug.log('Disconnecting QMP client')
        await (resources.qmpClient as QMPClient).disconnect()
        this.debug.log('QMP client disconnected')
      } catch (error) {
        this.debug.log('warn', `Failed to disconnect QMP client: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Step 2: Force kill QEMU process.
    if (resources.qemuProcess) {
      try {
        this.debug.log('Force killing QEMU process')
        await (resources.qemuProcess as QemuProcess).forceKill()
        this.debug.log('QEMU process killed')
      } catch (error) {
        this.debug.log('warn', `Failed to kill QEMU process: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Step 2b: BACKSTOP for the daemonized case. On a failed create, the daemon
    // PID may never have been adopted by the QemuProcess object (it is read in
    // completeStart, which only runs on QMP success), so forceKill() above can
    // target the already-exited fork PID and leave a live qemu-system holding the
    // TAP + display port. Read the real daemon PID from the pidfile and kill it
    // with /proc identity verification (never SIGKILL a recycled PID).
    if (resources.pidFilePath && resources.internalName) {
      try {
        let pidContent: string | null = null
        try {
          pidContent = fs.readFileSync(resources.pidFilePath, 'utf8').trim()
        } catch { /* pidfile already gone — nothing to reap */ }
        const daemonPid = pidContent ? parseInt(pidContent, 10) : NaN
        if (!isNaN(daemonPid) && daemonPid > 0) {
          const result = await sharedForceKillProcess(daemonPid, resources.internalName)
          if (result.signalled && result.confirmedGone) {
            this.debug.log(`Cleanup: reaped daemonized QEMU PID ${daemonPid} via pidfile`)
          } else if (result.skipped) {
            this.debug.log('info', `Cleanup: pidfile PID ${daemonPid} is not this VM's QEMU (already gone / recycled) — not signalled`)
          }
        }
      } catch (error) {
        this.debug.log('warn', `Cleanup: failed to reap daemon PID from pidfile: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Step 3: Wait for QEMU to fully release resources
    // QEMU may still be cleaning up network devices, virtio queues, etc.
    this.debug.log('Waiting 500ms for QEMU resource release')
    await sleep(500)

    // Step 4: Bring down TAP device (if exists)
    // This deactivates the interface before we try to remove firewall rules
    if (resources.tapDevice) {
      try {
        this.debug.log(`Bringing down TAP device: ${resources.tapDevice}`)
        await this.tapManager.bringDown(resources.tapDevice)
        this.debug.log(`TAP device ${resources.tapDevice} is down`)
      } catch (error) {
        this.debug.log('warn', `Failed to bring down TAP device: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Step 5: Wait for kernel to process interface state change
    this.debug.log('Waiting 200ms for interface state change')
    await sleep(200)

    // Step 6: Remove firewall chain BEFORE destroying TAP device
    // This is critical: nftables rules reference the TAP device name.
    // If we delete the TAP first, nftables may have stale references that
    // cause "Device or resource busy" errors on the chain deletion.
    // By removing the chain first, we ensure no firewall rules reference the TAP.
    if (resources.vmId) {
      try {
        this.debug.log(`Removing firewall chain for VM: ${resources.vmId}`)
        await this.nftables.removeVMChain(resources.vmId)
        this.debug.log(`Firewall chain removed for VM: ${resources.vmId}`)
      } catch (error) {
        this.debug.log('warn', `Failed to remove firewall chain: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Step 7: Wait for nftables to release TAP device references
    this.debug.log('Waiting 200ms for nftables resource release')
    await sleep(200)

    // Step 8: Destroy TAP device (now safe to delete) — but NEVER destroy a
    // persistent TAP that start() merely reused. Destroying it would break the
    // stop/start persistence invariant and force a recreate on the next start.
    if (resources.tapDevice && !resources.tapWasReused) {
      try {
        this.debug.log(`Destroying TAP device: ${resources.tapDevice}`)
        await this.tapManager.destroy(resources.tapDevice)
        this.debug.log(`TAP device ${resources.tapDevice} destroyed`)
      } catch (error) {
        this.debug.log('warn', `Failed to destroy TAP device: ${error instanceof Error ? error.message : String(error)}`)
      }
    } else if (resources.tapWasReused) {
      this.debug.log(`Preserving reused persistent TAP device: ${resources.tapDevice}`)
    }

    // Step 9: Clear DB configuration.
    // For a START failure, prefer a RECOVERABLE outcome: keep the persistent
    // config (tapDeviceName etc.) by clearing only volatile runtime fields, and
    // reset the row to 'off' (re-startable) instead of 'error' (a soft/transient
    // start failure must not strand an otherwise-healthy VM). For a CREATE
    // failure the row was never a valid VM, so wipe it and mark 'error'.
    if (resources.vmId) {
      try {
        if (resources.origin === 'start') {
          this.debug.log(`Resetting VM ${resources.vmId} to recoverable 'off' after start failure (config preserved)`)
          await this.prisma.clearVolatileMachineConfiguration(resources.vmId)
          await this.prisma.updateMachineStatus(resources.vmId, 'off')
        } else {
          this.debug.log(`Clearing DB configuration for VM: ${resources.vmId}`)
          await this.prisma.clearMachineConfiguration(resources.vmId)
          await this.prisma.updateMachineStatus(resources.vmId, 'error')
        }
        this.debug.log(`DB configuration finalized for VM: ${resources.vmId}`)
      } catch (error) {
        this.debug.log('warn', `Failed to finalize DB configuration: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Step 10: Remove socket files
    if (resources.qmpSocketPath && fs.existsSync(resources.qmpSocketPath)) {
      try {
        fs.unlinkSync(resources.qmpSocketPath)
        this.debug.log(`Removed QMP socket: ${resources.qmpSocketPath}`)
      } catch (error) {
        this.debug.log('warn', `Failed to remove QMP socket: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Remove guest agent socket
    if (resources.guestAgentSocketPath && fs.existsSync(resources.guestAgentSocketPath)) {
      try {
        fs.unlinkSync(resources.guestAgentSocketPath)
        this.debug.log(`Removed guest agent socket: ${resources.guestAgentSocketPath}`)
      } catch (error) {
        this.debug.log('warn', `Failed to remove guest agent socket: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Remove infini service socket
    if (resources.infiniServiceSocketPath && fs.existsSync(resources.infiniServiceSocketPath)) {
      try {
        fs.unlinkSync(resources.infiniServiceSocketPath)
        this.debug.log(`Removed infini service socket: ${resources.infiniServiceSocketPath}`)
      } catch (error) {
        this.debug.log('warn', `Failed to remove infini service socket: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Remove PID file
    if (resources.pidFilePath && fs.existsSync(resources.pidFilePath)) {
      try {
        fs.unlinkSync(resources.pidFilePath)
        this.debug.log(`Removed PID file: ${resources.pidFilePath}`)
      } catch (error) {
        this.debug.log('warn', `Failed to remove PID file: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Remove installation ISO (temporary file)
    if (resources.installationIsoPath && fs.existsSync(resources.installationIsoPath)) {
      try {
        fs.unlinkSync(resources.installationIsoPath)
        this.debug.log(`Cleaned up installation ISO: ${resources.installationIsoPath}`)
      } catch (error) {
        this.debug.log('warn', `Failed to remove installation ISO: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    // Note: We don't delete the disk image on failure as it might contain user data
    // The disk cleanup is left to explicit user action

    this.debug.log('Cleanup completed')
  }

  /**
   * Emits an event to the backend EventManager
   */
  private emitEvent (resource: string, action: string, id: string, data?: unknown): void {
    if (this.eventManager?.emitCRUD) {
      try {
        this.eventManager.emitCRUD(resource, action, id, data)
      } catch {
        // Ignore event emission errors
      }
    }
  }

  /**
   * Wraps an error in a LifecycleError
   */
  private wrapError (error: unknown, code: LifecycleErrorCode, vmId?: string): LifecycleError {
    if (error instanceof LifecycleError) {
      return error
    }

    const message = error instanceof Error ? error.message : String(error)
    return new LifecycleError(code, message, vmId)
  }

  /**
   * Sleep utility
   */
  private sleep (ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  /**
   * Verifies that QEMU successfully connected to the TAP device.
   * Checks carrier state with retries to allow time for QEMU to attach.
   *
   * When QEMU starts with a TAP device, it should open the TAP file descriptor
   * which brings the carrier up. If the TAP remains in NO-CARRIER state,
   * it indicates QEMU failed to connect (permissions issue, config mismatch, etc.).
   *
   * @param tapDevice - TAP device name to verify
   * @param vmId - VM identifier for error context
   * @param pid - QEMU process PID for diagnostics
   * @param bridge - Bridge name for diagnostics
   * @throws LifecycleError if TAP has no carrier after timeout
   */
  private async verifyTapConnection (
    tapDevice: string,
    vmId: string,
    pid: number,
    bridge: string
  ): Promise<void> {
    const MAX_RETRIES = 10
    const RETRY_DELAY_MS = 500 // Total timeout: 5 seconds

    this.debug.log(`Verifying TAP device connection for ${tapDevice} (VM: ${vmId})`)

    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      const hasCarrier = await this.tapManager.hasCarrier(tapDevice)

      if (hasCarrier) {
        this.debug.log(`TAP device ${tapDevice} has carrier - QEMU connected successfully (attempt ${attempt}/${MAX_RETRIES})`)
        return
      }

      if (attempt < MAX_RETRIES) {
        this.debug.log(`TAP device ${tapDevice} has no carrier yet, retrying in ${RETRY_DELAY_MS}ms (attempt ${attempt}/${MAX_RETRIES})`)
        await this.sleep(RETRY_DELAY_MS)
      }
    }

    // Verification failed - collect diagnostic information
    this.debug.log('error', `TAP device ${tapDevice} has no carrier after ${MAX_RETRIES} retries`)

    // Get TAP device state for diagnostics
    const tapState = await this.tapManager.getDeviceState(tapDevice)

    // Get bridge state for diagnostics (reuse tapManager.getDeviceState which uses safe command execution)
    const bridgeState = await this.tapManager.getDeviceState(bridge)

    // Check if QEMU process is still alive
    const processAlive = this.isProcessAlive(pid)

    const errorMessage = [
      `QEMU failed to connect to TAP device ${tapDevice}.`,
      'The TAP device has no carrier, indicating QEMU did not attach to it.',
      'This may be caused by:',
      '  (1) QEMU permissions issue accessing /dev/net/tun',
      '  (2) TAP device configuration error',
      '  (3) QEMU network configuration mismatch',
      '',
      `Diagnostics:`,
      `  - TAP Device: ${tapDevice}`,
      `  - Bridge: ${bridge}`,
      `  - QEMU PID: ${pid}`,
      `  - Process Alive: ${processAlive}`,
      `  - TAP State: ${tapState}`,
      `  - Bridge State: ${bridgeState}`
    ].join('\n')

    throw new LifecycleError(
      LifecycleErrorCode.NETWORK_ERROR,
      errorMessage,
      vmId
    )
  }
}
