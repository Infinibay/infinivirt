import { ChildProcess, spawn } from 'child_process'
import fs from 'fs'
import { assertSafePath } from '../utils/qemuArgSafety'

/**
 * Options for one {@link InfinigpuDeviceServer}.
 */
export interface InfinigpuDeviceServerOptions {
  /**
   * Path to the `infinigpu-device` binary (built from the infinigpu repo, placed like the
   * infiniservice binaries). Defaults to `$INFINIGPU_DEVICE_BIN` or `infinigpu-device` on PATH.
   */
  binaryPath?: string
  /** UNIX socket the server listens on; QEMU connects here at boot. MUST match the path
   *  passed to {@link QemuCommandBuilder.addInfinigpuDevice}. */
  socketPath: string
  /** VM id, forwarded to the server for logging / attribution. */
  vmId: string
  /** infiniPixel WebSocket port for this VM's remote-display stream; omit to disable streaming. */
  pixelPort?: number
  /** Extra environment (broker policy, etc.) merged over the inherited env. */
  env?: Record<string, string>
  /** Optional log sink (level, message); defaults to console. */
  log?: (level: 'info' | 'warn' | 'error', message: string) => void
}

/**
 * Manages the lifetime of one **`infinigpu-device`** vfio-user server process — one per GPU
 * VM. It is spawned **before** QEMU (QEMU connects to its socket at boot) and reaped on VM
 * stop, mirroring the QEMU / SPICE-proxy lifecycle. On stop the server drops its broker
 * admission ticket (freeing the VRAM commit + concurrency slot) and exits.
 *
 * **Opt-in and inert:** only instantiated for a VM whose department has GPU enabled — VMs
 * without GPU never construct one, so existing behavior is unchanged. See the infinigpu
 * repo's `docs/INTEGRATION.md` §2.
 */
export class InfinigpuDeviceServer {
  private process: ChildProcess | null = null
  private readonly binary: string
  private readonly socketPath: string
  private readonly vmId: string
  private readonly pixelPort?: number
  private readonly extraEnv: Record<string, string>
  private readonly log: (level: 'info' | 'warn' | 'error', message: string) => void
  private stopped = false

  constructor (options: InfinigpuDeviceServerOptions) {
    this.binary = options.binaryPath ?? process.env.INFINIGPU_DEVICE_BIN ?? 'infinigpu-device'
    // Reject a socket path that could splice arg/shell metacharacters (defence in depth —
    // spawn() takes an argv, but the socket is also handed to QEMU as a device sub-option).
    this.socketPath = assertSafePath(options.socketPath, 'infinigpuSocketPath')
    this.vmId = options.vmId
    this.pixelPort = options.pixelPort
    this.extraEnv = options.env ?? {}
    this.log = options.log ?? ((level, message) => {
      const line = `[infinigpu-device ${this.vmId}] ${message}`
      if (level === 'error') console.error(line)
      else if (level === 'warn') console.warn(line)
      else console.log(line)
    })
  }

  get pid (): number | null {
    return this.process?.pid ?? null
  }

  get running (): boolean {
    return this.process !== null && this.process.exitCode === null && !this.stopped
  }

  /** The argv the server is spawned with (exposed for logging / tests). */
  buildArgs (): string[] {
    return ['--socket', this.socketPath, '--vm-id', this.vmId]
  }

  /** The child environment. `INFINIGPU_PIXEL_PORT` enables this VM's infiniPixel stream. */
  buildEnv (): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env, ...this.extraEnv }
    if (this.pixelPort !== undefined) {
      env.INFINIGPU_PIXEL_PORT = String(this.pixelPort)
    }
    return env
  }

  /**
   * Spawn the device server and resolve once its socket is accepting (QEMU needs it to
   * exist before it connects). Rejects on early process exit, spawn error, or timeout.
   */
  async start (timeoutMs = 5000): Promise<void> {
    if (this.process) {
      throw new Error(`infinigpu-device for VM ${this.vmId} already started`)
    }
    // A stale socket from a prior run would make the server refuse to bind.
    try {
      fs.rmSync(this.socketPath, { force: true })
    } catch {
      /* best effort */
    }

    const child = spawn(this.binary, this.buildArgs(), {
      detached: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: this.buildEnv()
    })
    this.process = child
    this.stopped = false

    child.stdout?.on('data', (d) => this.log('info', d.toString().trimEnd()))
    child.stderr?.on('data', (d) => this.log('info', d.toString().trimEnd()))

    return await new Promise<void>((resolve, reject) => {
      let settled = false
      const finish = (fn: () => void) => {
        if (settled) return
        settled = true
        clearInterval(poll)
        clearTimeout(timer)
        fn()
      }

      child.once('error', (err) => {
        this.process = null
        finish(() => reject(new Error(`infinigpu-device failed to spawn (${this.binary}): ${err.message}`)))
      })
      child.once('exit', (code, signal) => {
        // Early exit before the socket appeared → startup failure.
        finish(() => {
          this.process = null
          reject(new Error(`infinigpu-device for VM ${this.vmId} exited during startup (code ${code}, signal ${signal})`))
        })
      })

      const poll = setInterval(() => {
        if (fs.existsSync(this.socketPath)) {
          this.log('info', `serving on ${this.socketPath} (pid ${child.pid})`)
          finish(resolve)
        }
      }, 100)
      const timer = setTimeout(() => {
        finish(() => reject(new Error(`infinigpu-device for VM ${this.vmId} did not create ${this.socketPath} within ${timeoutMs}ms`)))
      }, timeoutMs)
    })
  }

  /**
   * Gracefully stop the server (SIGTERM → wait → SIGKILL). The server drops its admission
   * ticket on exit. Safe to call more than once / when never started.
   */
  async stop (timeoutMs = 5000): Promise<void> {
    const child = this.process
    if (!child || this.stopped) {
      this.stopped = true
      return
    }
    this.stopped = true

    await new Promise<void>((resolve) => {
      let done = false
      const finish = () => {
        if (done) return
        done = true
        clearTimeout(killTimer)
        this.process = null
        resolve()
      }
      child.once('exit', finish)
      try {
        child.kill('SIGTERM')
      } catch {
        finish()
        return
      }
      const killTimer = setTimeout(() => {
        this.log('warn', 'did not exit on SIGTERM; sending SIGKILL')
        try {
          child.kill('SIGKILL')
        } catch {
          /* already gone */
        }
      }, timeoutMs)
    })

    // Clean up the socket so a later VM re-using the path can bind.
    try {
      fs.rmSync(this.socketPath, { force: true })
    } catch {
      /* best effort */
    }
  }
}
