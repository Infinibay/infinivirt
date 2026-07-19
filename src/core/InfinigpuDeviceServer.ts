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

/** On-disk sidecar written next to the socket so a RESTARTED backend can re-adopt a still-running
 *  device server (see {@link InfinigpuDeviceServer.adopt}). QEMU is `-daemonize`d and the device is
 *  spawned detached, so both survive a backend restart; this file is the only thing the new backend
 *  needs to find the survivor. */
interface InfinigpuDeviceMeta {
  pid: number
  vmId: string
  socketPath: string
  pixelPort?: number
}

/**
 * Manages the lifetime of one **`infinigpu-device`** vfio-user server process — one per GPU
 * VM. It is spawned **before** QEMU (QEMU connects to its socket at boot) and reaped on VM
 * stop, mirroring the QEMU / SPICE-proxy lifecycle. On stop the server drops its broker
 * admission ticket (freeing the VRAM commit + concurrency slot) and exits.
 *
 * **Survives a backend restart.** QEMU is `-daemonize`d (parented to init) and, because vfio-user's
 * `SocketAddress` has no `reconnect=`, QEMU can NEVER reconnect to a fresh device server — so if the
 * device died on restart, the guest's GPU would be gone until a full VM power-cycle. To avoid that we
 * spawn the device **detached** (its own session) with stdio to a **log file** (not a pipe to the
 * backend — a broken pipe would `panic!` the Rust `println!`/`env_logger` and kill it), and drop a
 * {@link InfinigpuDeviceMeta} sidecar. A restarted backend calls {@link InfinigpuDeviceServer.adopt}
 * to re-take ownership of the survivor (reap-by-pid) instead of orphaning it.
 *
 * **Opt-in and inert:** only instantiated for a VM whose department has GPU enabled — VMs
 * without GPU never construct one, so existing behavior is unchanged. See the infinigpu
 * repo's `docs/INTEGRATION.md` §2.
 */
export class InfinigpuDeviceServer {
  private process: ChildProcess | null = null
  /** Set instead of {@link process} when this instance was re-adopted (see {@link adopt}) from a
   *  device that a PRIOR backend spawned — we have its pid but not a ChildProcess handle. */
  private adoptedPid: number | null = null
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

  /** Sidecar path — the survivor record a restarted backend re-adopts from. */
  private get metaPath (): string {
    return `${this.socketPath}.meta`
  }

  /** Device stdout/stderr go here (a file, never a pipe to the backend — see the class doc). */
  private get logPath (): string {
    return `${this.socketPath}.log`
  }

  get pid (): number | null {
    return this.process?.pid ?? this.adoptedPid
  }

  get running (): boolean {
    if (this.stopped) return false
    if (this.process) return this.process.exitCode === null
    if (this.adoptedPid != null) return isPidAlive(this.adoptedPid)
    return false
  }

  /** The argv the server is spawned with (exposed for logging / tests). */
  buildArgs (): string[] {
    return ['--socket', this.socketPath, '--vm-id', this.vmId]
  }

  /**
   * Resolve the actual launch command. Fix E (opt-in, env INFINIGPU_NUMA_NODE=<node>): wrap the
   * device server in `numactl --cpunodebind=<node> --membind=<node>` so its CPU + memory (the
   * Vulkan replay + the mmap'd guest memfd it touches every submit) stay local to the GPU's NUMA
   * node on a multi-socket host. `numactl` exec's the target, so the tracked pid is still the
   * device. Unset (or an invalid value) → spawn the binary directly, unchanged. Requires `numactl`
   * on PATH when enabled.
   */
  private launchTarget (): { cmd: string, args: string[] } {
    const raw = process.env.INFINIGPU_NUMA_NODE
    if (raw !== undefined && /^\d+$/.test(raw.trim())) {
      const node = raw.trim()
      return {
        cmd: 'numactl',
        args: [`--cpunodebind=${node}`, `--membind=${node}`, '--', this.binary, ...this.buildArgs()]
      }
    }
    return { cmd: this.binary, args: this.buildArgs() }
  }

  /** The child environment. `INFINIGPU_PIXEL_PORT` enables this VM's infiniPixel stream. */
  buildEnv (): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = { ...process.env, ...this.extraEnv }
    if (this.pixelPort !== undefined) {
      env.INFINIGPU_PIXEL_PORT = String(this.pixelPort)
    }
    // Advertise the off-primary cursor plane (CAP_CURSOR_PLANE) by default so the guest
    // builds a DRM cursor plane and emits CURSOR_UPDATE sidebands instead of baking the
    // pointer into the primary scanout. Baked-in cursors leak stale sprites through the
    // damage-forwarding path — a cursor *trail* on the viewer — because the "restore the
    // pixels under the old pointer" damage is not reliably captured. With the plane on, the
    // device forwards the sprite/position to the viewer, which draws the cursor client-side
    // (also killing cursor lag). The guest self-gates (kernel >= 6.6 + reads the cap), so an
    // older guest simply ignores it and keeps the SW cursor. The device only checks the var's
    // presence, so translate an explicit falsey value into *unsetting* it (opt-out switch).
    const cur = process.env.INFINIGPU_CURSOR_PLANE
    if (cur !== undefined && /^(0|false|off|no)$/i.test(cur)) {
      delete env.INFINIGPU_CURSOR_PLANE
    } else {
      env.INFINIGPU_CURSOR_PLANE = '1'
    }
    return env
  }

  /**
   * Re-adopt a device server that a PRIOR backend spawned and that is still running (its
   * {@link InfinigpuDeviceMeta} sidecar exists and the pid is alive). Returns an instance that
   * owns the survivor by pid — no new process is spawned, the guest's GPU keeps rendering
   * uninterrupted. Returns `null` if there is no sidecar or the recorded pid is dead (the
   * device is truly gone and cannot be transparently restored — the VM needs a power-cycle).
   */
  static adopt (
    socketPath: string,
    log?: (level: 'info' | 'warn' | 'error', message: string) => void
  ): InfinigpuDeviceServer | null {
    const metaPath = `${assertSafePath(socketPath, 'infinigpuSocketPath')}.meta`
    let meta: InfinigpuDeviceMeta
    try {
      meta = JSON.parse(fs.readFileSync(metaPath, 'utf8')) as InfinigpuDeviceMeta
    } catch {
      return null // no sidecar → nothing to adopt
    }
    if (!meta || typeof meta.pid !== 'number' || !isPidAlive(meta.pid)) {
      // Stale sidecar for a dead device — clean it up so it doesn't mislead a later reconcile.
      try { fs.rmSync(metaPath, { force: true }) } catch { /* best effort */ }
      return null
    }
    const server = new InfinigpuDeviceServer({
      socketPath,
      vmId: meta.vmId ?? 'unknown',
      pixelPort: meta.pixelPort,
      log
    })
    server.adoptedPid = meta.pid
    server.stopped = false
    server.log('info', `re-adopted surviving device (pid ${meta.pid}) on ${socketPath}`)
    return server
  }

  /** The infiniPixel port this device streams on (needed to rebuild the host broker ticket). */
  get streamPixelPort (): number | undefined {
    return this.pixelPort
  }

  /**
   * Spawn the device server and resolve once its socket is accepting (QEMU needs it to
   * exist before it connects). Rejects on early process exit, spawn error, or timeout.
   */
  async start (timeoutMs = 5000): Promise<void> {
    if (this.process || this.adoptedPid != null) {
      throw new Error(`infinigpu-device for VM ${this.vmId} already started`)
    }
    // A stale socket from a prior run would make the server refuse to bind.
    try {
      fs.rmSync(this.socketPath, { force: true })
    } catch {
      /* best effort */
    }

    // stdio → a log file, NOT a pipe: if the backend dies, a piped stdout closes and the Rust
    // device panics on its next `println!`. A file fd stays valid regardless of the parent, so the
    // detached device keeps serving QEMU across a backend restart. Truncate per spawn.
    let logFd: number
    try {
      logFd = fs.openSync(this.logPath, 'w')
    } catch {
      // Fall back to discarding output rather than failing the spawn on a log-open error.
      logFd = fs.openSync('/dev/null', 'w')
    }

    let child: ChildProcess
    try {
      const { cmd, args } = this.launchTarget()
      child = spawn(cmd, args, {
        // Detached: own session/process-group, so a nodemon/process-group signal aimed at the
        // backend does not reach it. QEMU is likewise -daemonize'd; the pair survives together.
        detached: true,
        stdio: ['ignore', logFd, logFd],
        env: this.buildEnv()
      })
    } finally {
      // The child inherited the fd; the parent no longer needs it.
      try { fs.closeSync(logFd) } catch { /* best effort */ }
    }
    this.process = child
    this.stopped = false

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
          this.writeMeta(child.pid)
          // Don't let this (now self-sufficient, detached) child keep the backend event loop alive.
          child.unref()
          finish(resolve)
        }
      }, 100)
      const timer = setTimeout(() => {
        finish(() => reject(new Error(`infinigpu-device for VM ${this.vmId} did not create ${this.socketPath} within ${timeoutMs}ms`)))
      }, timeoutMs)
    })
  }

  /** Persist the survivor record a restarted backend re-adopts from. Best-effort. */
  private writeMeta (pid: number | undefined): void {
    if (pid == null) return
    const meta: InfinigpuDeviceMeta = { pid, vmId: this.vmId, socketPath: this.socketPath, pixelPort: this.pixelPort }
    try {
      fs.writeFileSync(this.metaPath, JSON.stringify(meta))
    } catch (err) {
      this.log('warn', `could not write device sidecar ${this.metaPath}: ${(err as Error).message}`)
    }
  }

  /**
   * Gracefully stop the server (SIGTERM → wait → SIGKILL). The server drops its admission
   * ticket on exit. Safe to call more than once / when never started. Works whether this
   * instance owns a ChildProcess (spawned here) or only a pid (re-adopted after a restart).
   */
  async stop (timeoutMs = 5000): Promise<void> {
    if (this.stopped) {
      this.cleanupFiles()
      return
    }
    this.stopped = true

    const child = this.process
    if (child) {
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
    } else if (this.adoptedPid != null) {
      // Re-adopted survivor: we have only a pid, so signal + poll for exit.
      await this.stopByPid(this.adoptedPid, timeoutMs)
      this.adoptedPid = null
    }

    this.cleanupFiles()
  }

  /** SIGTERM a re-adopted device by pid, escalate to SIGKILL, poll until gone. */
  private async stopByPid (pid: number, timeoutMs: number): Promise<void> {
    const trySignal = (sig: NodeJS.Signals): boolean => {
      try { process.kill(pid, sig); return true } catch { return false }
    }
    if (!trySignal('SIGTERM')) return // already gone
    const deadline = Date.now() + timeoutMs
    let killed = false
    while (Date.now() < deadline) {
      if (!isPidAlive(pid)) return
      await sleep(100)
      if (!killed && Date.now() > deadline - Math.floor(timeoutMs / 2)) {
        this.log('warn', `adopted device (pid ${pid}) did not exit on SIGTERM; sending SIGKILL`)
        trySignal('SIGKILL')
        killed = true
      }
    }
    if (isPidAlive(pid)) trySignal('SIGKILL')
  }

  /** Remove the socket, sidecar and log so a later VM re-using the path can bind cleanly. */
  private cleanupFiles (): void {
    for (const p of [this.socketPath, this.metaPath, this.logPath]) {
      try { fs.rmSync(p, { force: true }) } catch { /* best effort */ }
    }
  }
}

/** `kill(pid, 0)` — true iff the process exists and we may signal it. */
function isPidAlive (pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    // EPERM = exists but not ours (still "alive"); ESRCH = gone.
    return (err as NodeJS.ErrnoException).code === 'EPERM'
  }
}

function sleep (ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
