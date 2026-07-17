import { InfinigpuDeviceServer } from '../src/core/InfinigpuDeviceServer'
import { QemuArgValidationError } from '../src/utils/qemuArgSafety'
import fs from 'fs'
import os from 'os'
import path from 'path'

describe('InfinigpuDeviceServer', () => {
  let tmp: string

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'infinigpu-dev-'))
  })
  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true })
  })

  const sock = () => path.join(tmp, 'vm.gpu.sock')

  describe('argv / env construction (pure)', () => {
    it('builds the --socket/--vm-id argv', () => {
      const s = new InfinigpuDeviceServer({ socketPath: sock(), vmId: 'vm-42' })
      expect(s.buildArgs()).toEqual(['--socket', sock(), '--vm-id', 'vm-42'])
    })

    it('sets INFINIGPU_PIXEL_PORT only when a pixel port is given', () => {
      const off = new InfinigpuDeviceServer({ socketPath: sock(), vmId: 'v' })
      expect(off.buildEnv().INFINIGPU_PIXEL_PORT).toBeUndefined()
      const on = new InfinigpuDeviceServer({ socketPath: sock(), vmId: 'v', pixelPort: 6123 })
      expect(on.buildEnv().INFINIGPU_PIXEL_PORT).toBe('6123')
    })

    it('merges extra env over the inherited env', () => {
      const s = new InfinigpuDeviceServer({ socketPath: sock(), vmId: 'v', env: { INFINIGPU_X: 'y' } })
      expect(s.buildEnv().INFINIGPU_X).toBe('y')
    })

    it('rejects a socket path that would splice arg/shell metacharacters', () => {
      expect(() => new InfinigpuDeviceServer({ socketPath: '/run/x.sock,readonly=on', vmId: 'v' }))
        .toThrow(QemuArgValidationError)
    })
  })

  describe('process lifecycle', () => {
    // A fake "device" that creates the socket file then waits for SIGTERM.
    const fakeBinary = (): string => {
      const p = path.join(tmp, 'fake-device.sh')
      fs.writeFileSync(
        p,
        '#!/usr/bin/env bash\n' +
          'sock=""\n' +
          'while [ $# -gt 0 ]; do case "$1" in --socket) sock="$2"; shift 2;; *) shift;; esac; done\n' +
          ': > "$sock"\n' +
          'trap \'rm -f "$sock"; exit 0\' TERM\n' +
          'sleep 60 & wait\n',
        { mode: 0o755 }
      )
      return p
    }

    it('start() resolves once the socket appears, then stop() reaps it', async () => {
      const s = new InfinigpuDeviceServer({ binaryPath: fakeBinary(), socketPath: sock(), vmId: 'v', log: () => {} })
      await s.start(3000)
      expect(s.running).toBe(true)
      expect(s.pid).toBeGreaterThan(0)
      expect(fs.existsSync(sock())).toBe(true)

      await s.stop(3000)
      expect(s.running).toBe(false)
      expect(fs.existsSync(sock())).toBe(false)
    })

    it('start() rejects when the binary exits before creating the socket', async () => {
      const s = new InfinigpuDeviceServer({ binaryPath: '/bin/false', socketPath: sock(), vmId: 'v', log: () => {} })
      await expect(s.start(2000)).rejects.toThrow(/exited during startup|did not create/)
      expect(s.running).toBe(false)
    })

    it('start() rejects when the binary is missing', async () => {
      const s = new InfinigpuDeviceServer({ binaryPath: '/no/such/infinigpu-device-xyz', socketPath: sock(), vmId: 'v', log: () => {} })
      await expect(s.start(2000)).rejects.toThrow(/failed to spawn|exited during startup/)
    })

    it('stop() is safe to call when never started', async () => {
      const s = new InfinigpuDeviceServer({ socketPath: sock(), vmId: 'v', log: () => {} })
      await expect(s.stop()).resolves.toBeUndefined()
    })
  })
})
