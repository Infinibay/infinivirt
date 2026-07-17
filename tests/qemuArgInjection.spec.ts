import { QemuCommandBuilder } from '../src/core/QemuCommandBuilder'
import { QemuArgValidationError } from '../src/utils/qemuArgSafety'

describe('QemuCommandBuilder — argument-injection hardening', () => {
  let b: QemuCommandBuilder

  beforeEach(() => {
    b = new QemuCommandBuilder()
  })

  describe('addDisks', () => {
    it('rejects a per-disk cache that splices sub-options', () => {
      expect(() => b.addDisks([{ path: '/d.qcow2', format: 'qcow2', bus: 'virtio', cache: 'none,readonly=on' as never }]))
        .toThrow(QemuArgValidationError)
    })

    it('rejects a non-whitelisted bus', () => {
      expect(() => b.addDisks([{ path: '/d.qcow2', format: 'qcow2', bus: 'none,snapshot=on' as never, cache: 'none' }]))
        .toThrow(QemuArgValidationError)
    })

    it('rejects a disk path containing a comma', () => {
      expect(() => b.addDisks([{ path: '/d.qcow2,readonly=on', format: 'qcow2', bus: 'virtio', cache: 'none' }]))
        .toThrow(QemuArgValidationError)
    })

    it('emits file.locking=on for a valid disk (lock backstop)', () => {
      b.addDisks([{ path: '/d.qcow2', format: 'qcow2', bus: 'virtio', cache: 'none' }])
      const args = b.buildCommand().args.join(' ')
      expect(args).toContain('file.locking=on')
      expect(args).toContain('file=/d.qcow2')
    })
  })

  describe('addInfinigpuDevice', () => {
    it('adds a share=on memfd backend, makes the machine consume it, forces -vga none, and emits the JSON vfio-user device', () => {
      b.setMachine('q35', { accel: 'kvm' }).addInfinigpuDevice({ socketPath: '/run/infinization/sockets/vm1.gpu.sock', guestRamBytes: 4 * 1024 * 1024 * 1024 })
      const args = b.buildCommand().args
      const joined = args.join(' ')
      // memfd backend, sized in bytes, shared.
      expect(joined).toContain('memory-backend-memfd,id=mem0,share=on,size=4294967296')
      // the existing -machine was augmented to consume the backend (not duplicated).
      const machineIdx = args.indexOf('-machine')
      expect(args[machineIdx + 1]).toContain('memory-backend=mem0')
      expect(args.filter(a => a === '-machine').length).toBe(1)
      // our device is the only display.
      const vgaIdx = args.indexOf('-vga')
      expect(args[vgaIdx + 1]).toBe('none')
      // JSON device with the mandatory flags.
      const dev = JSON.parse(args[args.lastIndexOf('-device') + 1])
      expect(dev.driver).toBe('vfio-user-pci')
      expect(dev.socket).toEqual({ path: '/run/infinization/sockets/vm1.gpu.sock', type: 'unix' })
      expect(dev['x-no-posted-writes']).toBe(true)
      expect(dev['x-pci-class-code']).toBe(229376)
    })

    it('rejects a socket path that would splice shell/arg metacharacters', () => {
      expect(() => b.addInfinigpuDevice({ socketPath: '/run/x.sock,readonly=on', guestRamBytes: 1024 }))
        .toThrow()
    })

    it('rejects a non-positive guest RAM size', () => {
      expect(() => b.addInfinigpuDevice({ socketPath: '/run/x.sock', guestRamBytes: 0 })).toThrow()
    })
  })

  describe('setCpu / setProcessOptions / addNetwork', () => {
    it('rejects a -cpu model that splices features', () => {
      expect(() => b.setCpu('host,enforce=off')).toThrow(QemuArgValidationError)
    })

    it('rejects a -name that splices sub-options', () => {
      expect(() => b.setProcessOptions({ vmId: 'vm1', name: 'x,debug-threads=on', daemonize: false })).toThrow(QemuArgValidationError)
    })

    it('rejects a MAC with a comma', () => {
      expect(() => b.addNetwork({ tapName: 'tap0', model: 'virtio-net-pci', mac: '52:54:00:00,x=y' }))
        .toThrow(QemuArgValidationError)
    })
  })

  describe('enableSeccompSandbox', () => {
    it('emits the hardened -sandbox flag', () => {
      b.enableSeccompSandbox()
      const args = b.buildCommand().args.join(' ')
      expect(args).toContain('-sandbox')
      expect(args).toContain('elevateprivileges=deny')
      expect(args).toContain('spawn=deny')
    })
  })

  describe('setBootOrder', () => {
    it('emits a bare order= when no once device is given (unchanged behavior)', () => {
      b.setBootOrder(['c'])
      expect(b.buildCommand().args.join(' ')).toContain('-boot order=c')
    })

    it('emits order=<persistent>,once=<device> for an installer boot', () => {
      // The install idiom: boot the CD once, then the disk on every reboot.
      b.setBootOrder(['c'], { once: 'd' })
      const args = b.buildCommand().args.join(' ')
      expect(args).toContain('-boot order=c,once=d')
      // Must NOT emit a plain order=dc, which would re-enter the installer forever.
      expect(args).not.toContain('order=dc')
    })
  })

  describe('path setters', () => {
    it('rejects an ISO/firmware path that would flip a drive sub-option', () => {
      expect(() => b.setFirmware('/OVMF_CODE.fd,readonly=off')).toThrow(QemuArgValidationError)
      expect(() => b.addQmp('/run/qmp.sock,server=on,evil=1')).toThrow(QemuArgValidationError)
    })

    // Post-audit: these sites were initially missed and hardened after verification.
    it('rejects a primary CD-ROM ISO path with a comma', () => {
      expect(() => b.addCdrom('/isos/x.iso,readonly=off')).toThrow(QemuArgValidationError)
    })

    it('rejects a second CD-ROM (virtio) ISO path with a comma (-drive splice)', () => {
      expect(() => b.addSecondCdrom('/isos/virtio.iso,readonly=off')).toThrow(QemuArgValidationError)
    })

    it('rejects a TAP device name that would splice -netdev sub-options', () => {
      expect(() => b.addNetwork({ tapName: 'tap0,downscript=/evil', model: 'virtio-net-pci', mac: '52:54:00:00:00:01' }))
        .toThrow(QemuArgValidationError)
    })

    it('rejects a pidfile path with a comma', () => {
      expect(() => b.setProcessOptions({ vmId: 'v', name: 'ok', pidfile: '/run/x.pid,evil=1' }))
        .toThrow(QemuArgValidationError)
    })
  })
})
