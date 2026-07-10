/**
 * PrismaAdapter unit tests (DB-FREE).
 *
 * These tests drive a hand-rolled fake PrismaClientLike — there is NO real
 * database connection. They lock in the security-critical contracts identified
 * by the adversarial audit:
 *
 *   1. transitionVMStatus surfaces a VERSION_CONFLICT when the optimistic-lock
 *      updateMany returns count === 0 (a concurrent process won the race).
 *   2. The read paths fail CLOSED: a transient DB error must RE-THROW, never be
 *      collapsed into the `null`/`[]` that means "not found". Collapsing would,
 *      e.g., make the orphan scanner SIGKILL a live VM's QEMU on a DB blip.
 *   3. parseDiskPaths throws on a present-but-corrupt blob and returns null on
 *      absent — it must never silently drop a multi-disk VM's data disks.
 *   4. A transient P2034 (write-conflict/deadlock) is retried, then surfaced.
 *   5. The configuration mapper round-trips the advanced columns
 *      (tpmSocketPath/guestAgentSocketPath/virtioDriversIso/NUMA) from a select
 *      that includes them — guarding the just-fixed data-loss regression.
 */

import { PrismaAdapter } from '../src/db/PrismaAdapter'
import { PrismaAdapterError, PrismaAdapterErrorCode } from '../src/types/db.types'

// ---------------------------------------------------------------------------
// Fake PrismaClientLike scaffolding
// ---------------------------------------------------------------------------

type AnyArgs = Record<string, unknown>

/**
 * Builds a fake Prisma client whose every method throws by default, so each
 * test must explicitly opt into the behavior it exercises. This guarantees we
 * never accidentally pass because an unimplemented method returned undefined.
 */
function makeFakePrisma (overrides: {
  machine?: Partial<Record<string, (args: AnyArgs) => unknown>>
  machineConfiguration?: Partial<Record<string, (args: AnyArgs) => unknown>>
  transaction?: (fn: (tx: any) => Promise<unknown>) => Promise<unknown>
} = {}): any {
  const notImplemented = (name: string) => () => {
    throw new Error(`fake.${name} not configured for this test`)
  }

  const machine = {
    findUnique: notImplemented('machine.findUnique'),
    findFirst: notImplemented('machine.findFirst'),
    findMany: notImplemented('machine.findMany'),
    update: notImplemented('machine.update'),
    updateMany: notImplemented('machine.updateMany'),
    ...(overrides.machine ?? {})
  }

  const machineConfiguration = {
    upsert: notImplemented('machineConfiguration.upsert'),
    updateMany: notImplemented('machineConfiguration.updateMany'),
    ...(overrides.machineConfiguration ?? {})
  }

  const client: any = {
    machine,
    machineConfiguration,
    $transaction:
      overrides.transaction ??
      (async (fn: (tx: any) => Promise<unknown>) => fn(client))
  }

  return client
}

/** A fully-populated configuration row including the advanced columns. */
function fullConfigRow () {
  return {
    machineId: 'm-1',
    qemuPid: 4321,
    tapDeviceName: 'vnet-1',
    qmpSocketPath: '/run/qmp/m-1.sock',
    graphicProtocol: 'spice',
    graphicPort: 5900,
    graphicPassword: 'secret',
    graphicHost: '127.0.0.1',
    assignedGpuBus: null,
    bridge: 'virbr0',
    machineType: 'q35',
    cpuModel: 'host',
    diskBus: 'virtio',
    diskCacheMode: 'writeback',
    networkModel: 'virtio-net-pci',
    networkQueues: 4,
    memoryBalloon: true,
    diskPaths: ['/var/lib/vm/m-1.qcow2', '/var/lib/vm/m-1-data.qcow2'],
    uefiFirmware: '/usr/share/OVMF/OVMF_CODE.fd',
    hugepages: true,
    cpuPinning: { cores: [0, 1, 2, 3] },
    enableNumaCtlPinning: true,
    cpuPinningStrategy: 'hybrid',
    tpmSocketPath: '/run/swtpm/m-1.sock',
    guestAgentSocketPath: '/run/qga/m-1.sock',
    infiniServiceSocketPath: '/run/infini/m-1.sock',
    virtioDriversIso: '/var/lib/iso/virtio-win.iso',
    enableAudio: true,
    enableUsbTablet: true
  }
}

function fullMachineRow (overrides: AnyArgs = {}) {
  return {
    id: 'm-1',
    status: 'off',
    name: 'VM One',
    internalName: 'vm-one',
    os: 'win11',
    cpuCores: 4,
    ramGB: 8,
    diskSizeGB: 64,
    gpuPciAddress: null,
    version: 1,
    configuration: fullConfigRow(),
    firewallRuleSet: null,
    department: null,
    ...overrides
  }
}

// ---------------------------------------------------------------------------
// 1. transitionVMStatus → VERSION_CONFLICT when updateMany count === 0
// ---------------------------------------------------------------------------

describe('transitionVMStatus optimistic locking', () => {
  it('throws VERSION_CONFLICT when tx.machine.updateMany returns count === 0', async () => {
    const prisma = makeFakePrisma({
      machine: {
        findUnique: async () => fullMachineRow({ status: 'off', version: 1 }),
        // Simulate a concurrent writer: the conditional updateMany matches 0 rows.
        updateMany: async () => ({ count: 0 })
      }
    })
    const adapter = new PrismaAdapter(prisma)

    await expect(
      adapter.transitionVMStatus('m-1', 'off', 'starting', 1)
    ).rejects.toMatchObject({ code: PrismaAdapterErrorCode.VERSION_CONFLICT })
  })

  it('throws VERSION_CONFLICT when the current version does not match expected', async () => {
    const prisma = makeFakePrisma({
      machine: {
        findUnique: async () => fullMachineRow({ status: 'off', version: 7 }),
        updateMany: async () => ({ count: 1 })
      }
    })
    const adapter = new PrismaAdapter(prisma)

    await expect(
      adapter.transitionVMStatus('m-1', 'off', 'starting', 1)
    ).rejects.toMatchObject({ code: PrismaAdapterErrorCode.VERSION_CONFLICT })
  })

  it('succeeds and returns the incremented version when the lock holds', async () => {
    const prisma = makeFakePrisma({
      machine: {
        findUnique: async () => fullMachineRow({ status: 'off', version: 1 }),
        updateMany: async () => ({ count: 1 })
      }
    })
    const adapter = new PrismaAdapter(prisma)

    const result = await adapter.transitionVMStatus('m-1', 'off', 'starting', 1)
    expect(result.success).toBe(true)
    expect(result.newVersion).toBe(2)
    expect(result.vmConfig.status).toBe('starting')
    expect(result.vmConfig.version).toBe(2)
  })
})

// ---------------------------------------------------------------------------
// updateMachineStatus onlyIfNotIn guard: never clobber a terminal 'error'
// ---------------------------------------------------------------------------

describe('updateMachineStatus onlyIfNotIn guard', () => {
  it('folds the guard into the WHERE clause as an atomic conditional update', async () => {
    let capturedWhere: any
    const prisma = makeFakePrisma({
      machine: {
        updateMany: async (args: AnyArgs) => {
          capturedWhere = (args as any).where
          return { count: 1 }
        }
      }
    })
    const adapter = new PrismaAdapter(prisma)

    await adapter.updateMachineStatus('m-1', 'off', { onlyIfNotIn: ['error'] })

    // The status check must live in WHERE (one statement), NOT a read-then-write.
    expect(capturedWhere).toEqual({ id: 'm-1', status: { notIn: ['error'] } })
  })

  it('does not throw when the guard matches 0 rows (row was in a guarded state)', async () => {
    const prisma = makeFakePrisma({
      machine: {
        // Simulate the row already being 'error': the guarded update matches nothing.
        updateMany: async () => ({ count: 0 })
      }
    })
    const adapter = new PrismaAdapter(prisma)

    await expect(
      adapter.updateMachineStatus('m-1', 'off', { onlyIfNotIn: ['error'] })
    ).resolves.toBeUndefined()
  })

  it('uses a bare id WHERE when no guard is given (backward compatible)', async () => {
    let capturedWhere: any
    const prisma = makeFakePrisma({
      machine: {
        updateMany: async (args: AnyArgs) => {
          capturedWhere = (args as any).where
          return { count: 1 }
        }
      }
    })
    const adapter = new PrismaAdapter(prisma)

    await adapter.updateMachineStatus('m-1', 'off')

    expect(capturedWhere).toEqual({ id: 'm-1' })
  })

  it('treats an empty onlyIfNotIn array as no guard', async () => {
    let capturedWhere: any
    const prisma = makeFakePrisma({
      machine: {
        updateMany: async (args: AnyArgs) => {
          capturedWhere = (args as any).where
          return { count: 1 }
        }
      }
    })
    const adapter = new PrismaAdapter(prisma)

    await adapter.updateMachineStatus('m-1', 'off', { onlyIfNotIn: [] })

    expect(capturedWhere).toEqual({ id: 'm-1' })
  })
})

// ---------------------------------------------------------------------------
// 2. Fail-CLOSED read contract: re-throw, never collapse to null/[]
// ---------------------------------------------------------------------------

describe('fail-closed read contract', () => {
  const dbError = () => {
    throw new Error('connection terminated unexpectedly')
  }

  it('findMachineByInternalName re-throws on a DB error (does not return null)', async () => {
    const prisma = makeFakePrisma({ machine: { findFirst: async () => dbError() } })
    const adapter = new PrismaAdapter(prisma)

    await expect(adapter.findMachineByInternalName('vm-one')).rejects.toBeInstanceOf(
      PrismaAdapterError
    )
  })

  it('findRunningVMs re-throws on a DB error (does not return [])', async () => {
    const prisma = makeFakePrisma({ machine: { findMany: async () => dbError() } })
    const adapter = new PrismaAdapter(prisma)

    await expect(adapter.findRunningVMs()).rejects.toBeInstanceOf(PrismaAdapterError)
  })

  it('getFirewallRules re-throws on a DB error (does not return [])', async () => {
    const prisma = makeFakePrisma({ machine: { findUnique: async () => dbError() } })
    const adapter = new PrismaAdapter(prisma)

    await expect(adapter.getFirewallRules('m-1')).rejects.toBeInstanceOf(
      PrismaAdapterError
    )
  })

  it('getDepartmentFirewallPolicy re-throws on a DB error (does not return null)', async () => {
    const prisma = makeFakePrisma({ machine: { findUnique: async () => dbError() } })
    const adapter = new PrismaAdapter(prisma)

    await expect(adapter.getDepartmentFirewallPolicy('m-1')).rejects.toBeInstanceOf(
      PrismaAdapterError
    )
  })

  it('getFirewallRules still throws MACHINE_NOT_FOUND for a genuinely missing VM (null, not error)', async () => {
    const prisma = makeFakePrisma({ machine: { findUnique: async () => null } })
    const adapter = new PrismaAdapter(prisma)

    await expect(adapter.getFirewallRules('m-1')).rejects.toMatchObject({
      code: PrismaAdapterErrorCode.MACHINE_NOT_FOUND
    })
  })

  describe('getFirewallRulesSplit', () => {
    const mkRule = (id: string, overridesDept = false) => ({
      id,
      name: `rule-${id}`,
      description: null,
      action: 'ACCEPT',
      direction: 'IN',
      priority: 100,
      protocol: 'tcp',
      srcPortStart: null,
      srcPortEnd: null,
      dstPortStart: 80,
      dstPortEnd: 80,
      srcIpAddr: null,
      srcIpMask: null,
      dstIpAddr: null,
      dstIpMask: null,
      connectionState: null,
      overridesDept
    })

    it('returns department and VM rules in separate arrays (preserving override flag)', async () => {
      const machine = {
        id: 'm-1',
        department: {
          id: 'd-1',
          name: 'eng',
          firewallRuleSet: {
            id: 'rs-dept',
            name: 'dept-rules',
            rules: [mkRule('dept-1'), mkRule('dept-2')]
          }
        },
        firewallRuleSet: {
          id: 'rs-vm',
          name: 'vm-rules',
          rules: [mkRule('vm-1', true)]
        }
      }
      const client = { machine: { findUnique: jest.fn().mockResolvedValue(machine) } }
      const adapter = new PrismaAdapter(client as any)
      const r = await adapter.getFirewallRulesSplit('m-1')
      expect(r.departmentRules).toHaveLength(2)
      expect(r.vmRules).toHaveLength(1)
      // overridesDept flag must survive the mapping so NftablesService.mergeRules
      // can apply override semantics (the whole point of the split).
      expect(r.vmRules[0].overridesDept).toBe(true)
    })

    it('returns empty arrays when the VM has no rule sets', async () => {
      const machine = { id: 'm-1', department: null, firewallRuleSet: null }
      const client = { machine: { findUnique: jest.fn().mockResolvedValue(machine) } }
      const adapter = new PrismaAdapter(client as any)
      const r = await adapter.getFirewallRulesSplit('m-1')
      expect(r).toEqual({ departmentRules: [], vmRules: [] })
    })

    it('throws MACHINE_NOT_FOUND when the VM does not exist (fail-closed, not empty)', async () => {
      const client = { machine: { findUnique: jest.fn().mockResolvedValue(null) } }
      const adapter = new PrismaAdapter(client as any)
      await expect(adapter.getFirewallRulesSplit('missing')).rejects.toMatchObject({
        code: PrismaAdapterErrorCode.MACHINE_NOT_FOUND
      })
    })

    it('re-throws a DB error (fail-closed, never returns [])', async () => {
      const client = {
        machine: { findUnique: jest.fn().mockRejectedValue(new Error('connection lost')) }
      }
      const adapter = new PrismaAdapter(client as any)
      await expect(adapter.getFirewallRulesSplit('m-1')).rejects.toMatchObject({
        code: PrismaAdapterErrorCode.QUERY_FAILED
      })
    })
  })

  it('getDepartmentFirewallPolicy returns null for a genuinely missing/department-less VM', async () => {
    const prisma = makeFakePrisma({
      machine: { findUnique: async () => ({ id: 'm-1', status: 'off', department: null }) }
    })
    const adapter = new PrismaAdapter(prisma)

    await expect(adapter.getDepartmentFirewallPolicy('m-1')).resolves.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 3. parseDiskPaths: throw on corrupt, null on absent, pass-through on valid
// ---------------------------------------------------------------------------

describe('parseDiskPaths (via the config mapper)', () => {
  // parseDiskPaths is private; exercise it through findMachineWithConfig, which
  // runs the full mapToExtendedMachineConfiguration path.
  function adapterReturningConfig (diskPaths: unknown) {
    const row = fullMachineRow({ configuration: { ...fullConfigRow(), diskPaths } })
    const prisma = makeFakePrisma({ machine: { findUnique: async () => row } })
    return new PrismaAdapter(prisma)
  }

  it('returns null when diskPaths is null (absent)', async () => {
    const adapter = adapterReturningConfig(null)
    const cfg = await adapter.findMachineWithConfig('m-1')
    expect(cfg?.configuration?.diskPaths).toBeNull()
  })

  it('passes through a valid string[] blob', async () => {
    const paths = ['/a.qcow2', '/b.qcow2']
    const adapter = adapterReturningConfig(paths)
    const cfg = await adapter.findMachineWithConfig('m-1')
    expect(cfg?.configuration?.diskPaths).toEqual(paths)
  })

  it('throws (fail-closed) on a present-but-corrupt non-string[] blob', async () => {
    const adapter = adapterReturningConfig({ not: 'an array' })
    await expect(adapter.findMachineWithConfig('m-1')).rejects.toBeInstanceOf(
      PrismaAdapterError
    )
  })

  it('throws on a mixed array containing non-strings', async () => {
    const adapter = adapterReturningConfig(['/a.qcow2', 42])
    await expect(adapter.findMachineWithConfig('m-1')).rejects.toBeInstanceOf(
      PrismaAdapterError
    )
  })
})

// ---------------------------------------------------------------------------
// 4. P2034 retry then surface
// ---------------------------------------------------------------------------

describe('transitionVMStatus P2034 retry', () => {
  it('retries a transient P2034 then succeeds on a later attempt', async () => {
    let attempts = 0
    const prisma = makeFakePrisma({
      transaction: async (fn) => {
        attempts++
        if (attempts < 3) {
          // eslint-disable-next-line @typescript-eslint/no-throw-literal
          throw { code: 'P2034' }
        }
        return fn(prisma)
      },
      machine: {
        findUnique: async () => fullMachineRow({ status: 'off', version: 1 }),
        updateMany: async () => ({ count: 1 })
      }
    })
    const adapter = new PrismaAdapter(prisma)

    const result = await adapter.transitionVMStatus('m-1', 'off', 'starting', 1)
    expect(result.success).toBe(true)
    expect(attempts).toBe(3)
  })

  it('surfaces a P2034 that persists past MAX_TX_ATTEMPTS (mapped, not swallowed)', async () => {
    let attempts = 0
    const prisma = makeFakePrisma({
      transaction: async () => {
        attempts++
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
        throw { code: 'P2034' }
      }
    })
    const adapter = new PrismaAdapter(prisma)

    await expect(
      adapter.transitionVMStatus('m-1', 'off', 'starting', 1)
    ).rejects.toBeInstanceOf(PrismaAdapterError)
    // 3 attempts total (MAX_TX_ATTEMPTS), all exhausted.
    expect(attempts).toBe(3)
  })
})

// ---------------------------------------------------------------------------
// 5. Mapper round-trips the advanced columns from an inclusive select
// ---------------------------------------------------------------------------

describe('configuration mapper round-trips advanced columns', () => {
  it('preserves tpm/guestAgent/virtio/NUMA/audio/usbTablet from the select', async () => {
    const row = fullMachineRow()
    const prisma = makeFakePrisma({ machine: { findUnique: async () => row } })
    const adapter = new PrismaAdapter(prisma)

    const cfg = await adapter.findMachineWithConfig('m-1')
    const c = cfg?.configuration
    expect(c).toBeTruthy()
    expect(c?.tpmSocketPath).toBe('/run/swtpm/m-1.sock')
    expect(c?.guestAgentSocketPath).toBe('/run/qga/m-1.sock')
    expect(c?.infiniServiceSocketPath).toBe('/run/infini/m-1.sock')
    expect(c?.virtioDriversIso).toBe('/var/lib/iso/virtio-win.iso')
    expect(c?.enableNumaCtlPinning).toBe(true)
    expect(c?.cpuPinningStrategy).toBe('hybrid')
    expect(c?.enableAudio).toBe(true)
    expect(c?.enableUsbTablet).toBe(true)
    expect(c?.cpuPinning).toEqual({ cores: [0, 1, 2, 3] })
  })

  it('coerces an absent advanced column (undefined) to null, not undefined', async () => {
    const config = fullConfigRow()
    // Simulate a row where the column came back undefined (e.g. legacy NULL).
    delete (config as Record<string, unknown>).tpmSocketPath
    delete (config as Record<string, unknown>).enableNumaCtlPinning
    const row = fullMachineRow({ configuration: config })
    const prisma = makeFakePrisma({ machine: { findUnique: async () => row } })
    const adapter = new PrismaAdapter(prisma)

    const cfg = await adapter.findMachineWithConfig('m-1')
    expect(cfg?.configuration?.tpmSocketPath).toBeNull()
    expect(cfg?.configuration?.enableNumaCtlPinning).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// 6. RunningVMRecord.internalName is populated (CROSS-UNIT CONTRACT for HealthMonitor)
// ---------------------------------------------------------------------------

describe('RunningVMRecord.internalName cross-unit contract', () => {
  it('findRunningVMs returns internalName for each VM', async () => {
    const prisma = makeFakePrisma({
      machine: {
        findMany: async () => [
          {
            id: 'm-1',
            status: 'running',
            internalName: 'vm-one',
            configuration: {
              qemuPid: 100,
              tapDeviceName: 'vnet-1',
              qmpSocketPath: '/run/qmp/m-1.sock',
              guestAgentSocketPath: '/run/qga/m-1.sock',
              infiniServiceSocketPath: '/run/infini/m-1.sock'
            }
          }
        ]
      }
    })
    const adapter = new PrismaAdapter(prisma)

    const vms = await adapter.findRunningVMs()
    expect(vms[0].internalName).toBe('vm-one')
    expect(vms[0].MachineConfiguration?.qemuPid).toBe(100)
  })

  it('findMachineByInternalName echoes the queried internalName', async () => {
    const prisma = makeFakePrisma({
      machine: {
        findFirst: async () => ({
          id: 'm-1',
          status: 'running',
          internalName: 'vm-one',
          configuration: null
        })
      }
    })
    const adapter = new PrismaAdapter(prisma)

    const vm = await adapter.findMachineByInternalName('vm-one')
    expect(vm?.internalName).toBe('vm-one')
  })

  it('findMachinesByStatuses returns internalName for each VM', async () => {
    const prisma = makeFakePrisma({
      machine: {
        findMany: async () => [
          { id: 'm-2', status: 'starting', internalName: 'vm-two', configuration: null }
        ]
      }
    })
    const adapter = new PrismaAdapter(prisma)

    const vms = await adapter.findMachinesByStatuses(['starting'])
    expect(vms[0].internalName).toBe('vm-two')
  })
})

describe('PrismaAdapter node scoping (G0 — node-scoped enumeration reads)', () => {
  // Captures the `where` each enumeration read sends to Prisma so we can PROVE
  // the nodeId predicate is (or is not) applied. This is the structural G0
  // guard: the three reads below drive destructive actions keyed on the LOCAL
  // /proc (crash-detect mark-off, transient reconcile, orphan reap). Unscoped,
  // a host enumerates another node's VMs and cross-kills them.
  function makeWhereCapturingPrisma (rows: any[]) {
    const captured: { findMany: any[], findFirst: any[] } = { findMany: [], findFirst: [] }
    const prisma = makeFakePrisma({
      machine: {
        findMany: async (args: AnyArgs) => { captured.findMany.push(args.where); return rows },
        findFirst: async (args: AnyArgs) => { captured.findFirst.push(args.where); return rows[0] ?? null }
      }
    })
    return { prisma, captured }
  }

  const ROW = { id: 'm-1', status: 'running', internalName: 'vm-one', configuration: null }

  it('node-scoped adapter filters findRunningVMs by nodeId', async () => {
    const { prisma, captured } = makeWhereCapturingPrisma([ROW])
    const adapter = new PrismaAdapter(prisma, 'node-A')
    await adapter.findRunningVMs()
    expect(captured.findMany[0]).toEqual({ status: 'running', nodeId: 'node-A' })
  })

  it('node-scoped adapter filters findMachinesByStatuses by nodeId', async () => {
    const { prisma, captured } = makeWhereCapturingPrisma([ROW])
    const adapter = new PrismaAdapter(prisma, 'node-A')
    await adapter.findMachinesByStatuses(['starting', 'off'])
    expect(captured.findMany[0]).toEqual({ status: { in: ['starting', 'off'] }, nodeId: 'node-A' })
  })

  it('node-scoped findMachineByInternalName matches this node OR any migrating VM (orphan map stays local but never reaps an in-flight move)', async () => {
    const { prisma, captured } = makeWhereCapturingPrisma([ROW])
    const adapter = new PrismaAdapter(prisma, 'node-A')
    await adapter.findMachineByInternalName('vm-one')
    // A LOCAL pidfile maps to one of THIS node's VMs — EXCEPT a VM that is
    // mid-migration ('moving', migrationJobId set), whose nodeId may still name the
    // source while its QEMU already runs on the destination. Surfacing moving VMs
    // regardless of owner lets HealthMonitor.checkOrphanProcesses recognise and skip
    // them instead of killing a legitimately-migrating process.
    expect(captured.findFirst[0]).toEqual({
      internalName: 'vm-one',
      OR: [{ nodeId: 'node-A' }, { status: 'moving' }]
    })
  })

  it("a node-scoped adapter's running-VM query carries nodeId so another node's rows are excluded (cross-kill prevented)", async () => {
    const { prisma, captured } = makeWhereCapturingPrisma([])
    const adapter = new PrismaAdapter(prisma, 'node-A')
    const vms = await adapter.findRunningVMs()
    expect(vms).toEqual([])
    expect(captured.findMany[0]).toHaveProperty('nodeId', 'node-A')
  })

  it('an UN-scoped adapter (single-host) sends NO nodeId predicate — behaviour preserved bit-for-bit', async () => {
    const { prisma, captured } = makeWhereCapturingPrisma([ROW])
    const adapter = new PrismaAdapter(prisma) // no nodeId
    await adapter.findRunningVMs()
    await adapter.findMachinesByStatuses(['off'])
    await adapter.findMachineByInternalName('vm-one')
    expect(captured.findMany[0]).toEqual({ status: 'running' })
    expect(captured.findMany[1]).toEqual({ status: { in: ['off'] } })
    expect(captured.findFirst[0]).toEqual({ internalName: 'vm-one' })
  })
})
