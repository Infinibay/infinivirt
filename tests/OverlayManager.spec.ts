import { OverlayManager } from '../src/network/OverlayManager'
import type { OverlaySegmentSpec, OverlaySelfIdentity } from '../src/types/overlay.types'

/**
 * OverlayManager unit tests. The realizer is exercised with a fake CommandExecutor
 * (captures exact argv, no real `ip`/`wg`/`bridge` run) and a stub BridgeManager,
 * so these assert the wire-level commands and the idempotency/naming guardrails
 * without a host network. Real L2/WireGuard/VXLAN behaviour needs a live cluster.
 */

interface Call { cmd: string; args: string[] }

function makeExecutor (opts: { existingDevices?: Set<string>; fdbOutput?: string } = {}) {
  const existing = opts.existingDevices ?? new Set<string>()
  const calls: Call[] = []
  const executor = {
    execute: (cmd: string, args: string[]): Promise<string> => {
      calls.push({ cmd, args })
      // Model `ip link add/del <dev>` side effects so deviceExists() reflects reality
      // across the same call (e.g. a vxlan created earlier is "present" for the FDB step).
      if (cmd === 'ip' && args[0] === 'link' && args[1] === 'add') existing.add(args[2])
      if (cmd === 'ip' && args[0] === 'link' && args[1] === 'del') existing.delete(args[2])
      // `ip link show <dev>` — existence probe used by deviceExists().
      if (cmd === 'ip' && args[0] === 'link' && args[1] === 'show') {
        return existing.has(args[2]) ? Promise.resolve('') : Promise.reject(new Error('does not exist'))
      }
      if (cmd === 'bridge' && args[0] === 'fdb' && args[1] === 'show') {
        return Promise.resolve(opts.fdbOutput ?? '')
      }
      return Promise.resolve('')
    }
  }
  const find = (cmd: string, ...prefix: string[]): Call | undefined =>
    calls.find((c) => c.cmd === cmd && prefix.every((p, i) => c.args[i] === p))
  const findAll = (cmd: string, ...prefix: string[]): Call[] =>
    calls.filter((c) => c.cmd === cmd && prefix.every((p, i) => c.args[i] === p))
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return { executor: executor as any, calls, find, findAll, existing }
}

function makeBridge () {
  const bridge = {
    exists: jest.fn().mockResolvedValue(false),
    create: jest.fn().mockResolvedValue(undefined),
    addInterface: jest.fn().mockResolvedValue(undefined),
    assignIP: jest.fn().mockResolvedValue(undefined)
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return { bridge, asAny: bridge as any }
}

const SELF: OverlaySelfIdentity = {
  vtepIp: '10.77.0.3',
  wgPrivateKeyPath: '/etc/infinibay/wg-private.key',
  wgListenPort: 51820
}

const SPEC: OverlaySegmentSpec = {
  deptId: 'abc123def456',
  bridgeName: 'infinibr-abc123',
  vni: 4711,
  mtu: 1370,
  isGatewayOwner: false,
  peers: [{ nodeId: 'node-B', vtepIp: '10.77.0.4', wgPubKey: 'PUBKEYB=', wgEndpoint: '192.168.1.4:51820' }]
}

describe('OverlayManager.ensureSegment', () => {
  it('realizes bridge + WireGuard mesh + VXLAN + peer/FDB with the exact commands', async () => {
    const { executor, find } = makeExecutor()
    const { bridge, asAny } = makeBridge()
    const om = new OverlayManager(SELF, asAny, executor)

    await om.ensureSegment(SPEC)

    // Bridge created locally (the core cross-node fix) + MTU applied.
    expect(bridge.create).toHaveBeenCalledWith('infinibr-abc123')
    expect(find('ip', 'link', 'set', 'infinibr-abc123', 'mtu', '1370')).toBeTruthy()

    // Node-global WireGuard interface: created, keyed from a FILE (secret never in argv), addressed, up.
    expect(find('ip', 'link', 'add', 'infiwg', 'type', 'wireguard')).toBeTruthy()
    const wgSet = find('wg', 'set', 'infiwg', 'listen-port')
    expect(wgSet?.args).toEqual(['set', 'infiwg', 'listen-port', '51820', 'private-key', '/etc/infinibay/wg-private.key'])
    expect(find('ip', 'addr', 'add', '10.77.0.3/32', 'dev', 'infiwg')).toBeTruthy()
    expect(find('ip', 'link', 'set', 'infiwg', 'up')).toBeTruthy()

    // Per-department VXLAN netdev with VNI, local VTEP, nolearning; enslaved to the bridge.
    const vx = find('ip', 'link', 'add', 'infivx-abc123', 'type', 'vxlan')
    expect(vx?.args).toEqual(['link', 'add', 'infivx-abc123', 'type', 'vxlan', 'id', '4711', 'dstport', '4789', 'local', '10.77.0.3', 'nolearning'])
    expect(bridge.addInterface).toHaveBeenCalledWith('infinibr-abc123', 'infivx-abc123')

    // Peer added to the mesh + head-end FDB entry to its VTEP.
    const peer = find('wg', 'set', 'infiwg', 'peer')
    expect(peer?.args).toEqual(['set', 'infiwg', 'peer', 'PUBKEYB=', 'endpoint', '192.168.1.4:51820', 'allowed-ips', '10.77.0.4/32'])
    expect(find('bridge', 'fdb', 'append', '00:00:00:00:00:00', 'dev', 'infivx-abc123', 'dst', '10.77.0.4')).toBeTruthy()

    // Non-owner: no gateway IP assigned.
    expect(bridge.assignIP).not.toHaveBeenCalled()
  })

  it('assigns the gateway IP only on the gateway-owner node', async () => {
    const { executor } = makeExecutor()
    const { bridge, asAny } = makeBridge()
    const om = new OverlayManager(SELF, asAny, executor)
    await om.ensureSegment({ ...SPEC, isGatewayOwner: true, gatewayCidr: '10.10.100.1/24' })
    expect(bridge.assignIP).toHaveBeenCalledWith('infinibr-abc123', '10.10.100.1/24')
  })

  it('is idempotent: with the wg iface and vxlan already present, it re-creates neither', async () => {
    const { executor, findAll } = makeExecutor({ existingDevices: new Set(['infiwg', 'infivx-abc123']) })
    const { bridge, asAny } = makeBridge()
    bridge.exists.mockResolvedValue(true) // bridge already present too
    const om = new OverlayManager(SELF, asAny, executor)

    await om.ensureSegment(SPEC)

    expect(bridge.create).not.toHaveBeenCalled()
    expect(findAll('ip', 'link', 'add', 'infiwg')).toHaveLength(0)
    expect(findAll('ip', 'link', 'add', 'infivx-abc123')).toHaveLength(0)
  })

  it('reconciles FDB: deletes a stale peer dst and appends the new one', async () => {
    // Device present, and the live FDB already floods to an OLD peer 10.77.0.9.
    const fdb = '00:00:00:00:00:00 dev infivx-abc123 dst 10.77.0.9 self permanent\n'
    const { executor, find } = makeExecutor({ existingDevices: new Set(['infiwg', 'infivx-abc123']), fdbOutput: fdb })
    const { bridge, asAny } = makeBridge()
    bridge.exists.mockResolvedValue(true)
    const om = new OverlayManager(SELF, asAny, executor)

    await om.setPeers('abc123def456', 'infinibr-abc123', SPEC.peers) // desired = 10.77.0.4

    expect(find('bridge', 'fdb', 'del', '00:00:00:00:00:00', 'dev', 'infivx-abc123', 'dst', '10.77.0.9')).toBeTruthy()
    expect(find('bridge', 'fdb', 'append', '00:00:00:00:00:00', 'dev', 'infivx-abc123', 'dst', '10.77.0.4')).toBeTruthy()
  })

  it('derives the VXLAN device from the UNIQUE bridge suffix, not the deptId prefix (shortId-collision safe)', async () => {
    // Two departments whose ids share the first 6 chars but the master de-collided
    // into DISTINCT salted bridge names must realize DISTINCT vxlan devices.
    const { executor: ex1, find: find1 } = makeExecutor()
    const b1 = makeBridge()
    await new OverlayManager(SELF, b1.asAny, ex1).ensureSegment({ ...SPEC, deptId: 'abc123AAAAAA', bridgeName: 'infinibr-abc123' })

    const { executor: ex2, find: find2 } = makeExecutor()
    const b2 = makeBridge()
    await new OverlayManager(SELF, b2.asAny, ex2).ensureSegment({ ...SPEC, deptId: 'abc123BBBBBB', bridgeName: 'infinibr-9f7e01', vni: 4712 })

    // Distinct devices (from the bridge suffix), each enslaved to its own bridge.
    expect(find1('ip', 'link', 'add', 'infivx-abc123', 'type', 'vxlan')).toBeTruthy()
    expect(b1.bridge.addInterface).toHaveBeenCalledWith('infinibr-abc123', 'infivx-abc123')
    expect(find2('ip', 'link', 'add', 'infivx-9f7e01', 'type', 'vxlan')).toBeTruthy()
    expect(b2.bridge.addInterface).toHaveBeenCalledWith('infinibr-9f7e01', 'infivx-9f7e01')
  })

  it('actively removes a stale gateway IP on a NON-owner node (symmetric gateway)', async () => {
    const { executor, find } = makeExecutor()
    const { asAny } = makeBridge()
    const om = new OverlayManager(SELF, asAny, executor)
    await om.ensureSegment({ ...SPEC, isGatewayOwner: false, gatewayCidr: '10.10.100.1/24' })
    expect(find('ip', 'addr', 'del', '10.10.100.1/24', 'dev', 'infinibr-abc123')).toBeTruthy()
  })

  it('recreates the VXLAN device when its live VNI has drifted', async () => {
    // Device exists but `ip -d link show` reports a stale VNI → del + recreate.
    const { executor, find, calls } = makeExecutor({ existingDevices: new Set(['infiwg', 'infivx-abc123']) })
    // Make `ip -d link show <dev>` report the OLD vni 9999.
    const origExecute = executor.execute
    executor.execute = (cmd: string, args: string[]) => {
      if (cmd === 'ip' && args[0] === '-d' && args[1] === 'link' && args[2] === 'show') {
        calls.push({ cmd, args })
        return Promise.resolve('vxlan id 9999 dstport 4789 local 10.77.0.3 nolearning')
      }
      return origExecute(cmd, args)
    }
    const { asAny, bridge } = makeBridge()
    bridge.exists.mockResolvedValue(true)
    const om = new OverlayManager(SELF, asAny, executor)
    await om.ensureSegment(SPEC) // desired vni 4711
    expect(find('ip', 'link', 'del', 'infivx-abc123')).toBeTruthy()
    expect(find('ip', 'link', 'add', 'infivx-abc123', 'type', 'vxlan')).toBeTruthy()
  })

  it('rejects a bridge name that looks like a VM TAP (vnet-*)', async () => {
    const { executor } = makeExecutor()
    const { asAny } = makeBridge()
    const om = new OverlayManager(SELF, asAny, executor)
    await expect(om.ensureSegment({ ...SPEC, bridgeName: 'vnet-evil' })).rejects.toThrow(/vnet-\* is reserved/)
  })

  it('rejects an out-of-range VNI', async () => {
    const { executor } = makeExecutor()
    const { asAny } = makeBridge()
    const om = new OverlayManager(SELF, asAny, executor)
    await expect(om.ensureSegment({ ...SPEC, vni: 0 })).rejects.toThrow(/Invalid VNI/)
  })

  it('throws on a host with no overlay identity (not overlay-capable)', async () => {
    const { executor } = makeExecutor()
    const { asAny } = makeBridge()
    const om = new OverlayManager(undefined, asAny, executor)
    expect(om.isConfigured).toBe(false)
    await expect(om.ensureSegment(SPEC)).rejects.toThrow(/not configured/)
  })
})

describe('OverlayManager.destroySegment', () => {
  it('removes the per-department VXLAN device when present', async () => {
    const { executor, find } = makeExecutor({ existingDevices: new Set(['infivx-abc123']) })
    const { asAny } = makeBridge()
    const om = new OverlayManager(SELF, asAny, executor)
    await om.destroySegment('abc123def456', 'infinibr-abc123')
    expect(find('ip', 'link', 'del', 'infivx-abc123')).toBeTruthy()
  })

  it('is a no-op when the device is already absent', async () => {
    const { executor, find } = makeExecutor({ existingDevices: new Set() })
    const { asAny } = makeBridge()
    const om = new OverlayManager(SELF, asAny, executor)
    await om.destroySegment('abc123def456', 'infinibr-abc123')
    expect(find('ip', 'link', 'del', 'infivx-abc123')).toBeUndefined()
  })
})
