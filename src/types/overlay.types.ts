/**
 * Public contract for the department L2 overlay (07-networking.md §1, ADR-N1/N4).
 *
 * A department's network is a single Linux bridge `infinibr-<shortId>`. To make it
 * span nodes, every member node realizes the SAME bridge locally and enslaves a
 * per-department VXLAN netdev `infivx-<shortId>` (VNI = Department.vni) into it. The
 * VXLAN traffic is carried inside ONE node-global WireGuard interface `infiwg`
 * (the encrypted underlay mesh): peer `allowed-ips` and the VXLAN `local`/FDB `dst`
 * addresses are the WireGuard-interface (VTEP) addresses, not raw underlay IPs.
 *
 * The master is the sole control plane: it allocates the VNI, computes each
 * department's peer set, and PUSHES it to member agents (agents never read overlay
 * rows from the DB — that would need a new InfinizationDatabase Pick method). Hence
 * every field a node needs to realize a segment arrives as a call argument.
 */

/**
 * Device-name prefixes for overlay netdevs. These MUST differ from
 * `TAP_NAME_PREFIX` ('vnet-') so overlay devices are never treated as VM TAPs by
 * the vnet-scoped DHCP wildcard or reaped by the orphan-TAP sweep
 * (`TapDeviceManager.cleanupOrphanedTapDevices`, which only enumerates
 * `type tuntap` + 'vnet-'). This naming discipline is a load-bearing guardrail.
 */
export const OVERLAY_VXLAN_PREFIX = 'infivx-'
/** The single node-global WireGuard interface carrying every VNI's VTEP mesh. */
export const OVERLAY_WG_INTERFACE = 'infiwg'
/** IANA VXLAN UDP destination port. */
export const VXLAN_DSTPORT = 4789

/**
 * One remote node in a department's overlay mesh. Master-computed and pushed to
 * the agent (never read from the DB by the node). `vtepIp` is the peer's WireGuard
 * interface address; `wgEndpoint` is the underlay `host:port` the peer is dialed on.
 */
export interface OverlayPeer {
  nodeId: string
  vtepIp: string
  wgPubKey: string
  wgEndpoint: string
}

/**
 * This node's own overlay endpoint identity. Node-local by construction — the
 * WireGuard PRIVATE key never leaves the host, so this is supplied via
 * `InfinizationConfig.overlay` (set by the node agent from its on-disk key), NOT
 * over RPC. Absent on a host that is not overlay-capable, in which case
 * `ensureSegment` throws rather than silently realizing a broken segment.
 */
export interface OverlaySelfIdentity {
  /** This node's WireGuard-interface (VTEP) address, e.g. "10.77.0.3". */
  vtepIp: string
  /** Path to the WireGuard private key file (0600). Passed to `wg set … private-key <file>`
   *  so the secret is read from disk and never appears in argv/logs. */
  wgPrivateKeyPath: string
  /** UDP port `infiwg` listens on for peer handshakes (matches the reported wgEndpoint port). */
  wgListenPort: number
}

/**
 * Arguments for `ensureSegment` — everything a node needs to idempotently realize a
 * department's L2 segment locally. The master fills every field (ADR-N1: "agents are
 * told, they don't allocate").
 */
export interface OverlaySegmentSpec {
  deptId: string
  /** Persisted `Department.bridgeName` ("infinibr-<shortId>"); realized locally if absent. */
  bridgeName: string
  /** `Department.vni` — the VXLAN id for this department's segment. */
  vni: number
  /** `Department.overlayMtu` applied to both the bridge and the VXLAN netdev. */
  mtu: number
  /** Whether THIS node owns gatewayIP + dnsmasq + NAT for the department (ADR-N2). */
  isGatewayOwner: boolean
  /** "10.10.100.1/24" — assigned to the bridge ONLY when `isGatewayOwner`. */
  gatewayCidr?: string
  /** Other member nodes (excludes self). */
  peers: OverlayPeer[]
}
