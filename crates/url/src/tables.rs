//! The fixed tables the guard reads a host by: where the cloud metadata
//! services are, which names always stay on the local network, and which
//! public names answer with whatever address they are asked for.

/// Where a metadata service listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    /// An IPv4 address.
    V4([u8; 4]),
    /// An IPv6 address, as its eight groups.
    V6([u16; 8]),
    /// A name, whole, without a trailing dot.
    Name(&'static str),
}

/// The cloud metadata services: where each listens, and the provider beside
/// it. One table, read by the host judgement and walked by the tests, so a
/// row cannot be added without being checked.
///
/// A metadata service hands out the machine's credentials to anything on the
/// machine that asks, which is why this is its own rule and wins over the
/// local-address one: the reason says what it is.
pub(crate) const METADATA: [(Endpoint, &str); 13] = [
    (
        Endpoint::V4([169, 254, 169, 254]),
        "AWS, Google Cloud, Azure, DigitalOcean and OpenStack",
    ),
    (Endpoint::V4([169, 254, 170, 2]), "AWS ECS task credentials"),
    (Endpoint::V4([100, 100, 100, 200]), "Alibaba Cloud"),
    (Endpoint::V4([192, 0, 0, 192]), "Oracle Cloud"),
    (Endpoint::V4([168, 63, 129, 16]), "Azure host"),
    (Endpoint::V6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]), "AWS"),
    (Endpoint::Name("metadata.google.internal"), "Google Cloud"),
    (Endpoint::Name("metadata"), "Google Cloud"),
    (Endpoint::Name("instance-data"), "AWS"),
    (Endpoint::Name("instance-data.ec2.internal"), "AWS"),
    (Endpoint::Name("metadata.azure.com"), "Azure"),
    (Endpoint::Name("metadata.tencentyun.com"), "Tencent Cloud"),
    (
        Endpoint::Name("metadata.platformequinix.com"),
        "Equinix Metal",
    ),
];

/// Names that only ever mean this machine: `localhost` and everything under
/// it (RFC 6761), which a resolver answers with a loopback address.
pub(crate) const LOOPBACK_NAME: &str = "localhost";

/// Name endings (a whole label, or labels, at the end) that are for a local
/// network and never delegated on the public one: RFC 6762 `local`, RFC 8375
/// `home.arpa`, the `internal` ending ICANN set aside for private use, and
/// the endings routers, Windows domains and local development servers use by
/// habit. A public name never ends in one of them.
pub(crate) const NETWORK_SUFFIXES: [&str; 12] = [
    "local",
    // Kubernetes: `kubernetes.default.svc` (and `.svc.cluster.local`, under
    // `.local`) names a service inside a cluster.
    "svc",
    "internal",
    "home.arpa",
    "lan",
    "localdomain",
    "intranet",
    "corp",
    "home",
    "private",
    // Reserved for tests (RFC 2606); local development servers answer for
    // them on the machine (`.test` is what Valet and many dev proxies use).
    "test",
    "example",
];

/// Public names that resolve to the address written in them, or always to
/// loopback, so the name says nothing about where the request goes (DNS
/// rebinding services). A name under one is judged as local, whole: reading
/// an embedded address out of the name would be a second parser to get wrong,
/// and nothing a fetch is for needs one.
///
/// This is a list of what is known; any public name can point at a private
/// address through its own DNS, and a guard that does no lookup cannot see
/// that.
pub(crate) const REBINDING: [&str; 15] = [
    "nip.io",
    "sslip.io",
    "xip.io",
    "traefik.me",
    "localtest.me",
    "lvh.me",
    "vcap.me",
    "lacolhost.com",
    "local.gd",
    "localdev.me",
    "fuf.me",
    "localho.st",
    "localhost.direct",
    "1u.ms",
    "rbndr.us",
];

/// The longest URL read, in bytes. A URL this long is not one an agent
/// fetches, and a limit keeps every answer quick.
pub(crate) const MAX_URL: usize = 8192;
