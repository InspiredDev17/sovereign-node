# Platform Support and Deployment Evidence

## Implemented v0.1

The hardened daemon and stateful identity commands require Unix ownership,
permission, descriptor and advisory-lock primitives. macOS and Linux are the
supported source targets. The daemon refuses root and remote service on an
unsupported platform.

macOS is first-class for ARM64 identity/state, TLS, exact-file publication,
Unix permissions and local-only operation. The runtime does not claim cgroups,
namespaces, seccomp, Linux `no_new_privs`, CUDA isolation or an equivalent
process sandbox on macOS. Apple Metal and unified-memory facts are accepted only
from a fresh role-separated signed resource snapshot; their absence is Unknown,
not fabricated support.

Linux remains a primary deployment target, but cgroups v2, namespaces, seccomp,
dedicated service identities, systemd supervision and GPU isolation are not
implemented by this repository. They must not be advertised in sandbox fields.
The workload manifest represents each enforcement dimension explicitly as
Enforced, Partial, Advisory or Unavailable.

## Deployment

- Run under a dedicated unprivileged account.
- Keep the data directory mode 0700 and identity, database, TLS key,
  configuration, snapshot and archive files owner-controlled.
- Configuration may be service-user-owned or root-owned, but must be a regular
  no-follow descriptor, singly linked, bounded to 1 MiB, and not group/world
  writable. Every resolved sensitive ancestor must be root/service-owned and
  non-replaceable.
- Bind only one exact loopback/private address and provision TLS server trust
  separately. The server certificate is not bound to NodeId in v0.1.
- Do not expose the listener directly to the public Internet.
- Use owner-local archive/status/recovery commands while the daemon is stopped
  when their lifecycle lease requires it.

Evidence must be classified by where it actually ran. Compilation on macOS is
not Linux runtime evidence; simulated Metal/CUDA nodes are not physical GPU or
multi-host operation; local ephemeral certificates are not production key
custody.
