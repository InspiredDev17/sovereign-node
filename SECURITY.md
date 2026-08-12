# Security policy

Please report suspected vulnerabilities privately through GitHub's private vulnerability reporting
for `InspiredDev17/sovereign-node`. Do not include production keys, credentials, raw authorization
objects, private paths, or personal hardware identifiers in a report.

## Security invariants

A report is especially useful if it demonstrates any of the following:

- execution before local authorization, replay reservation, or audit persistence;
- acceptance of a forged, expired, revoked, wrong-node, or capability-mismatched request;
- a file-root escape, symlink escape, arbitrary executable, shell, environment, or code-upload path;
- pairing or key rotation without local owner approval and proof of key possession;
- an unauthenticated, plaintext, wildcard, or public listener;
- exposure of identity private keys, credentials, raw arguments, or protected hardware identifiers;
- automatic Internet update or control/disablement of Agent Green.

Sovereign Node does not claim resistance to a privileged local attacker, kernel compromise, stolen
device identity keys, or physical attacks. A signed response proves possession of the node key at a
point in time; it is not remote attestation or proof that the host was uncompromised.
