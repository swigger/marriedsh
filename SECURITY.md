# Security model and v1 wire protocol

This is a new implementation, not an independently audited remote-access product.
The audit history of a dependency does not constitute an audit of this application,
its composition, or the pinned dependency version. Report suspected vulnerabilities
privately to the project owner before using it on sensitive machines.

## Trust boundaries

- Bob's local Unix user controls every device paired with that daemon.
- Alice executes commands as the user running join. A shell is full access to that account.
- Bob refuses all incoming execution requests. V1 also rejects configuration attempting
  to enable them, because an unrestricted same-UID shell could bypass routing restrictions.
- Separate devices require separate passwords and credential IDs. Duplicate secrets
  in a daemon configuration are rejected. Labels are not authentication credentials.
- The network protocol has no destination/forwarding field: a command applies only
  to the authenticated connection's other endpoint. Session IDs are local to a connection.
- Another process running as the same UID, root, or a compromised endpoint is outside
  the isolation boundary. Never share daemon credentials or its control socket.

## Authentication

The only v1 suite is OPAQUE-3DH with Ristretto255 and SHA-512 (`opaque-ke` 4.0.1,
RFC 9807), with Argon2id v19 using 8192 KiB memory, 2 iterations, 1 lane.
The memory cost is fixed to fit smaller Linux devices; it is not selected by a peer.
Prefer generated 256-bit passwords over human passwords.

Bob already possesses the manually provisioned password, so it performs OPAQUE
registration locally at startup. No network registration endpoint exists. It retains
the server setup and registration record in memory. Both can be regenerated at restart;
Alice authenticates through its unchanged password. This does not promise that Bob
never knew the password: both sides were explicitly provisioned with it.

The initial length-prefixed message contains `MRSH0001`, the public credential selector,
and OPAQUE KE1. Bob returns KE2 and Alice returns KE3. OPAQUE binds a fixed
protocol/suite context, the credential ID as client identity, and `marriedsh/bob/v1`
as server identity. Invalid authentication aborts before metadata or execution.
Unknown credentials use the library's dummy-record path. Endpoint names and connection
IDs are exchanged only after authentication in encrypted Hello messages.

The resulting OPAQUE session key feeds HKDF-SHA256 with the fixed protocol context
as salt. Distinct `marriedsh/v1/join-to-daemon` and `marriedsh/v1/daemon-to-join` labels
derive 32-byte ChaCha20-Poly1305 keys. Both sides exchange encrypted Ready records
before Hello. There is no plaintext fallback, version negotiation, or 0-RTT execution.

Each encrypted record is preceded by a 4-byte big-endian ciphertext length (max 65536).
The AEAD nonce is four zero bytes followed by the implicit 64-bit sequence number in
big-endian order. AAD is the length followed by that sequence number. Counters start at
zero independently in each direction. Each new connection performs a fresh OPAQUE
exchange and gets new keys. At 2^32 records the connection must close and reauthenticate.
Length, content, ordering, direction, and replay within a connection are authenticated.
Explicitly erased temporary key material and zeroizing password storage reduce secret
retention, but memory erasure cannot cover all allocator/compiler/library copies.

Payloads use postcard 1.x encoding, bounded input frames and trailing-byte rejection.
This wire format is project-specific v1, not an interoperable
general-purpose OPAQUE transport. Changing suite parameters or encoding requires a new version.

## Session state and resource limits

Join-originated session IDs are odd; daemon-originated IDs are even. Each direction
must strictly increase its IDs, and IDs cannot be reused. Input, output, and control
frames are checked against the initiating/executing role. Closed-session data is ignored
to tolerate in-flight frames; Open IDs are still checked against the high-water mark.

Both directions receive 64 KiB initial credit per session. A data frame spends
max(payload length, 1024) bytes, and credit is returned only after the receiving
process pipe or local console socket accepts the data. Credits cannot exceed the
window. Frames are at most 8 KiB of data. Each connection has at most 8 sessions,
with bounded reader, writer, and session queues. Invalid flow-control or flooding
control queues closes the connection. Command arguments are limited to 256 entries
and 32 KiB total, with NUL rejected.

Unauthenticated connections have a deadline, an 8-handshake concurrency limit,
and a per-source-IP rate limit (8 attempts per 10 seconds, bounded address table).
These limits mitigate resource exhaustion and online guessing; they do not make weak
passwords immune to online guesses or protect against volumetric denial of service.
Network record writes have a 30-second deadline. The client initiates ping/pong;
both sides remove unresponsive connections. TCP packet loss can stall all sessions.

The local control socket lives in a private directory and checks peer UID. Its
listener is bounded to 64 simultaneous clients. Lock files and socket metadata
checks prevent accidental replacement of active instances or unrelated files.
The console-to-daemon stdin path also has a 64 KiB credit window and a separate
input forwarding task, so a command that does not read stdin cannot prevent the
control reader from observing signals or a disconnected console.

## Disconnects and lifecycle

On Unix, daemon/join read configuration and any interactive password before
forking or creating the asynchronous runtime. The default double-fork startup
detaches from the terminal, closes inherited descriptors, and sets umask 077.
It does not serialize the password into a new child command line or environment.
Logs and PID files must be private regular files owned by the current user;
symlinks are rejected. The parent receives readiness or startup errors over a
private socketpair. Foreground mode is available for service supervisors.
An optional `--lock` gate acquires a nonblocking flock before loading configuration
or reading a password. Only lock contention is a silent successful skip. The file
must be private, regular and owned by the current user; symlinks are rejected.
The open descriptor survives daemonization but is close-on-exec for user commands.
The file is never unlinked by the service, avoiding an inode-replacement race.

Connection recovery never resubmits a command. If an acknowledgement or exit status
is lost, the user must treat command outcome as unknown. Sessions are not persistent.
The executor creates a new process session/group and terminates that group on
controller loss, connection loss, or command completion. A deliberately detached
process can escape group cleanup; this is not process containment or a sandbox.
Command output is intentionally untrusted terminal data, as with an ordinary remote shell.

## References

- [OPAQUE, RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html)
- [opaque-ke implementation and audit history](https://github.com/facebook/opaque-ke)
- [Why password-derived TLS external PSKs allow offline guessing, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
- [External PSK deployment guidance, RFC 9257](https://www.rfc-editor.org/rfc/rfc9257.html)
