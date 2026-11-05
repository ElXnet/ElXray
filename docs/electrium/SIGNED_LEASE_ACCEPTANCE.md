# Signed core lease acceptance

ElXray already enforces short, Control-signed subscription leases via the local rate limiter. The separate `elx-lease-accept-bin` evidence proves that the **pinned core itself** accepted the ticket and its enforcing limiter still regards the deadline as active. The existence of a server-issued Control ticket or an agent transport ACK alone is not sufficient.

The private Commander `GetSubscription` request may include `elx-lease-accept-challenge`: exactly 32 lowercase hexadecimal digits selected by Control. The response metadata `elx-lease-accept-bin` is a fixed 88-byte record plus a 64-byte core Ed25519 signature.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 16 | Running ElXray core UUID |
| 16 | 16 | Pinned Control node UUID |
| 32 | 8 | Actually installed Control lease sequence (positive) |
| 40 | 8 | Absolute lease expiry (Unix seconds) |
| 48 | 8 | Signed lease upload ceiling (B/s) |
| 56 | 8 | Signed lease download ceiling (B/s) |
| 64 | 8 | Currently installed policy revision |
| 72 | 8 | Current upload limiter rate |
| 80 | 8 | Current download limiter rate |
| 88 | 64 | Ed25519 signature by the pinned core key |

All integers are big-endian. The signed transcript is `elx-lease-accept-v1\n` followed by the lowercase hexadecimal UTF-8 bytes of the Control challenge, newline, lowercase hexadecimal UTF-8 subscription identifier, newline and lowercase hexadecimal 88-byte record. The nonce must be single-use on the Control side. The core does **not** record it as consumed: replay protection belongs to the authenticated journal challenge transaction.

The core refuses to attest if lease enforcement is disabled, the durable policy key is absent, the ticket has not been accepted by its limiter, the monotonic deadline has expired or tripped, the subscription is disabled, the configured rates exceed the accepted Control ticket, or the policy/identity no longer matches the core.

Control must verify both signatures independently: (1) signed usage/pressure from the pinned ElXray and (2) this lease acceptance from **the same core incarnation**, **the same subscription**, **the same fresh nonce** and **the assigned node**. A valid proof cannot be used outside its short lease expiry, should not count as a device HWID, and must never bypass the purchased/FUP budget or the signed reduction barrier.
