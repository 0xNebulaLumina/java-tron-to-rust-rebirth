# C028 secure transport

TRON P2P is the sole permitted public plaintext exception. **Do not publish HTTP, gRPC, JSON-RPC, ZeroMQ, Prometheus, admin, or backup directly.** Loopback plaintext is acceptable only when the host boundary is trusted.

Terminate mutually authenticated TLS in a separately managed proxy, bind the node upstream to `127.0.0.1`, restrict source identities and routes, enforce request/body/deadline limits, and rotate proxy keys independently of release trust roots. Preserve client identity in audited proxy metadata without logging credentials or private keys.

Witness backup traffic additionally requires the HMAC-SHA256-v1 envelope, replay window and rotating keyring, even inside a private authenticated tunnel. HMAC authenticates messages; it does not provide confidentiality. Never place witness private keys, passwords, backup HMAC keys, release signing keys, snapshot signing keys, or trust anchors in an image, release bundle, HOCON, environment dump, command line or log. Use systemd credentials or an equivalent secret mount.

Fail deployment if `public=true` is used for any plaintext API. Firewall admin `9080`, metrics `9527` and event `5555` to loopback/proxy namespaces.
