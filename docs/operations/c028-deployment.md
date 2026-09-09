# C028 deployment

Install only a bundle authenticated by `tron-release-verify`; never execute files directly from a mirror. The supported release row is Linux x86_64 GNU (`P-LINUX-X64`, `rustlog-v1`).

```sh
tron-release-verify verify --trust-store /etc/tron/release-trust-store.json --manifest release-manifest.dsse.json --bundle bundle --platform P-LINUX-X64 --channel stable --minimum-sequence 1 --verification-time 2026-09-08T12:00:00Z
tron-release-verify install --trust-store /etc/tron/release-trust-store.json --manifest release-manifest.dsse.json --bundle bundle --platform P-LINUX-X64 --channel stable --minimum-sequence 1 --prefix /opt/tron --config-root /etc/tron --receipt /var/lib/tron/install-receipt.json --retained-slots 2 --verification-time 2026-09-08T12:00:00Z
/opt/tron/current/bin/tron-fullnode preflight --deployment-config /etc/tron/current/fullnode.deployment.json --json
systemctl enable --now tron-fullnode.service
/opt/tron/current/bin/tron-fullnode probe --deployment-config /etc/tron/current/fullnode.deployment.json --kind ready
```

Deployment JSON owns release identity, absolute paths, exposure and security policy; HOCON owns chain-compatible settings. Files are root-owned `0644`; data, keystore and external parameter directories are node-owned `0700`. Supply Sapling spend/output files from an operator-controlled source at the configured paths. They are never in a release or image.

Only P2P `18888/tcp+udp` is public. HTTP, gRPC, JSON-RPC, ZeroMQ, Prometheus, backup and admin are loopback by default. Use an authenticated encrypted proxy before any remote exposure.

## Container deployment

The shipped image is a non-root bootstrap image, not an alternate unsigned installation path. `entrypoint.sh` requires the immutable read-only candidate and external trust store on every start. A clean start installs only authenticated candidate bytes. Every later start re-verifies the signed manifest and complete candidate bundle for the requested platform, channel, minimum release sequence, and trusted verification time; requires the authenticated manifest digest, release identity, topology, and inventories to equal the receipt; and only then verifies the installed binary and configuration bytes before mandatory node preflight. Receipt existence alone never authorizes execution. A missing or tampered candidate, relocated or substituted receipt/file, invalid signature threshold, rollback, revocation, or missing operator material stops startup before the node process is executed.

Prepare the directory containing `packaging/container/compose.yaml` with these operator-controlled inputs:

```text
candidate/release-manifest.dsse.json   # signed release manifest
candidate/bundle/**                    # exact immutable published bundle
trust/release-trust-store.json         # external production 2-of-3 release root
trust/snapshot-trust-store.json        # independently provisioned snapshot root
trust/backup-keyring.txt                # authenticated backup keyring
parameters/sapling-spend.params         # exact C006 size/BLAKE2b-512 policy
parameters/sapling-output.params        # exact C006 size/BLAKE2b-512 policy
```

Set `TRON_IMAGE_DIGEST` to the verified OCI manifest digest and set `TRON_VERIFICATION_TIME` to an operator-trusted RFC3339 UTC instant such as `2026-09-08T12:00:00Z`; both variables are mandatory. The verification time is an explicit policy input, not the container clock: obtain it from the operator's trusted time source immediately before each deployment or restart, and refresh it before retrying an install or receipt verification. Never reuse a stale value merely to make an expired or not-yet-valid signing policy pass.

Launch only through `python3 tools/release/c028_compose.py full` for FullNode or `python3 tools/release/c028_compose.py solidity` for SolidityNode, from the prepared directory containing `compose.yaml`. The launcher accepts exactly one mode, constructs the single corresponding profile command, and rejects zero, multiple, unknown, or conflicting `COMPOSE_PROFILES` input before invoking Docker. Do not invoke profiles directly or name a service on the command line. Each supported launch selects exactly its one node service, mounts that mode's separate `/opt/tron`, `/etc/tron`, and `/var/lib/tron` named volumes, and cannot publish the other mode's ports. The entrypoint also rejects a raw `COMPOSE_PROFILES=full,solidity` injection before authentication, installation mutation, or node start. Compose bind-mounts the candidate and every trust/parameter input read-only.

Missing or non-canonical `TRON_VERIFICATION_TIME` is rejected by the entrypoint before it examines or mutates installation volumes. Calendar-invalid or policy-invalid timestamps are rejected by `tron-release-verify` before installation publication. Treat changing this value like changing a release trust-policy input: record the chosen instant with deployment evidence and use the same reviewed value for every start.

Do not copy a trust store from `candidate/`, make the candidate writable, or pre-populate `/opt/tron/current`. To upgrade, replace `candidate/` atomically with another externally verified immutable publication, refresh `TRON_VERIFICATION_TIME`, and raise `TRON_MINIMUM_RELEASE_SEQUENCE` when policy requires it; the installer activates the signed release ID into a new slot.
