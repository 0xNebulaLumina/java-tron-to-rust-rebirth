#!/usr/bin/env python3
"""Strict parser for C021Oracle's authenticated raw application captures."""
REQUIRED_CLASSES = {
    "org.tron.core.net.message.TronMessageFactory",
    "org.tron.core.net.message.handshake.HelloMessage",
    "org.tron.core.net.peer.PeerConnection",
    "org.tron.core.net.service.sync.SyncService",
    "org.tron.core.net.service.adv.AdvService",
    "org.tron.core.net.service.relay.RelayService",
    "org.tron.core.net.messagehandler.SyncBlockChainMsgHandler",
    "org.tron.core.net.messagehandler.ChainInventoryMsgHandler",
    "org.tron.core.net.messagehandler.InventoryMsgHandler",
    "org.tron.core.net.messagehandler.FetchInvDataMsgHandler",
    "org.tron.core.net.messagehandler.TransactionsMsgHandler",
    "org.tron.core.net.messagehandler.BlockMsgHandler",
    "org.tron.core.net.messagehandler.PbftMsgHandler",
}
import hashlib

def parse(stdout: str) -> dict[str, dict[str, object]]:
    captures = {}
    for line in stdout.splitlines():
        if not line.endswith(tuple("0123456789abcdef")) or "_HEX=" not in line:
            continue
        name, value = line.split("=", 1)
        try:
            body = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"invalid C021 capture {name}") from exc
        captures[name.removesuffix("_HEX").lower()] = {
            "hex": value, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()
        }
    if "C021_ORACLE_OK" not in stdout:
        raise ValueError("C021 oracle completion marker missing")
    classes = {line.removeprefix("CLASS=") for line in stdout.splitlines() if line.startswith("CLASS=")}
    if classes != REQUIRED_CLASSES:
        raise ValueError(f"C021 production class evidence mismatch: {sorted(classes ^ REQUIRED_CLASSES)}")
    return captures
