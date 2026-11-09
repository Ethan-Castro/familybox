"""NEAR anchoring for the tamper-evident logs: put each person's chain head on the NEAR blockchain.

What goes on-chain, per person: the box id (random, made on the box), a salted hash of the person's
id (the salt never leaves the box, so nobody can tell whose log it is), the chain head hash and the
number of entries. No names, no questions, no answers, no file names.

The box signs with a function-call access key that can only call anchor() on the anchor contract and
cannot move money. Without NEAR_ACCOUNT_ID and a key the client stays in dry-run: it builds and prints
the exact call it would send and touches no network. See docs/ANCHOR.md.

The transaction is encoded with Borsh and signed with ed25519 exactly as NEAR expects
(signature over sha256 of the encoded Transaction), then sent with the send_tx JSON-RPC method.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path

import httpx

DEFAULT_GAS = 30 * 10**12          # 30 Tgas; anchor() needs far less
RPC_DEFAULTS = {"testnet": "https://rpc.testnet.near.org", "mainnet": "https://rpc.mainnet.near.org"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BOX_ID = re.compile(r"^[a-z0-9_-]{3,64}$")
ACCOUNT_ID = re.compile(r"^(?=.{2,64}$)(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$")


class AnchorError(Exception):
    pass


# --- base58 (NEAR keys and block hashes) ---------------------------------------------------------

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        i = _B58.find(ch)
        if i < 0:
            raise AnchorError("not base58")
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(text) - len(text.lstrip("1"))
    return b"\0" * pad + body


# --- the box's anchor identity: box id + salt, kept on the box only ------------------------------

def identity_path(runtime: Path) -> Path:
    return runtime / "ledger" / "anchor_id.json"


def load_identity(runtime: Path, *, create: bool = True) -> dict:
    """{"box_id", "salt"}. Made once per box (0600). Losing it only means new person hashes on-chain."""
    path = identity_path(runtime)
    if path.exists():
        try:
            d = json.loads(path.read_text())
            ok = (isinstance(d, dict) and isinstance(d.get("box_id"), str) and BOX_ID.match(d["box_id"])
                  and isinstance(d.get("salt"), str) and len(bytes.fromhex(d["salt"])) >= 16)
        except (OSError, ValueError) as e:
            raise AnchorError(f"the box's anchor id file ({path}) cannot be read: {e}") from None
        if not ok:
            raise AnchorError(f"the box's anchor id file ({path}) is damaged")
        return d
    if not create:
        raise AnchorError("this box has no anchor id yet")
    d = {"box_id": "fb-" + secrets.token_hex(10), "salt": secrets.token_hex(32)}
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    return d


def person_hash(identity: dict, person_id: str) -> str:
    """Salted hash of a person id. Without the box's salt nobody can link it to a name."""
    msg = f"familybox-person-v1|{identity['box_id']}|{person_id}".encode()
    return hmac.new(bytes.fromhex(identity["salt"]), msg, hashlib.sha256).hexdigest()


# --- settings ------------------------------------------------------------------------------------

@dataclass
class Settings:
    network: str
    rpc_url: str
    contract: str | None
    account_id: str | None
    private_key: str | None      # "ed25519:<base58 of 64-byte secret>", never printed

    @property
    def live_ready(self) -> bool:
        return bool(self.contract and self.account_id and self.private_key)

    def missing(self) -> list[str]:
        out = []
        if not self.account_id:
            out.append("NEAR_ACCOUNT_ID")
        if not self.private_key:
            out.append("a key (familybox anchor keygen, or NEAR_ANCHOR_PRIVATE_KEY)")
        if not self.contract:
            out.append("NEAR_ANCHOR_CONTRACT")
        return out


def key_path(runtime: Path) -> Path:
    return runtime / "ledger" / "near_key.json"


def settings(runtime: Path, env: dict | None = None) -> Settings:
    env = os.environ if env is None else env
    network = env.get("NEAR_NETWORK", "testnet")
    if network not in RPC_DEFAULTS:
        raise AnchorError("NEAR_NETWORK must be testnet or mainnet")
    key = env.get("NEAR_ANCHOR_PRIVATE_KEY") or None
    if not key and key_path(runtime).exists():
        key = _read_key_file(runtime)
    account = env.get("NEAR_ACCOUNT_ID") or None
    contract = env.get("NEAR_ANCHOR_CONTRACT") or None
    for label, v in (("NEAR_ACCOUNT_ID", account), ("NEAR_ANCHOR_CONTRACT", contract)):
        if v and not ACCOUNT_ID.match(v):
            raise AnchorError(f"{label} is not a valid NEAR account id")
    return Settings(network, env.get("NEAR_RPC_URL", RPC_DEFAULTS[network]), contract, account, key)


# --- keys ----------------------------------------------------------------------------------------

def _read_key_file(runtime: Path) -> str:
    path = key_path(runtime)
    try:
        d = json.loads(path.read_text())
        key = d["private_key"] if isinstance(d, dict) else None
    except (OSError, ValueError, KeyError) as e:
        raise AnchorError(f"the box's anchoring key file ({path}) cannot be read: {e}") from None
    if not isinstance(key, str):
        raise AnchorError(f"the box's anchoring key file ({path}) is damaged")
    return key


def _signing_key(private_key: str):
    from nacl.signing import SigningKey
    if not private_key.startswith("ed25519:"):
        raise AnchorError("only ed25519 keys are supported")
    raw = b58decode(private_key.split(":", 1)[1])
    if len(raw) not in (32, 64):
        raise AnchorError("the key is not a NEAR ed25519 secret key")
    sk = SigningKey(raw[:32])
    if len(raw) == 64 and bytes(sk.verify_key) != raw[32:]:
        raise AnchorError("the key's public half does not match its secret half")
    return sk


def public_key_of(private_key: str) -> str:
    return "ed25519:" + b58encode(bytes(_signing_key(private_key).verify_key))


def keygen(runtime: Path, *, force: bool = False) -> str:
    """Make the box's anchoring key (0600) and return its public key. The secret is never printed."""
    from nacl.signing import SigningKey
    path = key_path(runtime)
    if path.exists() and not force:
        return public_key_of(_read_key_file(runtime))
    sk = SigningKey.generate()
    secret = "ed25519:" + b58encode(bytes(sk) + bytes(sk.verify_key))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"private_key": secret}, f)
    os.replace(tmp, path)
    return public_key_of(secret)


# --- the call ------------------------------------------------------------------------------------

def anchor_args(box_id: str, p_hash: str, head_hash: str, count: int) -> dict:
    if not BOX_ID.match(box_id):
        raise AnchorError("bad box id")
    if not HEX64.match(p_hash) or not HEX64.match(head_hash):
        raise AnchorError("hashes must be 64 lowercase hex characters")
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise AnchorError("count must be a positive whole number")
    return {"box_id": box_id, "person_hash": p_hash, "head_hash": head_hash, "count": count}


def args_bytes(args: dict) -> bytes:
    return json.dumps(args, separators=(",", ":"), sort_keys=True).encode()


def plan(s: Settings, args: dict, *, gas: int = DEFAULT_GAS) -> dict:
    """The transaction the box would send, in plain JSON. Nonce and block hash come from the network."""
    ab = args_bytes(args)
    return {
        "network": s.network,
        "rpc": s.rpc_url,
        "signer_id": s.account_id or "(not set: NEAR_ACCOUNT_ID)",
        "public_key": public_key_of(s.private_key) if s.private_key else "(no key yet: familybox anchor keygen)",
        "receiver_id": s.contract or "(not set: NEAR_ANCHOR_CONTRACT)",
        "actions": [{"FunctionCall": {"method_name": "anchor", "args": args,
                                      "args_base64": base64.b64encode(ab).decode(),
                                      "gas": gas, "deposit": "0"}}],
        "nonce": "(access key nonce + 1, read from the network when sending)",
        "block_hash": "(latest final block, read from the network when sending)",
    }


# --- Borsh encoding (only what a FunctionCall transaction needs) ----------------------------------

def _u32(n: int) -> bytes:
    return struct.pack("<I", n)


def _u64(n: int) -> bytes:
    return struct.pack("<Q", n)


def _u128(n: int) -> bytes:
    return n.to_bytes(16, "little")


def _string(s: str) -> bytes:
    b = s.encode()
    return _u32(len(b)) + b


def _bytes(b: bytes) -> bytes:
    return _u32(len(b)) + b


def function_call_action(method_name: str, args: bytes, gas: int, deposit: int = 0) -> bytes:
    return bytes([2]) + _string(method_name) + _bytes(args) + _u64(gas) + _u128(deposit)  # 2 = FunctionCall


def encode_transaction_actions(*, signer_id: str, public_key: bytes, nonce: int, receiver_id: str,
                               block_hash: bytes, actions: list[bytes]) -> bytes:
    """Transaction (V0): signer, ed25519 public key, nonce, receiver, block hash, Vec<Action>."""
    if len(public_key) != 32 or len(block_hash) != 32:
        raise AnchorError("public key and block hash must be 32 bytes")
    return (_string(signer_id) + bytes([0]) + public_key + _u64(nonce) + _string(receiver_id) + block_hash
            + _u32(len(actions)) + b"".join(actions))


def encode_transaction(*, signer_id: str, public_key: bytes, nonce: int, receiver_id: str, block_hash: bytes,
                       method_name: str, args: bytes, gas: int, deposit: int = 0) -> bytes:
    return encode_transaction_actions(signer_id=signer_id, public_key=public_key, nonce=nonce,
                                      receiver_id=receiver_id, block_hash=block_hash,
                                      actions=[function_call_action(method_name, args, gas, deposit)])


def sign_transaction(tx: bytes, private_key: str) -> bytes:
    """SignedTransaction bytes: the transaction followed by an ed25519 signature over sha256(tx)."""
    sig = _signing_key(private_key).sign(hashlib.sha256(tx).digest()).signature
    return tx + bytes([0]) + sig


def tx_hash(tx: bytes) -> str:
    return b58encode(hashlib.sha256(tx).digest())


# --- JSON-RPC ------------------------------------------------------------------------------------

class Rpc:
    def __init__(self, url: str, http: httpx.Client | None = None, timeout: float = 20.0):
        self.url = url
        self.http = http or httpx.Client(timeout=timeout)

    def call(self, method: str, params) -> dict:
        try:
            r = self.http.post(self.url, json={"jsonrpc": "2.0", "id": "familybox", "method": method,
                                               "params": params})
            r.raise_for_status()
            body = r.json()
        except (httpx.HTTPError, ValueError) as e:
            raise AnchorError(f"could not reach NEAR ({method}): {e}") from None
        if body.get("error"):
            err = body["error"]
            cause = (err.get("cause") or {}).get("name") if isinstance(err, dict) else None
            raise AnchorError(f"NEAR RPC {method} failed: {cause or err.get('message') or err}")
        return body["result"]


def _check_key_permission(perm, contract: str) -> None:
    """Refuse a full-access key: the box should only ever hold a key that can call anchor()."""
    if perm == "FullAccess" or not isinstance(perm, dict) or "FunctionCall" not in perm:
        raise AnchorError("the box's key is a full-access key. Give the box a function-call key that can only "
                          "call anchor() on the anchor contract (see docs/ANCHOR.md)")
    fc = perm["FunctionCall"]
    if fc.get("receiver_id") != contract:
        raise AnchorError("the box's key is for a different contract")
    # An empty list means "any method" on NEAR. The box's key must be limited to anchor() and nothing else.
    if fc.get("method_names") != ["anchor"]:
        raise AnchorError("the box's key must be limited to anchor() only (its allowed methods are "
                          f"{fc.get('method_names') or 'any method'}). See docs/ANCHOR.md")


def send_anchor(s: Settings, args: dict, *, rpc: Rpc | None = None, gas: int = DEFAULT_GAS,
                last_nonce: int | None = None) -> dict:
    """Sign and send anchor(). Returns {"tx_hash", "status", "nonce"}. Needs NEAR_ACCOUNT_ID, a key and the
    contract. When sending several in a row, pass the previous result's nonce as last_nonce: the chain's
    view of the key can lag a block or two behind a transaction that was just sent, and reusing a nonce
    gets the transaction refused."""
    if not s.live_ready:
        raise AnchorError("cannot send yet; missing " + ", ".join(s.missing()))
    rpc = rpc or Rpc(s.rpc_url)
    pub = public_key_of(s.private_key)
    ak = rpc.call("query", {"request_type": "view_access_key", "finality": "optimistic",
                            "account_id": s.account_id, "public_key": pub})
    _check_key_permission(ak.get("permission"), s.contract)
    nonce = int(ak["nonce"]) + 1
    if last_nonce is not None:
        nonce = max(nonce, int(last_nonce) + 1)
    block = rpc.call("block", {"finality": "final"})
    tx = encode_transaction(signer_id=s.account_id, public_key=b58decode(pub.split(":", 1)[1]),
                            nonce=nonce, receiver_id=s.contract,
                            block_hash=b58decode(block["header"]["hash"]), method_name="anchor",
                            args=args_bytes(args), gas=gas, deposit=0)
    signed = sign_transaction(tx, s.private_key)
    res = rpc.call("send_tx", {"signed_tx_base64": base64.b64encode(signed).decode(),
                               "wait_until": "EXECUTED_OPTIMISTIC"})
    status = (res or {}).get("status") or {}
    if isinstance(status, dict) and "Failure" in status:
        raise AnchorError(f"the anchor transaction failed on-chain: {json.dumps(status['Failure'])[:300]}")
    return {"tx_hash": tx_hash(tx), "status": "sent", "nonce": nonce}


def view_box(s: Settings, box_id: str, *, rpc: Rpc | None = None) -> dict | None:
    """The contract's get_box(box_id) view: {"writer", ...} or None if the box id is not registered."""
    if not s.contract:
        raise AnchorError("NEAR_ANCHOR_CONTRACT is not set")
    rpc = rpc or Rpc(s.rpc_url)
    args = base64.b64encode(args_bytes({"box_id": box_id})).decode()
    res = rpc.call("query", {"request_type": "call_function", "finality": "final", "account_id": s.contract,
                             "method_name": "get_box", "args_base64": args})
    return json.loads(bytes(res["result"]).decode() or "null")


def view_anchor(s: Settings, box_id: str, p_hash: str, *, rpc: Rpc | None = None) -> dict | None:
    """The contract's get(box_id, person_hash) view: the latest anchored head, or None."""
    if not s.contract:
        raise AnchorError("NEAR_ANCHOR_CONTRACT is not set")
    rpc = rpc or Rpc(s.rpc_url)
    args = base64.b64encode(args_bytes({"box_id": box_id, "person_hash": p_hash})).decode()
    res = rpc.call("query", {"request_type": "call_function", "finality": "final", "account_id": s.contract,
                             "method_name": "get", "args_base64": args})
    return json.loads(bytes(res["result"]).decode() or "null")
