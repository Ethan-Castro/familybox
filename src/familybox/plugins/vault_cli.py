"""Command line for the encrypted home folder (operators; families use the box page).

  familybox vault status
  familybox vault encrypt --seal-to <laptop public key>   move a box set up before encryption (box stopped)
  familybox vault lock                                     close the encrypted folder, as a power cut would
  familybox vault setup-code --seal-to <key>               a new setup code for the box's sticker

Secrets these print (the recovery key, the setup code) are sealed to the operator's laptop key, so a
remote command's job log never holds them. scripts/vault_seal_key.py makes that key and opens the output.
"""

from __future__ import annotations

from .. import vault as vaultmod


def cli(sub) -> None:
    p = sub.add_parser("vault", help="the encrypted home folder")
    ps = p.add_subparsers(dest="vault_action", required=True)
    ps.add_parser("status")
    e = ps.add_parser("encrypt")
    e.add_argument("--seal-to", required=True, help="the operator laptop's public key (base64)")
    ps.add_parser("lock")
    s = ps.add_parser("setup-code")
    s.add_argument("--seal-to", required=True)


def run_cli(args, cfg) -> int | None:
    if args.cmd != "vault":
        return None
    v = vaultmod.Vault(cfg.home)
    act = args.vault_action
    try:
        if act == "status":
            if not v.exists():
                print("no keys: this box was set up before encryption")
            else:
                state = "locked" if v.locked() else ("open" if v.mounted() else "not encrypted")
                print(f"keys: yes; files: {state if v.encrypted() else 'not encrypted'}; "
                      f"unlock phones: {len(v.devices())}; setup code: {'yes' if v.needs_setup_code() else 'no'}")
            return 0
        if act == "encrypt":
            _, code, n = vaultmod.encrypt_existing(cfg.home, cfg.name, v)
            print(f"encrypted {n} files. Recovery key, sealed for the operator's laptop:")
            print(vaultmod.seal(args.seal_to, code))
            return 0
        if act == "lock":
            v.close()
            print("locked" if v.locked() else "not encrypted, nothing to lock")
            return 0
        if act == "setup-code":
            code = vaultmod.new_setup_code()
            v.set_setup_code(code)
            print("setup code, sealed for the operator's laptop:")
            print(vaultmod.seal(args.seal_to, code))
            return 0
    except vaultmod.VaultError as e:
        print(f"stopped: {e}")
        return 2
    return None
