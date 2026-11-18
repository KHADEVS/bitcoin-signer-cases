"""Runs every case through Krux's own PSBT code and prints what the device does.

Krux is MicroPython firmware. Its hardware modules are replaced with the same stand-ins
Krux's own test suite uses (tests/conftest.py, tests/shared_mocks.py), and embit is
the copy Krux vendors. The adapter then follows Home.sign_psbt() in
src/krux/pages/home_pages/home.py: PSBTSigner (any exception is a refusal before
review), the warnings shown before the review, the review totals from outputs(), then
sign().

Usage: python -I adapters/krux_adapter.py <krux checkout> <cases dir>
"""

import json
import random
import sys
import time
import types
from base64 import b64decode
from pathlib import Path
from unittest import mock

FEE_WARNING_PERCENT = 10.0  # Home._fees_psbt_warn


def install_stand_ins(checkout: Path):
    sys.path.insert(0, str(checkout / "vendor" / "embit" / "src"))
    sys.path.insert(0, str(checkout / "src"))
    sys.path.insert(0, str(checkout))

    from embit.util import secp256k1
    from tests import shared_mocks as sm

    # The native BC-UR extension is only reached for UR input; cases are raw bytes.
    uur = types.ModuleType("uUR")

    class UR:
        pass

    uur.UR = UR
    uur.Types = mock.MagicMock()

    stand_ins = {
        "uUR": uur,
        "qrcode": mock.MagicMock(encode_to_string=sm.encode_to_string, encode=sm.encode),
        "secp256k1": mock.MagicMock(wraps=secp256k1),
        "urandom": random,
        "flash": mock.MagicMock(),
        "machine": mock.MagicMock(),
        "sensor": mock.MagicMock(),
        "lcd": mock.MagicMock(),
        "Maix": mock.MagicMock(),
        "fpioa_manager": mock.MagicMock(),
        "pmu": mock.MagicMock(),
        "image": mock.MagicMock(),
        "ucryptolib": mock.MagicMock(),
        "shannon": mock.MagicMock(),
        "uos": mock.MagicMock(statvfs=sm.statvfs),
        "deflate": mock.MagicMock(DeflateIO=sm.DeflateIO),
        "uhashlib_hw": mock.MagicMock(),
        "base32": mock.MagicMock(decode=sm.base32_decode, encode=sm.base32_encode),
        "base43": mock.MagicMock(decode=sm.base43_decode, encode=sm.base43_encode),
        "ujson": json,
        "board": sm.board_m5stickv(),
    }
    sys.modules.update(stand_ins)
    time.sleep_ms = lambda *_: None
    time.ticks_ms = lambda: 1
    sys.print_exception = lambda *_: None


def run_case(case, k):
    wallet = k.Wallet(
        k.Key(
            case["wallet"]["mnemonic"],
            k.TYPE_SINGLESIG,
            k.NETWORKS["test" if case["wallet"]["network"] == "testnet" else "main"],
            script_type=case["wallet"]["script_type"],
        )
    )
    try:
        signer = k.PSBTSigner(wallet, b64decode(case["psbt"]), k.FORMAT_NONE)
    except Exception as e:
        return {"verdict": "refuse", "stage": "load", "detail": "%s: %s" % (type(e).__name__, e)}

    warnings = []
    try:
        if signer.path_mismatch():
            warnings.append("path_mismatch")
        if wallet.key.fingerprint != b"\x00\x00\x00\x00" and signer.fill_zero_fingerprint():
            warnings.append("fingerprint_unset")

        # Record how outputs() classifies each output, so the totals below are the ones
        # the review screens are built from.
        classified = []
        original = signer._classify_output

        def recording(out_policy, out):
            kind = original(out_policy, out)
            classified.append(kind)
            return kind

        signer._classify_output = recording
        _, fee_percent = signer.outputs()
    except Exception as e:
        return {"verdict": "refuse", "stage": "review", "detail": "%s: %s" % (type(e).__name__, e)}

    if signer.unverified_input_amounts():
        warnings.append("unverified_input_amounts")
    if fee_percent >= FEE_WARNING_PERCENT:
        warnings.append("high_fee")

    vout = signer.psbt.tx.vout
    inputs = sum(inp.utxo.value for inp in signer.psbt.inputs)
    spend = sum(o.value for o, kind in zip(vout, classified) if kind == k.SPEND)
    change = sum(o.value for o, kind in zip(vout, classified) if kind != k.SPEND)
    shown = {"inputs": inputs, "spend": spend, "change": change, "fee": inputs - sum(o.value for o in vout)}

    try:
        signer.sign()
    except Exception as e:
        return {"verdict": "no-signature", "stage": "signing", "detail": "%s: %s" % (type(e).__name__, e),
                "warnings": warnings, "shown": shown}

    return {"verdict": "warn" if warnings else "sign", "stage": "signed", "warnings": warnings, "shown": shown}


def main():
    checkout, cases_dir = Path(sys.argv[1]), Path(sys.argv[2])
    install_stand_ins(checkout)

    from embit.networks import NETWORKS
    from krux.key import TYPE_SINGLESIG, Key
    from krux.psbt import SPEND, PSBTSigner
    from krux.qr import FORMAT_NONE
    from krux.wallet import Wallet

    k = types.SimpleNamespace(NETWORKS=NETWORKS, TYPE_SINGLESIG=TYPE_SINGLESIG, Key=Key, SPEND=SPEND,
                              PSBTSigner=PSBTSigner, FORMAT_NONE=FORMAT_NONE, Wallet=Wallet)
    results = {}
    for path in sorted(cases_dir.glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        results[case["id"]] = run_case(case, k)
    sys.stdout.reconfigure(newline="\n")
    json.dump(results, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
