"""Runs every case on a Trezor emulator through HWI and prints what the device does.

HWI turns the PSBT into Trezor's signing messages, as it does for Bitcoin Core, Specter
or Nunchuk users. Trezor then shows its own screens. A driver on the debug link reads each
screen before confirming it (HWI's own automatic confirmation is turned off), so the
recorded amounts are the ones the device displayed.

A signature only counts when it is valid for the PSBT's own transaction. Trezor rebuilds
the scripts of outputs it treats as change from their derivation paths, so a PSBT whose
change metadata lies gets a signature for a different transaction, which the attacker
cannot use.

Needs a running emulator with its debug link (UDP 21324/21325), HWI and trezorlib, and
embit to check signatures. The device is loaded with the case seed if it is empty.

Usage: python adapters/trezor_adapter.py <cases dir>
"""

import json
import re
import sys
import threading
import time
from decimal import Decimal
from pathlib import Path

import hwilib.devices.trezorlib.debuglink as hwi_debuglink

# HWI drives emulators through a debug client that presses "yes" on every screen.
# Here it only acknowledges; the driver below reads each screen first.
hwi_debuglink.DebugUI.button_request = lambda self, br: None

from embit.ec import PublicKey, SchnorrSig, Signature  # noqa: E402
from embit.psbt import PSBT  # noqa: E402
from hwilib.common import Chain  # noqa: E402
from hwilib.devices.trezor import TrezorClient as HwiTrezor  # noqa: E402
from hwilib.psbt import PSBT as HwiPSBT  # noqa: E402
from trezorlib.debuglink import DebugLink, TrezorTestContext, load_device  # noqa: E402
from trezorlib.transport import get_transport  # noqa: E402

DEVICE = "udp:127.0.0.1:21324"
DEBUG = "udp:127.0.0.1:21325"
LABEL = "cases"
TIMEOUT = 60
WARNING_WORDS = ("warning", "unusual", "unexpectedly", "wrong", "unknown", "not recognized", "caution")


def ensure_loaded(mnemonic):
    ctx = TrezorTestContext(get_transport(DEVICE))
    if not ctx.features.initialized:
        load_device(ctx.get_seedless_session(), mnemonic=mnemonic, pin=None,
                    passphrase_protection=False, label=LABEL)
    ctx.transport.close()


def sats(text):
    """'0.006 TEST' -> 600000."""
    m = re.search(r"([0-9][0-9,]*(?:\.[0-9]+)?)\s*(?:TEST|tBTC|BTC|REGTEST)", text)
    return int(Decimal(m.group(1).replace(",", "")) * 100_000_000) if m else None


class Driver(threading.Thread):
    """Reads every new screen, records it, then confirms it (holding, for screens that
    need a hold). Transitions, progress screens and the homescreen are not touched."""

    def __init__(self, debug):
        super().__init__(daemon=True)
        self.debug, self.screens, self.stop = debug, [], threading.Event()

    def run(self):
        last = None
        while not self.stop.is_set():
            try:
                lay = self.debug.read_layout()
                title, content = lay.title(), lay.screen_content()
            except Exception:
                time.sleep(0.1)
                continue
            key = (title, content)
            idle = (title == "" and content.strip() in (LABEL, "no main component", "Progress", ""))
            if key != last:
                last = key
                if not idle:
                    self.screens.append({"title": title.replace("\n", " "), "text": " ".join(content.split())})
                    self.debug.press_yes(hold_ms=1500)
                    continue
            time.sleep(0.1)


def valid_signatures(signed_b64):
    """Returns the sighash types of the signatures in the PSBT that verify against its
    own transaction, with each input's amount taken from its previous transaction
    whenever the PSBT carries one that hashes to the outpoint: that is the amount the
    network checks, whatever the witness UTXO claims."""
    psbt = PSBT.from_string(signed_b64)
    for inp, txin in zip(psbt.inputs, psbt.tx.vin):
        prev = inp.non_witness_utxo
        # segwit inputs only: a legacy input with a witness UTXO would be hashed as segwit
        if inp.witness_utxo is not None and prev is not None and prev.txid() == txin.txid \
                and txin.vout < len(prev.vout):
            inp.witness_utxo = prev.vout[txin.vout]
    good = []
    for i, inp in enumerate(psbt.inputs):
        for pub, sig in inp.partial_sigs.items():
            der, sighash = sig[:-1], sig[-1]
            if pub.verify(Signature.parse(der), psbt.sighash(i, sighash=sighash)):
                good.append(sighash)
        # embit 0.8.0 leaves PSBT_IN_TAP_KEY_SIG (0x13) among the unknown keys
        sig = getattr(inp, "taproot_key_sig", None) or inp.unknown.get(b"\x13")
        if sig:
            sighash = sig[64] if len(sig) == 65 else 0
            output_key = PublicKey.from_xonly(inp.utxo.script_pubkey.data[2:34])
            if output_key.schnorr_verify(SchnorrSig.parse(sig[:64]), psbt.sighash(i, sighash=sighash)):
                good.append(sighash)
    return sorted(set(good))


def run_case(case, debug):
    psbt = HwiPSBT()
    try:
        psbt.deserialize(case["psbt"])
    except Exception as e:  # HWI will not even load it
        return {"verdict": "refuse", "stage": "host (HWI)", "detail": "%s: %s" % (type(e).__name__, e),
                "warnings": [], "screens": []}
    driver = Driver(debug)
    driver.start()
    outcome = {}

    def sign():
        try:
            client = HwiTrezor(DEVICE, chain=Chain.TEST)
            outcome["psbt"] = client.sign_tx(psbt)
        except Exception as e:  # HWI or the device refused
            outcome["error"] = "%s: %s" % (type(e).__name__, e)
            outcome["by_device"] = type(e).__name__ == "TrezorFailure"

    worker = threading.Thread(target=sign, daemon=True)
    worker.start()
    worker.join(TIMEOUT)
    time.sleep(0.5)
    driver.stop.set()
    driver.join(2)
    screens = driver.screens
    if worker.is_alive():
        return {"verdict": "no-signature", "stage": "signing", "detail": "timed out", "screens": screens}

    spend = sum(sats(s["text"]) or 0 for s in screens if s["title"].startswith("Amount"))
    fee = next((sats(s["text"].split("fee", 1)[1]) for s in screens
                if s["title"] == "Summary" and "fee" in s["text"]), None)
    warnings = [s["title"] or s["text"] for s in screens
                if any(w in (s["title"] + " " + s["text"]).lower() for w in WARNING_WORDS)]
    shown = None
    if fee is not None:
        outputs = sum(o.nValue for o in psbt.tx.vout)
        shown = {"inputs": outputs + fee, "spend": spend, "change": outputs - spend, "fee": fee}

    result = {"warnings": warnings, "screens": screens}
    if shown:
        result["shown"] = shown
    if "error" in outcome:
        # The device refusing, or HWI failing to give the device what it asked for
        # (a previous transaction, say) after the user confirmed: nothing is signed.
        stage = "device" if outcome["by_device"] else "host (HWI)"
        result.update(verdict="refuse" if not screens or outcome["by_device"] else "no-signature",
                      stage=stage, detail=outcome["error"])
        return result
    sighashes = valid_signatures(outcome["psbt"].serialize())
    if not sighashes:
        result.update(verdict="no-signature", stage="signing",
                      detail="no signature valid for the PSBT's transaction")
    else:
        result.update(verdict="warn" if warnings else "sign", stage="signed", sighashes=sighashes)
    return result


def main():
    cases_dir = Path(sys.argv[1])
    cases = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(cases_dir.glob("*.json"))]
    ensure_loaded(cases[0]["wallet"]["mnemonic"])
    debug = DebugLink(get_transport(DEBUG))
    debug.open()
    results = {}
    for case in cases:
        results[case["id"]] = run_case(case, debug)
        print("%-44s %s" % (case["id"], results[case["id"]]["verdict"]), file=sys.stderr, flush=True)
    sys.stdout.reconfigure(newline="\n")
    json.dump(results, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
