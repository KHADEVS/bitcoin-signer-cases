"""Runs every case through SeedSigner's own PSBT code and prints what the device does.

The adapter follows the path of the signing flow in seedsigner/views/psbt_views.py:
the fingerprint check that picks the seed, PSBTParser (any exception there is a
refusal before review), the review totals and warnings, then sign_with() and the
signature count the flow uses to decide whether signing did anything.

Usage: python -I adapters/seedsigner_adapter.py <seedsigner checkout> <cases dir>
Needs the embit version SeedSigner pins in requirements.txt.
"""

import json
import sys
from base64 import b64decode
from pathlib import Path


def run_case(case, PSBT, PSBTParser, Seed, network):
    psbt = PSBT.parse(b64decode(case["psbt"]))
    seed = Seed(case["wallet"]["mnemonic"].split())

    if not PSBTParser.has_matching_input_fingerprint(psbt=psbt, seed=seed, network=network):
        return {"verdict": "refuse", "stage": "seed selection", "detail": "no input matches the seed"}

    try:
        parser = PSBTParser(p=psbt, seed=seed, network=network)
    except Exception as e:  # the flow routes every parser error to an error screen
        return {"verdict": "refuse", "stage": "review", "detail": "%s: %s" % (type(e).__name__, e)}

    shown = {
        "inputs": parser.verified_input_amount,
        "spend": parser.spend_amount,
        "change": parser.change_amount,
        "fee": parser.fee_amount,
    }
    if parser.op_return_data is not None:
        shown["op_return"] = parser.op_return_data.hex()
    warnings = list(parser.warnings)

    before = PSBTParser.sig_count(psbt)
    try:
        psbt.sign_with(parser.root)
    except Exception as e:
        return {"verdict": "no-signature", "stage": "signing", "detail": "%s: %s" % (type(e).__name__, e),
                "warnings": warnings, "shown": shown}
    if PSBTParser.sig_count(PSBTParser.trim(psbt)) == before:
        return {"verdict": "no-signature", "stage": "signing", "detail": "sign_with added no signature",
                "warnings": warnings, "shown": shown}

    return {"verdict": "warn" if warnings else "sign", "stage": "signed", "warnings": warnings, "shown": shown}


def main():
    checkout, cases_dir = Path(sys.argv[1]), Path(sys.argv[2])
    sys.path.insert(0, str(checkout / "src"))

    from embit.psbt import PSBT
    from seedsigner.models.psbt_parser import PSBTParser
    from seedsigner.models.seed import Seed
    from seedsigner.models.settings_definition import SettingsConstants

    networks = {"testnet": SettingsConstants.TESTNET, "mainnet": SettingsConstants.MAINNET}
    results = {}
    for path in sorted(cases_dir.glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        results[case["id"]] = run_case(case, PSBT, PSBTParser, Seed, networks[case["wallet"]["network"]])
    sys.stdout.reconfigure(newline="\n")
    json.dump(results, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
