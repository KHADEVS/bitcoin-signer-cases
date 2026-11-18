# Bitcoin signer cases

PSBTs built the way a hostile coordinator would build them, and a harness that runs each one through the real PSBT code of a signing device to record what the device does: refuse it, warn, or sign it and show the user some amounts. The same cases run against every signer, so the results line up in one table.

The first two signers are [SeedSigner](https://github.com/SeedSigner/seedsigner) and [Krux](https://github.com/selfcustody/krux). Both are open-source firmware written in Python on top of [embit](https://github.com/diybitcoinhardware/embit), so their own parsers can run unchanged on a desktop.

**Results: [results/MATRIX.md](results/MATRIX.md).**

## Why

The coordinator, the software on a computer that builds the PSBT, is the part a signing device is there to distrust. Most of what a PSBT says about inputs, change and keys is a claim the device has to check against the seed or against what the signature commits to. The ways those checks go wrong are well known and keep coming back: fee lies on inputs whose amounts the sighash does not commit, change that carries our key in its metadata but pays someone else, signatures whose sighash leaves the outputs open.

Signer projects fix these one at a time, each with its own tests. Since September 2026, SeedSigner has merged eleven pull requests into its PSBT parser, Krux five into its PSBT code and vendored embit, and Krux's embit fork thirteen more. A shared corpus lets each project check itself against what the others have already learned, and catches the same mistake when it comes back.

## What a case holds

Each file in `cases/` is one PSBT and what is expected of a signer that gets it.

| Field | Content |
| --- | --- |
| `psbt` | The PSBT, base64 |
| `wallet` | The seed (the BIP-39 test mnemonic), network, script type and account the device signs with |
| `attack` | What the coordinator is trying to do |
| `rule` | What a signer should do about it |
| `level` | `must` when failing means a loss the user cannot see on the screen, `should` for weaker protection, `baseline` for honest PSBTs |
| `acceptable` | The verdicts that pass: `refuse` (before the review), `warn`, `sign`, `no-signature` (the user approves but no signature comes out) |
| `honest_view` | The amounts an honest review shows: inputs, spend, change, fee |
| `refs` | The BIPs and write-ups behind the rule |

`gen/gen.py` writes all of them, deterministically. Every case is on testnet and every coin in them is made up.

## Cases

| Case | What the coordinator does |
| --- | --- |
| `baseline-p2wpkh`, `baseline-p2tr`, `baseline-p2pkh` | Nothing: an honest spend with change, which must sign |
| `legacy-input-without-prev-tx` | Understates a legacy input and leaves out the transaction that would prove it |
| `prev-tx-does-not-hash-to-prevout` | Attaches the wrong previous transaction |
| `witness-utxo-disagrees-with-prev-tx` | Gives a witness UTXO that contradicts the previous transaction |
| `segwit-v0-inputs-without-prev-tx` | Sends two segwit v0 inputs with nothing proving their amounts (BIP-143 only commits each signature to its own input) |
| `outputs-exceed-inputs` | Builds outputs worth more than the inputs |
| `sighash-none`, `sighash-single-anyonecanpay` | Asks for a signature that leaves the outputs open |
| `change-paid-to-foreign-key` | Labels a payment to someone else with our key and change path |
| `taproot-change-with-hidden-script-path` | Pays our taproot key tweaked with a script path only the attacker can use |
| `change-in-other-script-type` | Sends the change to our key in a script type the wallet does not watch |
| `change-in-another-account` | Sends the change to another account of the same seed |
| `op-return-with-value` | Burns 300,000 sats in an OP_RETURN output |

## Grading

A signer passes a case when its verdict is one of the case's acceptable verdicts and, whenever it shows the user a review (`sign` or `warn`), the spend, change and fee on that review are the honest ones. A refusal always counts as safe; whether it is also convenient is not graded.

## How the adapters work

The adapters call the signers' own code at a pinned commit. They do not reimplement it. Each follows the device's signing flow as its source reads:

- `adapters/seedsigner_adapter.py` follows `seedsigner/views/psbt_views.py`: the fingerprint check that selects the seed, `PSBTParser` (an exception there is a refusal), the totals and warnings the review screens get, then `sign_with()` and the signature count the flow uses to tell whether signing did anything.
- `adapters/krux_adapter.py` follows `Home.sign_psbt()` in `src/krux/pages/home_pages/home.py`: `PSBTSigner` (an exception there is a refusal), the warnings shown before the review, the classification behind `outputs()`, then `sign()`. Krux's hardware modules are replaced with the stand-ins its own test suite uses.

What this does not cover: the code runs on CPython, not on the device, and the amounts are read from the objects the screens are built from, not from the screens. A difference between those and what the display draws would not show up here.

## Running

```
pip install -r requirements.txt              # embit 0.8.0, as SeedSigner pins it
python -I gen/gen.py                         # write cases/

python -I adapters/seedsigner_adapter.py <seedsigner checkout> cases > results/seedsigner-dev.json
python -I adapters/krux_adapter.py <krux checkout> cases > results/krux-develop.json
python -I report.py                          # write results/MATRIX.md
```

Run each adapter in its own environment: SeedSigner uses embit from PyPI, Krux its vendored copy (`git submodule update --init vendor/embit`; the Krux environment needs `pyqrcode` for the test stand-ins). `results/targets.json` names the commits. CI checks out those commits, rebuilds the cases and the results, and fails if anything differs from what is committed.

## Next

- Multisig: change to a multisig with a swapped cosigner, inputs from two different multisigs, a descriptor that does not match the PSBT.
- PSBTv2 fields, taproot script-path spends, MuSig2 and silent payments as signers add them.
- More signers. Devices with an emulator (Trezor, BitBox02, Coldcard, Ledger) can run the same cases through HWI.

## Reporting

A case that shows a problem nobody has reported yet is sent to the signer's maintainers privately first, and appears here only once they know about it. The notes in [results/MATRIX.md](results/MATRIX.md) say, for each failure in the current results, where it is already tracked or when it was reported.

## License

MIT
