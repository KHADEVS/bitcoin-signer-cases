# Bitcoin signer cases

PSBTs built the way a hostile coordinator would build them, and a harness that runs each one through the real PSBT code of a signing device to record what the device does: refuse it, warn, or sign it and show the user some amounts. The same cases run against every signer, so the results line up in one table.

The signers so far:

- [SeedSigner](https://github.com/SeedSigner/seedsigner) and [Krux](https://github.com/selfcustody/krux), open-source firmware written in Python on top of [embit](https://github.com/diybitcoinhardware/embit), so their own parsers run unchanged on a desktop;
- [BDK](https://github.com/bitcoindevkit/bdk_wallet), the wallet library many software wallets are built on, in three ways: `Wallet::sign` as released in 3.2.0, `bitcoin::Psbt::sign` on its own (what the 3.2.0 deprecation note points to), and `Psbt::sign` after the checks that [bdk_wallet#647](https://github.com/bitcoindevkit/bdk_wallet/pull/647) proposes for 4.0;
- [Trezor](https://github.com/trezor/trezor-firmware) Safe 5, on Trezor's own emulator build of firmware 2.13.1, driven through [HWI](https://github.com/bitcoin-core/HWI) as Bitcoin Core, Specter or Nunchuk users drive it, with the amounts read from the device's screens.

**Results: [results/MATRIX.md](results/MATRIX.md).**

## Why

The coordinator, the software on a computer that builds the PSBT, is the part a signing device is there to distrust. Most of what a PSBT says about inputs, change and keys is a claim the device has to check against the seed or against what the signature commits to. The ways those checks go wrong are well known and keep coming back: fee lies on inputs whose amounts the sighash does not commit, change that carries our key in its metadata but pays someone else, signatures whose sighash leaves the outputs open.

Signer projects fix these one at a time, each with its own tests. Since September 2026, SeedSigner has merged eleven pull requests into its PSBT parser, Krux five into its PSBT code and vendored embit, and Krux's embit fork thirteen more. A shared corpus lets each project check itself against what the others have already learned, and catches the same mistake when it comes back.

## What a case holds

Each file in `cases/` is one PSBT and what is expected of a signer that gets it.

| Field | Content |
| --- | --- |
| `psbt` | The PSBT, base64 |
| `wallet` | The seed (the BIP-39 test mnemonic), network, script type and account the device signs with, and for multisig the descriptor loaded on the device |
| `attack` | What the coordinator is trying to do |
| `rule` | What a signer should do about it |
| `level` | `must` when failing means a loss the user cannot see on the screen, `should` for weaker protection, `baseline` for honest PSBTs |
| `acceptable` | The verdicts that pass: `refuse` (before the review), `warn`, `sign`, `no-signature` (the user approves but no signature comes out) |
| `honest_view` | The amounts an honest review shows: inputs, spend, change, fee |
| `also_safe` | Other verdicts that pass with another view, when there is one: a signer that does not recognise an output as its own and shows it as a spend is not hiding anything |
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
| `change-at-huge-index` | Sends the change to address index 2,147,483,000, past any gap limit |
| `op-return-with-value` | Burns 300,000 sats in an OP_RETURN output |
| `baseline-p2wsh-multisig` | Nothing: an honest 2-of-3 spend with change, the wallet's descriptor loaded on the device |
| `multisig-change-to-attacker-keys` | Keeps our key in the change script but replaces both other cosigners with the attacker's keys, labelled with the real cosigners' fingerprints |
| `multisig-change-to-attacker-keys-and-xpubs` | The same, with the PSBT's global xpubs swapped so the attacker's keys trace back to them |

## Grading

A signer passes a case when its verdict is one of the case's acceptable verdicts and, whenever it shows the user a review (`sign` or `warn`), the spend, change and fee on that review are the honest ones. Outside the honest baselines, a refusal always counts as safe, and so does a signing step that produces no signature valid for the PSBT's transaction, since every attack here needs one; whether that is also convenient is not graded. A case can list other safe outcomes in `also_safe`: a review that shows the real input amounts, an own output shown as a spend, a signature made with SIGHASH_ALL when the PSBT asked for something else.

## How the adapters work

The adapters call the signers' own code at a pinned commit. They do not reimplement it. Each follows the device's signing flow as its source reads:

- `adapters/seedsigner_adapter.py` follows `seedsigner/views/psbt_views.py`: the fingerprint check that selects the seed, `PSBTParser` (an exception there is a refusal), the totals and warnings the review screens get, the check of each multisig change output against the loaded descriptor that `PSBTChangeDetailsView` makes, then `sign_with()` and the signature count the flow uses to tell whether signing did anything.
- `adapters/krux_adapter.py` loads the multisig descriptor into the wallet when the case has one, then follows `Home.sign_psbt()` in `src/krux/pages/home_pages/home.py`: `PSBTSigner` (an exception there is a refusal), the warnings shown before the review, the classification behind `outputs()`, then `sign()`. Krux's hardware modules are replaced with the stand-ins its own test suite uses.
- `adapters/bdk` (Rust) builds a BDK wallet from the case's seed. BDK has no screens, so the review is what a wallet built on it gets from the library: the fee from `PsbtUtils::fee_amount` (none means no fee can be shown, a refusal) and each output sorted with `Wallet::is_mine`. It then signs in one of three modes: `wallet-sign` (`Wallet::sign` with `SignOptions::default()`), `psbt-sign` (`bitcoin::Psbt::sign`) and `psbt-sign-checked` (the checks from bdk_wallet#647's `examples/signing_checks.rs`, copied unchanged into `adapters/bdk/src/checks.rs`, then `Psbt::sign`). A verdict counts a signature as soon as one is in the PSBT, even when the call also returns an error.
- `adapters/trezor_adapter.py` passes the PSBT to HWI's Trezor client against a running emulator. HWI's automatic confirmation is turned off; a driver on the debug link reads each screen, records it, then confirms it, holding where the device asks for a hold. The spend is the sum of the amounts shown for recipients and the fee is read from the summary. A signature counts only if it verifies against the PSBT's own transaction, with each input's amount taken from its previous transaction when the PSBT carries one, since that is what the network checks.

What this does not cover: SeedSigner, Krux and BDK run on CPython or as a library, not on a device, and their amounts are read from the objects the screens are built from, not from the screens. Trezor runs as an emulator, not on hardware, and is not run in CI yet: its results were recorded locally (the notes in [results/MATRIX.md](results/MATRIX.md) name the build).

## Running

```
pip install -r requirements.txt              # embit 0.8.0, as SeedSigner pins it
python -I gen/gen.py                         # write cases/

python -I adapters/seedsigner_adapter.py <seedsigner checkout> cases > results/seedsigner-dev.json
python -I adapters/krux_adapter.py <krux checkout> cases > results/krux-develop.json

cargo build --release --manifest-path adapters/bdk/Cargo.toml
adapters/bdk/target/release/bdk-adapter wallet-sign cases > results/bdk-wallet-sign.json
adapters/bdk/target/release/bdk-adapter psbt-sign cases > results/psbt-sign-alone.json
adapters/bdk/target/release/bdk-adapter psbt-sign-checked cases > results/psbt-sign-with-checks.json

python adapters/trezor_adapter.py cases > results/trezor-safe5.json   # Linux, emulator running

python -I report.py                          # write results/MATRIX.md
```

The Trezor adapter needs Linux, the emulator binary from `https://data.trezor.io/dev/firmware/releases/emulators-new/T3T1/` (it links SDL3 and SDL3_image; on a system without them, build both and point the binary at them with `patchelf`), and `hwi`, `trezor` and `embit==0.8.0` in its environment. Start the emulator with `SDL_VIDEODRIVER=offscreen TREZOR_DISABLE_ANIMATION=1`; the adapter loads the case seed into it if it is empty.

Run each adapter in its own environment: SeedSigner uses embit from PyPI, Krux its vendored copy (`git submodule update --init vendor/embit`; the Krux environment needs `pyqrcode` for the test stand-ins). `results/targets.json` names the commits. CI checks out those commits, rebuilds the cases and the results, and fails if anything differs from what is committed.

## Next

- More multisig: inputs from two different multisigs, a wallet with no descriptor loaded, P2SH and nested P2WSH, taproot multisig.
- PSBTv2 fields, taproot script-path spends, MuSig2 and silent payments as signers add them.
- More signers. Other devices with an emulator (Coldcard, BitBox02, Ledger, Trezor One) can run the same cases through HWI, or through [bhwi](https://github.com/wizardsardine/bhwi).
- The Trezor emulator in CI.

## Reporting

A case that shows a problem nobody has reported yet is sent to the signer's maintainers privately first, and appears here only once they know about it. The notes in [results/MATRIX.md](results/MATRIX.md) say, for each failure in the current results, where it is already tracked or when it was reported.

## License

MIT
