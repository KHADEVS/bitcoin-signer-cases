"""Writes every case under cases/ from scratch.

Each case is a PSBT built the way a hostile coordinator would build it, plus what an
honest review screen would show and what a signer is expected to do with it. The
output is deterministic: the same embit version always writes the same files, which
CI checks.

Usage: python gen/gen.py [cases_dir]
"""

import json
import sys
from base64 import b64encode
from hashlib import sha256
from pathlib import Path

from embit import bip32, bip39
from embit.ec import PublicKey
from embit.hashes import tagged_hash
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.descriptor.checksum import add_checksum
from embit.script import Script, multisig, p2pkh, p2tr, p2wpkh, p2wsh
from embit.transaction import Transaction, TransactionInput, TransactionOutput

# The BIP-39 test mnemonic. Every case is on testnet.
MNEMONIC = "abandon " * 11 + "about"
NETWORK = NETWORKS["test"]

ROOT = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(MNEMONIC), version=NETWORK["xprv"])
FINGERPRINT = ROOT.my_fingerprint

# Someone else's wallet: the attacker, or just the recipient.
FOREIGN = bip32.HDKey.from_seed(
    sha256(b"bitcoin-signer-cases: foreign wallet").digest(), version=NETWORK["xprv"]
)

ACCOUNTS = {
    "p2pkh": "m/44h/1h/0h",
    "p2wpkh": "m/84h/1h/0h",
    "p2tr": "m/86h/1h/0h",
    "p2wsh": "m/48h/1h/0h/2h",
}

SIGHASH_TYPES = {"none": 0x02, "single-anyonecanpay": 0x83}

COIN = 1_000_000  # each coin being spent, in sats
SEND = 600_000
FEE = 10_000
CHANGE = COIN - SEND - FEE


def pub(path: str) -> PublicKey:
    return ROOT.derive(path).key.get_public_key()


def der(path: str) -> DerivationPath:
    return DerivationPath(FINGERPRINT, bip32.parse_path(path))


def foreign_pub(index: int) -> PublicKey:
    return FOREIGN.derive("m/84h/1h/0h/0/%d" % index).key.get_public_key()


def script_for(script_type: str, key: PublicKey) -> Script:
    return {"p2pkh": p2pkh, "p2wpkh": p2wpkh, "p2tr": p2tr}[script_type](key)


def prev_tx(tag: str, outputs) -> Transaction:
    """A made-up funding transaction. Its only input points at a tag-derived txid."""
    vin = [TransactionInput(sha256(tag.encode()).digest(), 0)]
    return Transaction(version=2, vin=vin, vout=outputs, locktime=0)


class Coin:
    """One of our coins: where it sits and the transaction that created it."""

    def __init__(self, tag, script_type, path, value=COIN):
        self.script_type = script_type
        self.path = path
        self.key = pub(path)
        self.output = TransactionOutput(value, script_for(script_type, self.key))
        self.tx = prev_tx(tag, [self.output])


def build(coins, outputs, *, prev_tx_mode="always"):
    """Spends `coins` to `outputs`, filling in what an honest coordinator would.

    prev_tx_mode: "always" attaches the funding transaction to every input, "legacy"
    only to legacy inputs, "never" to none (taproot never needs it).
    """
    vin = [TransactionInput(c.tx.txid(), 0, sequence=0xFFFFFFFD) for c in coins]
    vout = [TransactionOutput(value, spk) for spk, value, _ in outputs]
    psbt = PSBT(Transaction(version=2, vin=vin, vout=vout, locktime=0))
    for inp, c in zip(psbt.inputs, coins):
        if c.script_type != "p2pkh":
            inp.witness_utxo = c.output
        attach = prev_tx_mode == "always" or (
            prev_tx_mode == "legacy" and c.script_type == "p2pkh"
        )
        if attach:
            inp.non_witness_utxo = c.tx
        if c.script_type == "p2tr":
            inp.taproot_internal_key = c.key
            inp.taproot_bip32_derivations[c.key] = ([], der(c.path))
        else:
            inp.bip32_derivations[c.key] = der(c.path)
    for out, (_, _, claim) in zip(psbt.outputs, outputs):
        if claim is None:
            continue
        kind, key, path = claim
        if kind == "p2tr":
            out.taproot_internal_key = key
            out.taproot_bip32_derivations[key] = ([], der(path))
        else:
            out.bip32_derivations[key] = der(path)
    return psbt


def change_to(script_type, path):
    key = pub(path)
    return (script_for(script_type, key), CHANGE, (script_type, key, path))


def send_to_foreign(value=SEND, index=0):
    return (p2wpkh(foreign_pub(index)), value, None)


def truth(inputs, spend, change):
    return {"inputs": inputs, "spend": spend, "change": change, "fee": inputs - spend - change}


CASES = []


def case(id, cls, title, level, acceptable, script_type, psbt, honest, attack, rule, refs, descriptor=None,
         also_safe=None):
    """`also_safe` lists other (verdict, view) pairs that pass: a signer that does not
    recognise an output as its own and shows it as a spend is not hiding anything."""
    wallet = {
        "mnemonic": MNEMONIC,
        "network": "testnet",
        "script_type": script_type,
        "account": ACCOUNTS[script_type],
    }
    if descriptor is not None:
        # A multisig wallet: the descriptor the user loaded on the device beforehand
        wallet["descriptor"] = descriptor
    entry = {
        "id": id,
        "class": cls,
        "title": title,
        "level": level,
        "acceptable": acceptable,
        "wallet": wallet,
        "psbt": b64encode(psbt.serialize()).decode(),
        "honest_view": honest,
        "attack": attack,
        "rule": rule,
        "refs": refs,
    }
    if also_safe is not None:
        entry["also_safe"] = [{"verdict": v, "view": view} for v, view in also_safe]
    CASES.append(entry)


BIP174 = "https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki"
BIP143 = "https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki"
BIP341 = "https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki"
BIP86 = "https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki"
TREZOR_2020 = "https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd"

# --- Baselines: honest PSBTs every signer should sign as they are.

for st in ("p2wpkh", "p2tr", "p2pkh"):
    acct = ACCOUNTS[st]
    coin = Coin("baseline-" + st, st, acct + "/0/0")
    psbt = build([coin], [send_to_foreign(), change_to(st, acct + "/1/0")])
    case(
        "baseline-" + st,
        "baseline",
        "Honest %s spend with change" % st,
        "baseline",
        ["sign"],
        st,
        psbt,
        truth(COIN, SEND, CHANGE),
        "None. One of our coins pays a foreign address and the rest comes back as change.",
        "Sign, showing the amount sent, the change and the fee.",
        [BIP174],
    )

# --- Input amounts: the fee shown is only as good as the input amounts behind it.

acct = ACCOUNTS["p2pkh"]
coin = Coin("legacy-input-without-prev-tx", "p2pkh", acct + "/0/0", value=5 * COIN)
psbt = build([coin], [send_to_foreign(), change_to("p2pkh", acct + "/1/0")], prev_tx_mode="never")
# The coordinator states the coin's value without the transaction that proves it.
psbt.inputs[0].witness_utxo = TransactionOutput(COIN, coin.output.script_pubkey)
case(
    "legacy-input-without-prev-tx",
    "input-amounts",
    "Legacy input whose amount comes without its previous transaction",
    "must",
    ["refuse", "no-signature"],
    "p2pkh",
    psbt,
    truth(5 * COIN, SEND, CHANGE),
    "The coin holds 0.05 BTC but the PSBT says 0.01 BTC and leaves out the previous "
    "transaction. A legacy signature does not commit to the amount, so the 0.04 BTC "
    "difference goes to the miner while the screen shows a 10,000 sat fee.",
    "Refuse a legacy input that does not carry its previous transaction.",
    [BIP174, BIP143],
)

acct = ACCOUNTS["p2wpkh"]
coin = Coin("prev-tx-does-not-hash-to-prevout", "p2wpkh", acct + "/0/0")
other = Coin("prev-tx-does-not-hash-to-prevout/other", "p2wpkh", acct + "/0/0")
psbt = build([coin], [send_to_foreign(), change_to("p2wpkh", acct + "/1/0")])
psbt.inputs[0].non_witness_utxo = other.tx
case(
    "prev-tx-does-not-hash-to-prevout",
    "input-amounts",
    "Previous transaction that is not the one the input spends",
    "must",
    ["refuse", "no-signature"],
    "p2wpkh",
    psbt,
    truth(COIN, SEND, CHANGE),
    "The previous transaction attached to the input is a different transaction, so it "
    "proves nothing about the coin being spent.",
    "Check that the previous transaction hashes to the txid the input spends, and refuse otherwise.",
    [BIP174],
)

coin = Coin("witness-utxo-disagrees-with-prev-tx", "p2wpkh", acct + "/0/0", value=5 * COIN)
psbt = build([coin], [send_to_foreign(), change_to("p2wpkh", acct + "/1/0")])
psbt.inputs[0].witness_utxo = TransactionOutput(COIN, coin.output.script_pubkey)
case(
    "witness-utxo-disagrees-with-prev-tx",
    "input-amounts",
    "Witness UTXO that contradicts the previous transaction",
    "must",
    ["refuse", "no-signature"],
    "p2wpkh",
    psbt,
    truth(5 * COIN, SEND, CHANGE),
    "The previous transaction says the coin holds 0.05 BTC, the witness UTXO says 0.01 "
    "BTC. A signer that reads the second for the fee shows 10,000 sats.",
    "Refuse an input whose witness UTXO differs from the output it points to in the previous transaction.",
    [BIP174],
)

coins = [
    Coin("segwit-v0-inputs-without-prev-tx/%d" % i, "p2wpkh", acct + "/0/%d" % i)
    for i in range(2)
]
psbt = build(coins, [send_to_foreign(COIN + SEND), change_to("p2wpkh", acct + "/1/0")], prev_tx_mode="never")
case(
    "segwit-v0-inputs-without-prev-tx",
    "input-amounts",
    "Two segwit v0 inputs with no previous transactions",
    "should",
    ["refuse", "warn", "no-signature"],
    "p2wpkh",
    psbt,
    truth(2 * COIN, COIN + SEND, CHANGE),
    "Nothing is false here, but nothing proves the amounts either. BIP-143 commits each "
    "signature to its own input's amount only, so a coordinator can understate a "
    "different input in each of two signing rounds and combine one valid signature from "
    "each: the fee actually paid is larger than either screen showed.",
    "Ask for the previous transactions, or tell the user the input amounts are unverified.",
    [BIP143, TREZOR_2020],
)

coin = Coin("outputs-exceed-inputs", "p2wpkh", acct + "/0/0")
psbt = build([coin], [send_to_foreign(COIN), change_to("p2wpkh", acct + "/1/0")])
case(
    "outputs-exceed-inputs",
    "input-amounts",
    "Outputs worth more than the inputs",
    "must",
    ["refuse", "no-signature"],
    "p2wpkh",
    psbt,
    truth(COIN, COIN, CHANGE),
    "The outputs add up to more than the inputs. The transaction is invalid, and a signer "
    "that subtracts naively shows a negative fee, which reads like a cheap transaction.",
    "Refuse a PSBT whose outputs exceed its inputs.",
    [BIP174],
)

# --- Sighash: a signature that does not commit to the outputs lets them be changed later.

for name, value in SIGHASH_TYPES.items():
    coin = Coin("sighash-" + name, "p2wpkh", acct + "/0/0")
    psbt = build([coin], [send_to_foreign(), change_to("p2wpkh", acct + "/1/0")])
    psbt.inputs[0].sighash_type = value
    case(
        "sighash-" + name,
        "sighash",
        "Input asking for SIGHASH_%s" % name.upper().replace("-", "|"),
        "must",
        ["refuse", "no-signature"],
        "p2wpkh",
        psbt,
        truth(COIN, SEND, CHANGE),
        "The input asks to be signed with sighash 0x%02x. The resulting signature does not "
        "cover all the outputs, so whoever holds it can redirect the funds after the user "
        "approved the screen." % value,
        "Never produce a signature with a sighash other than ALL (or DEFAULT on taproot) "
        "without telling the user; refusing is simplest.",
        [BIP174, BIP341],
    )

# --- Change: an output the coordinator calls ours must be proved ours from the seed.

coin = Coin("change-paid-to-foreign-key", "p2wpkh", acct + "/0/0")
claimed = pub(acct + "/1/0")
outputs = [
    send_to_foreign(),
    (p2wpkh(foreign_pub(1)), CHANGE, ("p2wpkh", claimed, acct + "/1/0")),
]
psbt = build([coin], outputs)
case(
    "change-paid-to-foreign-key",
    "change",
    "Change claimed with our key and path, paid to someone else",
    "must",
    ["sign", "warn", "refuse"],
    "p2wpkh",
    psbt,
    truth(COIN, SEND + CHANGE, 0),
    "The second output carries our public key and change path in its PSBT metadata, but "
    "its script pays a foreign key. A signer that trusts the metadata hides a 0.0039 BTC "
    "payment to the attacker as change.",
    "Rebuild the output script from the seed at the claimed path and count the output as "
    "a spend unless it matches.",
    [BIP174],
)

coin = Coin("change-in-other-script-type", "p2wpkh", acct + "/0/0")
key = pub(acct + "/1/0")
outputs = [send_to_foreign(), (p2pkh(key), CHANGE, ("p2pkh", key, acct + "/1/0"))]
psbt = build([coin], outputs)
case(
    "change-in-other-script-type",
    "change",
    "Change to our key, wrapped in another script type",
    "should",
    ["sign", "warn", "refuse"],
    "p2wpkh",
    psbt,
    truth(COIN, SEND + CHANGE, 0),
    "The change pays our own key at the change path, but as P2PKH while the wallet is "
    "P2WPKH. The seed can still spend it, but the wallet that watches this account will "
    "not see it, so the user believes the funds are gone until someone tells them where "
    "to look.",
    "Show it as a spend (or warn): it is not change of the wallet being used.",
    [BIP174],
)

acct = ACCOUNTS["p2tr"]
coin = Coin("taproot-change-with-hidden-script-path", "p2tr", acct + "/0/0")
internal = pub(acct + "/1/0")
leaf_script = b"\x20" + foreign_pub(2).xonly() + b"\xac"  # <foreign key> OP_CHECKSIG
leaf_hash = tagged_hash("TapLeaf", b"\xc0" + bytes([len(leaf_script)]) + leaf_script)
hidden = Script(b"\x51\x20" + internal.taproot_tweak(leaf_hash).xonly())
outputs = [send_to_foreign(), (hidden, CHANGE, ("p2tr", internal, acct + "/1/0"))]
psbt = build([coin], outputs)
case(
    "taproot-change-with-hidden-script-path",
    "change",
    "Taproot change whose output key hides a script path for someone else",
    "must",
    ["sign", "warn", "refuse"],
    "p2tr",
    psbt,
    truth(COIN, SEND + CHANGE, 0),
    "The change output's internal key is ours at the change path, but the output key is "
    "tweaked with a script tree holding a single leaf, <foreign key> OP_CHECKSIG. The "
    "attacker can spend the 'change' through that leaf without our key.",
    "Rebuild the BIP-86 output key (no script tree) and count the output as a spend unless it matches.",
    [BIP341, BIP86],
)

acct = ACCOUNTS["p2wpkh"]
coin = Coin("change-at-huge-index", "p2wpkh", acct + "/0/0")
psbt = build([coin], [send_to_foreign(), change_to("p2wpkh", acct + "/1/2147483000")])
case(
    "change-at-huge-index",
    "change",
    "Change at address index 2,147,483,000",
    "should",
    ["warn", "refuse"],
    "p2wpkh",
    psbt,
    truth(COIN, SEND, CHANGE),
    "The change really is ours, but so far past the gap limit that no wallet will find it "
    "by scanning. Whoever built the PSBT knows the index; the user does not.",
    "Warn, or refuse, when the change index is far beyond the indexes the inputs come from. "
    "A signer that does not recognise the output as change and shows it as a spend is safe too.",
    [BIP174],
    also_safe=[("sign", truth(COIN, SEND + CHANGE, 0))],
)

coin = Coin("change-in-another-account", "p2wpkh", acct + "/0/0")
psbt = build([coin], [send_to_foreign(), change_to("p2wpkh", "m/84h/1h/1h/1/0")])
case(
    "change-in-another-account",
    "change",
    "Change sent to another account of the same seed",
    "should",
    ["sign", "warn", "refuse"],
    "p2wpkh",
    psbt,
    truth(COIN, SEND + CHANGE, 0),
    "The change goes to account 1 of our seed while the coins and the wallet are account "
    "0. The seed can spend it, the wallet in use will not show it.",
    "Show it as a spend (or warn): it is not change of the account being used.",
    [BIP174],
)

coin = Coin("op-return-with-value", "p2wpkh", acct + "/0/0")
burn = 300_000
op_return = Script(b"\x6a\x04" + b"burn")
psbt = build(
    [coin],
    [send_to_foreign(SEND - burn), (op_return, burn, None), change_to("p2wpkh", acct + "/1/0")],
)
case(
    "op-return-with-value",
    "outputs",
    "OP_RETURN output carrying 0.003 BTC",
    "must",
    ["sign", "warn", "refuse"],
    "p2wpkh",
    psbt,
    truth(COIN, SEND, CHANGE),
    "An OP_RETURN output carries 300,000 sats. They are destroyed, not sent. A signer that "
    "skips data outputs when it adds up what is sent shows less leaving the wallet than "
    "actually does.",
    "Count the value of every output, OP_RETURN included, and show that it is burned.",
    [BIP174],
)


# --- Multisig: a 2-of-3 P2WSH wallet whose descriptor the user loaded on the device.

MS_ACCOUNT = ACCOUNTS["p2wsh"]


def other_root(tag):
    return bip32.HDKey.from_seed(sha256(tag.encode()).digest(), version=NETWORK["xprv"])


COSIGNERS = [ROOT, other_root("bitcoin-signer-cases: cosigner A"), other_root("bitcoin-signer-cases: cosigner B")]
ATTACKERS = [other_root("bitcoin-signer-cases: attacker 1"), other_root("bitcoin-signer-cases: attacker 2")]


def member(root, branch, index, claimed_fingerprint=None):
    """A key of the multisig script, with the derivation the PSBT claims for it."""
    path = "%s/%d/%d" % (MS_ACCOUNT, branch, index)
    fingerprint = claimed_fingerprint or root.my_fingerprint
    return root.derive(path).key.get_public_key(), DerivationPath(fingerprint, bip32.parse_path(path))


def sortedmulti(members):
    return multisig(2, sorted((key for key, _ in members), key=lambda k: k.sec()))


def descriptor_of(roots):
    keys = ",".join(
        "[%s/48h/1h/0h/2h]%s/<0;1>/*" % (r.my_fingerprint.hex(), r.derive(MS_ACCOUNT).to_public().to_base58())
        for r in roots
    )
    return add_checksum("wsh(sortedmulti(2,%s))" % keys)


MS_DESCRIPTOR = descriptor_of(COSIGNERS)


def ms_output(members, value=CHANGE):
    return (p2wsh(sortedmulti(members)), value, members)


def build_multisig(tag, outputs, xpubs=None):
    """Spends one coin of the 2-of-3 wallet to `outputs`, as (scriptPubKey, value,
    members or None). `xpubs` lists the global xpubs as (root, claimed fingerprint);
    an honest coordinator lists the three cosigners."""
    members = [member(r, 0, 0) for r in COSIGNERS]
    witness_script = sortedmulti(members)
    funding = TransactionOutput(COIN, p2wsh(witness_script))
    ptx = prev_tx(tag, [funding])
    vin = [TransactionInput(ptx.txid(), 0, sequence=0xFFFFFFFD)]
    vout = [TransactionOutput(value, spk) for spk, value, _ in outputs]
    psbt = PSBT(Transaction(version=2, vin=vin, vout=vout, locktime=0))
    for root, fingerprint in xpubs or [(r, r.my_fingerprint) for r in COSIGNERS]:
        psbt.xpubs[root.derive(MS_ACCOUNT).to_public()] = DerivationPath(fingerprint, bip32.parse_path(MS_ACCOUNT))
    inp = psbt.inputs[0]
    inp.witness_utxo = funding
    inp.non_witness_utxo = ptx
    inp.witness_script = witness_script
    for key, derivation in members:
        inp.bip32_derivations[key] = derivation
    for out, (_, _, out_members) in zip(psbt.outputs, outputs):
        if out_members is None:
            continue
        out.witness_script = sortedmulti(out_members)
        for key, derivation in out_members:
            out.bip32_derivations[key] = derivation
    return psbt


psbt = build_multisig(
    "baseline-p2wsh-multisig",
    [send_to_foreign(), ms_output([member(r, 1, 0) for r in COSIGNERS])],
)
case(
    "baseline-p2wsh-multisig",
    "baseline",
    "Honest 2-of-3 multisig spend with change",
    "baseline",
    ["sign"],
    "p2wsh",
    psbt,
    truth(COIN, SEND, CHANGE),
    "None. A coin of the 2-of-3 wallet pays a foreign address and the rest comes back to "
    "the same wallet's change branch.",
    "Sign, showing the amount sent, the change and the fee.",
    [BIP174],
    descriptor=MS_DESCRIPTOR,
)

# Our key stays in the change script; the two cosigners are replaced by attacker keys
# that the PSBT labels with the cosigners' fingerprints.
hijacked = [
    member(ROOT, 1, 0),
    member(ATTACKERS[0], 1, 0, claimed_fingerprint=COSIGNERS[1].my_fingerprint),
    member(ATTACKERS[1], 1, 0, claimed_fingerprint=COSIGNERS[2].my_fingerprint),
]
psbt = build_multisig("multisig-change-to-attacker-keys", [send_to_foreign(), ms_output(hijacked)])
case(
    "multisig-change-to-attacker-keys",
    "change",
    "Multisig change where both other cosigners are replaced by the attacker",
    "must",
    ["sign", "warn", "refuse"],
    "p2wsh",
    psbt,
    truth(COIN, SEND + CHANGE, 0),
    "The change is a 2-of-3 that still holds our key at the change path, so it looks like "
    "ours, but the other two keys belong to the attacker, labelled with the real "
    "cosigners' fingerprints. The attacker alone holds two of the three keys.",
    "Rebuild the change script from the wallet's descriptor (or the inputs' cosigners) and "
    "count the output as a spend unless it matches.",
    [BIP174],
    descriptor=MS_DESCRIPTOR,
)

psbt = build_multisig(
    "multisig-change-to-attacker-keys-and-xpubs",
    [send_to_foreign(), ms_output(hijacked)],
    xpubs=[
        (ROOT, ROOT.my_fingerprint),
        (ATTACKERS[0], COSIGNERS[1].my_fingerprint),
        (ATTACKERS[1], COSIGNERS[2].my_fingerprint),
    ],
)
case(
    "multisig-change-to-attacker-keys-and-xpubs",
    "change",
    "Multisig change to attacker keys, with global xpubs that vouch for them",
    "must",
    ["sign", "warn", "refuse"],
    "p2wsh",
    psbt,
    truth(COIN, SEND + CHANGE, 0),
    "As in multisig-change-to-attacker-keys, and the PSBT's global xpubs are swapped too: "
    "the attacker's account xpubs, under the real cosigners' fingerprints, so the change "
    "keys trace back to listed xpubs. A signer that takes the cosigners from the global "
    "xpubs rather than from the descriptor the user loaded sees a consistent wallet.",
    "Take the cosigners from the descriptor the user loaded, never from the PSBT's global xpubs.",
    [BIP174],
    descriptor=MS_DESCRIPTOR,
)


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent.parent / "cases")
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    for c in CASES:
        path = out / (c["id"] + ".json")
        path.write_text(json.dumps(c, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("%d cases written to %s" % (len(CASES), out))


if __name__ == "__main__":
    main()
