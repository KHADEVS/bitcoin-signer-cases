//! Runs every case through BDK and prints what a wallet built on it does.
//!
//! BDK is a library, not a device, so the "review" here is what a BDK-based wallet has
//! to build one from: the fee from `PsbtUtils::fee_amount` (no fee means the wallet
//! cannot show one, which counts as a refusal), and each output sorted into change or
//! spend with `Wallet::is_mine`. Signing depends on the mode:
//!
//! - `wallet-sign`: `Wallet::sign` with `SignOptions::default()`, deprecated in 3.2.0;
//! - `psbt-sign`: `bitcoin::Psbt::sign`, which the deprecation note points to;
//! - `psbt-sign-checked`: the same, after the checks bdk_wallet#647 adds as an example
//!   to replace the `SignOptions` defaults (`checks.rs`).
//!
//! An error while signing, or a call that adds no signature, is "no-signature".
//!
//! Usage: cargo run --release -- <mode> <cases dir>

mod checks;

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use base64::Engine;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{Network, NetworkKind, Psbt};
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{SignOptions, Wallet};
use serde_json::{json, Value};

fn account_path(script_type: &str) -> &'static str {
    match script_type {
        "p2pkh" => "m/44'/1'/0'",
        "p2wpkh" => "m/84'/1'/0'",
        "p2tr" => "m/86'/1'/0'",
        "p2wsh" => "m/48'/1'/0'/2'",
        other => panic!("unknown script type {other}"),
    }
}

fn master_key(wallet: &Value) -> Xpriv {
    let mnemonic = Mnemonic::parse(wallet["mnemonic"].as_str().unwrap()).unwrap();
    Xpriv::new_master(NetworkKind::Test, &mnemonic.to_seed("")).unwrap()
}

/// The wallet's two descriptors (receive, change), with our private key in them.
fn descriptors(wallet: &Value) -> (String, String) {
    let secp = Secp256k1::new();
    let master = master_key(wallet);
    let fingerprint = master.fingerprint(&secp);
    let script_type = wallet["script_type"].as_str().unwrap();
    let path = DerivationPath::from_str(account_path(script_type)).unwrap();
    let account = master.derive_priv(&secp, &path).unwrap();
    let origin = format!("[{}/{}]", fingerprint, &account_path(script_type)[2..]);

    if let Some(multisig) = wallet["descriptor"].as_str() {
        // The loaded multisig descriptor, with our xpub swapped for our xprv.
        let ours = Xpub::from_priv(&secp, &account).to_string();
        let body = multisig.split('#').next().unwrap().replace(&ours, &account.to_string());
        assert!(body.contains(&account.to_string()), "our xpub is not in the descriptor");
        return (body.replace("<0;1>", "0"), body.replace("<0;1>", "1"));
    }
    let wrap = |branch: u32| {
        let key = format!("{origin}{account}/{branch}/*");
        match script_type {
            "p2pkh" => format!("pkh({key})"),
            "p2wpkh" => format!("wpkh({key})"),
            "p2tr" => format!("tr({key})"),
            _ => unreachable!(),
        }
    };
    (wrap(0), wrap(1))
}

fn signature_count(psbt: &Psbt) -> usize {
    psbt.inputs
        .iter()
        .map(|i| {
            i.partial_sigs.len()
                + i.tap_script_sigs.len()
                + usize::from(i.tap_key_sig.is_some())
                + usize::from(i.final_script_sig.is_some())
                + usize::from(i.final_script_witness.is_some())
        })
        .sum()
}

fn run_case(case: &Value, mode: &str) -> Value {
    let (receive, change) = descriptors(&case["wallet"]);
    let wallet = Wallet::create(receive, change)
        .network(Network::Testnet)
        .create_wallet_no_persist()
        .expect("wallet");

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(case["psbt"].as_str().unwrap())
        .unwrap();
    let mut psbt = match Psbt::deserialize(&bytes) {
        Ok(p) => p,
        Err(e) => return json!({"verdict": "refuse", "stage": "load", "detail": e.to_string()}),
    };

    // fee_amount() panics when the outputs exceed the inputs (bdk_wallet#558); a wallet
    // that crashes signs nothing, so that is a refusal too.
    let fee = match std::panic::catch_unwind(|| psbt.fee_amount()) {
        Ok(fee) => fee,
        Err(_) => {
            return json!({"verdict": "refuse", "stage": "review",
                          "detail": "fee_amount() panicked (bdk_wallet#558)"})
        }
    };
    let Some(fee) = fee else {
        return json!({"verdict": "refuse", "stage": "review",
                      "detail": "fee_amount() is None: an input amount is missing or does not check out"});
    };
    let inputs: u64 = (0..psbt.inputs.len())
        .map(|i| psbt.get_utxo_for(i).map(|o| o.value.to_sat()).unwrap_or(0))
        .sum();
    let (mut spend, mut change) = (0u64, 0u64);
    for out in &psbt.unsigned_tx.output {
        if wallet.is_mine(out.script_pubkey.clone()) {
            change += out.value.to_sat();
        } else {
            spend += out.value.to_sat();
        }
    }
    let shown = json!({"inputs": inputs, "spend": spend, "change": change, "fee": fee.to_sat()});

    let before = signature_count(&psbt);
    let signed: Result<(), String> = match mode {
        #[allow(deprecated)]
        "wallet-sign" => wallet
            .sign(&mut psbt, SignOptions::default())
            .map(|_| ())
            .map_err(|e| format!("{e:?}")),
        "psbt-sign" => psbt_sign(&mut psbt, &case["wallet"]),
        "psbt-sign-checked" => checks::check_prevouts(&wallet, &psbt)
            .and_then(|_| checks::check_sighashes(&psbt))
            .map_err(|e| format!("checks: {e}"))
            .and_then(|_| psbt_sign(&mut psbt, &case["wallet"])),
        other => panic!("unknown mode {other}"),
    };
    // What counts is whether a signature came out: Psbt::sign can sign some inputs and
    // still return an error for others, and those signatures are in the PSBT it hands back.
    let added = signature_count(&psbt) > before;
    match (added, signed) {
        (true, Ok(())) => json!({"verdict": "sign", "stage": "signed", "warnings": [], "shown": shown}),
        (true, Err(e)) => json!({"verdict": "sign", "stage": "signed", "detail": format!("signed despite: {e}"),
                                 "warnings": [], "shown": shown}),
        (false, Err(e)) => json!({"verdict": "no-signature", "stage": "signing", "detail": e,
                                  "warnings": [], "shown": shown}),
        (false, Ok(())) => json!({"verdict": "no-signature", "stage": "signing",
                                  "detail": "no signature added", "warnings": [], "shown": shown}),
    }
}

/// `bitcoin::Psbt::sign` with the wallet's master key.
fn psbt_sign(psbt: &mut Psbt, wallet: &Value) -> Result<(), String> {
    let secp = Secp256k1::new();
    psbt.sign(&master_key(wallet), &secp)
        .map(|_| ())
        .map_err(|(_, errors)| format!("Psbt::sign: {errors:?}"))
}

fn main() {
    let mode = std::env::args().nth(1).expect("usage: bdk-adapter <mode> <cases dir>");
    let dir = std::env::args().nth(2).expect("usage: bdk-adapter <mode> <cases dir>");
    // fee_amount() panics are caught and reported; keep them off stderr.
    std::panic::set_hook(Box::new(|_| {}));
    let mut results = BTreeMap::new();
    let mut paths: Vec<_> = std::fs::read_dir(Path::new(&dir))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let case: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        results.insert(case["id"].as_str().unwrap().to_string(), run_case(&case, &mode));
    }
    println!("{}", serde_json::to_string_pretty(&results).unwrap());
}
