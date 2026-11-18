//! The checks that replace `SignOptions` defaults when signing with `bitcoin::Psbt::sign`,
//! copied unchanged from bitcoindevkit/bdk_wallet pull request #647
//! (`examples/signing_checks.rs` at commit 38bb925, MIT OR Apache-2.0), apart from the
//! imports below.

use anyhow::Context;
use bdk_wallet::bitcoin::psbt::{self, PsbtSighashType};
use bdk_wallet::bitcoin::sighash::{EcdsaSighashType, TapSighashType};
use bdk_wallet::bitcoin::{OutPoint, Psbt, Transaction, TxOut};
use bdk_wallet::Wallet;

/// Verifies prevouts using `non_witness_utxo` or wallet-held Taproot parents.
///
/// Why needed: A PSBT creator can falsify input amounts to hide excessive fees.
pub fn check_prevouts(wallet: &Wallet, psbt: &Psbt) -> anyhow::Result<()> {
    let inputs = psbt.inputs.iter().zip(&psbt.unsigned_tx.input);

    let all_amounts_committed = inputs.clone().all(|(input, txin)| {
        !is_anyone_can_pay(input) && is_verified_taproot(wallet, input, txin.previous_output)
    });

    for (i, (input, txin)) in inputs.enumerate() {
        // The signer checks supplied parents on unfinalized inputs even during the exemption.
        let check_supplied_parent = input.non_witness_utxo.is_some()
            && input.final_script_sig.is_none()
            && input.final_script_witness.is_none();
        if !all_amounts_committed || check_supplied_parent {
            check_input_amount(wallet, input, txin.previous_output, i)?;
        }
    }
    Ok(())
}

/// Whether the input's sighash type sets the `ANYONECANPAY` flag.
fn is_anyone_can_pay(input: &psbt::Input) -> bool {
    input.sighash_type.is_some_and(|ty| ty.to_u32() & 0x80 != 0)
}

/// Identifies Taproot using a wallet-held or txid-verified parent, never `witness_utxo` alone.
fn is_verified_taproot(wallet: &Wallet, input: &psbt::Input, outpoint: OutPoint) -> bool {
    let spends_p2tr = |parent: &Transaction| {
        parent
            .output
            .get(outpoint.vout as usize)
            .is_some_and(|prevout| prevout.script_pubkey.is_p2tr())
    };
    match wallet.tx_graph().get_tx(outpoint.txid) {
        Some(parent) => spends_p2tr(&parent),
        None => input
            .non_witness_utxo
            .as_ref()
            .is_some_and(|parent| parent.compute_txid() == outpoint.txid && spends_p2tr(parent)),
    }
}

/// Checks the supplied parent, or a wallet-held Taproot parent, against `witness_utxo`.
fn check_input_amount(
    wallet: &Wallet,
    input: &psbt::Input,
    outpoint: OutPoint,
    i: usize,
) -> anyhow::Result<()> {
    let vout = outpoint.vout as usize;
    let prevout: TxOut = match &input.non_witness_utxo {
        Some(parent) if parent.compute_txid() != outpoint.txid => {
            anyhow::bail!("input {i}: non_witness_utxo has the wrong txid");
        }
        Some(parent) => parent
            .output
            .get(vout)
            .cloned()
            .with_context(|| format!("input {i}: previous output index is out of range"))?,
        None => wallet
            .tx_graph()
            .get_tx(outpoint.txid)
            .and_then(|parent| parent.output.get(vout).cloned())
            .filter(|prevout| prevout.script_pubkey.is_p2tr())
            .with_context(|| format!("input {i}: missing non_witness_utxo"))?,
    };
    if let Some(witness_utxo) = &input.witness_utxo {
        anyhow::ensure!(
            witness_utxo.value == prevout.value,
            "input {i}: witness_utxo amount does not match the previous output"
        );
        anyhow::ensure!(
            witness_utxo.script_pubkey == prevout.script_pubkey,
            "input {i}: witness_utxo script_pubkey does not match the previous output"
        );
    } else if input.non_witness_utxo.is_none() {
        anyhow::bail!("input {i}: missing witness_utxo");
    }
    Ok(())
}

// === Former `SignOptions::allow_all_sighashes: false` ===

/// Allows unset sighashes, `ALL`, and `DEFAULT`.
///
/// Why needed: Other sighash types can allow inputs or outputs to change after signing.
pub fn check_sighashes(psbt: &Psbt) -> anyhow::Result<()> {
    let allowed: [PsbtSighashType; 2] = [
        EcdsaSighashType::All.into(), // same value as `TapSighashType::All`
        TapSighashType::Default.into(),
    ];
    for (i, input) in psbt.inputs.iter().enumerate() {
        if input.sighash_type.is_some_and(|ty| !allowed.contains(&ty)) {
            anyhow::bail!("input {i}: disallowed sighash type");
        }
    }
    Ok(())
}

