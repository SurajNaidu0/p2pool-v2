use bitcoin::{Transaction, consensus::verify_transaction, OutPoint};
use crate::store::Store;

pub fn validate_raw_transaction(
    tx: &Transaction,
    store: &Store,
) -> Result<(), bitcoin::transaction::TxVerifyError> {

    // checking for 
    // -> all the tx inputs are in the store
    // -> all the tx input are unspent 
    // -> if spent does txid spending this has all the same input for rbf
    // -> rbf tx is paying more gass 

    // need to implement local cache for outpoint. so, if its called twice the second time the closure should return None
    verify_transaction(tx, |outpoint: &OutPoint| {
        match store.get_spent_by_txout(outpoint) {
            Ok(stored_output) => Some(stored_output.txout),
            Err(_e) => None,
        }
    })
}

//verify_transaction doesn't validate 
// The amount field in the tx


#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        Amount, ScriptBuf, TxIn, TxOut, 
        secp256k1::{Secp256k1, SecretKey, PublicKey, Keypair, XOnlyPublicKey},
        sighash::{SighashCache, EcdsaSighashType, TapSighashType, Prevouts},
        ecdsa::Signature as EcdsaSignature,
        PublicKey as BitcoinPublicKey,
        Address, Network,
    };
    use crate::test_utils::TestShareBlockBuilder;
    use tempfile::tempdir;

    /// Helper function to create a P2PKH script_pubkey from a public key
    fn create_p2pkh_script(pubkey: &PublicKey) -> ScriptBuf {
        let bitcoin_pubkey = BitcoinPublicKey::new(*pubkey);
        let address = Address::p2pkh(bitcoin_pubkey, Network::Bitcoin);
        address.script_pubkey()
    }

    /// Helper function to create a signed P2PKH transaction
    fn create_p2pkh_transaction(
        previous_output: OutPoint,
        _previous_value: Amount,
        previous_script_pubkey: ScriptBuf,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
        secret_key: &SecretKey,
    ) -> Transaction {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, secret_key);

        // Create unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(), // Will be filled after signing
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Create sighash for signing
        let sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .legacy_signature_hash(0, &previous_script_pubkey, EcdsaSighashType::All.to_u32())
            .expect("Failed to create sighash");

        // Sign the transaction
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let message = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        let signature = secp.sign_ecdsa(&message, secret_key);
        let ecdsa_sig = EcdsaSignature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };

        // Create script_sig: <signature> <pubkey>
        let mut script_sig = ScriptBuf::new();
        script_sig.push_slice(ecdsa_sig.serialize());
        script_sig.push_slice(public_key.serialize());

        // Update the transaction with the signature
        tx.input[0].script_sig = script_sig;

        tx
    }

    /// Helper function to create a P2TR (Taproot) script_pubkey from an x-only public key
    fn create_p2tr_script(secp: &Secp256k1<bitcoin::secp256k1::All>, internal_key: &XOnlyPublicKey) -> ScriptBuf {
        // For key path spend, we need to tweak the internal key
        let address = Address::p2tr(secp, *internal_key, None, Network::Bitcoin);
        address.script_pubkey()
    }

    /// Helper function to create a signed P2TR transaction (key path spend)
    fn create_p2tr_keypath_transaction(
        previous_output: OutPoint,
        previous_value: Amount,
        previous_script_pubkey: ScriptBuf,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
        keypair: &Keypair,
    ) -> Transaction {
        let secp = Secp256k1::new();

        // Create unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(), // Empty for taproot
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(), // Will be filled after signing
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Create prevouts for taproot sighash
        let prevouts = vec![TxOut {
            value: previous_value,
            script_pubkey: previous_script_pubkey,
        }];
        let prevouts = Prevouts::All(&prevouts);

        // Create taproot sighash
        let mut sighash_cache = SighashCache::new(&mut tx);
        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .expect("Failed to create taproot sighash");

        // Sign with schnorr signature
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr_no_aux_rand(&msg, keypair);

        // Create witness: just the signature for key path spend
        let mut witness = bitcoin::Witness::new();
        witness.push(signature.as_ref());

        // Update the transaction with the witness
        tx.input[0].witness = witness;

        tx
    }

    // ==================== P2TR HTLC Helper Functions ====================

    use bitcoin::{
        opcodes,
        taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
        TapLeafHash,
    };

    // Well-recognized NUMS point from BIP-341
    const NUMS_POINT_HEX: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

    /// Helper function to create P2TR HTLC redeem script
    /// Script: OP_SHA256 <payment_hash> OP_EQUALVERIFY <responder_pubkey> OP_CHECKSIG
    fn create_p2tr_htlc_redeem_script(
        payment_hash: &[u8; 32],
        responder_xonly_pubkey: &XOnlyPublicKey,
    ) -> ScriptBuf {
        ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_SHA256)
            .push_slice(payment_hash)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_x_only_key(responder_xonly_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    /// Helper function to create P2TR HTLC refund script
    /// Script: <timelock> OP_CSV OP_DROP <initiator_pubkey> OP_CHECKSIG
    fn create_p2tr_htlc_refund_script(
        timelock: u32,
        initiator_xonly_pubkey: &XOnlyPublicKey,
    ) -> ScriptBuf {
        ScriptBuf::builder()
            .push_int(timelock as i64)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_x_only_key(initiator_xonly_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    }

    /// Helper function to create P2TR HTLC instant refund script
    /// Script: <initiator_pubkey> OP_CHECKSIG <responder_pubkey> OP_CHECKSIGADD OP_2 OP_NUMEQUAL
    fn create_p2tr_htlc_instant_refund_script(
        initiator_xonly_pubkey: &XOnlyPublicKey,
        responder_xonly_pubkey: &XOnlyPublicKey,
    ) -> ScriptBuf {
        ScriptBuf::builder()
            .push_x_only_key(initiator_xonly_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_x_only_key(responder_xonly_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIGADD)
            .push_int(2)
            .push_opcode(opcodes::all::OP_NUMEQUAL)
            .into_script()
    }

    /// Helper function to create P2TR HTLC Taproot spend info
    /// Creates a taproot tree with three script paths: redeem, refund, and instant refund
    fn create_p2tr_htlc_spend_info(
        payment_hash: &[u8; 32],
        initiator_xonly_pubkey: &XOnlyPublicKey,
        responder_xonly_pubkey: &XOnlyPublicKey,
        timelock: u32,
    ) -> TaprootSpendInfo {
        let secp = Secp256k1::new();

        // Create the three script paths
        let redeem_script = create_p2tr_htlc_redeem_script(payment_hash, responder_xonly_pubkey);
        let refund_script = create_p2tr_htlc_refund_script(timelock, initiator_xonly_pubkey);
        let instant_refund_script = create_p2tr_htlc_instant_refund_script(initiator_xonly_pubkey, responder_xonly_pubkey);

        // Use NUMS point as internal key (unspendable key path)
        let nums_bytes = hex::decode(NUMS_POINT_HEX).expect("Valid NUMS point hex");
        let internal_key = XOnlyPublicKey::from_slice(&nums_bytes)
            .expect("Valid NUMS point");

        // Build Taproot script tree
        // Depth 1: redeem script (most likely path)
        // Depth 2: refund and instant refund scripts
        let taproot_builder = TaprootBuilder::new()
            .add_leaf(1, redeem_script)
            .expect("Failed to add redeem leaf")
            .add_leaf(2, refund_script)
            .expect("Failed to add refund leaf")
            .add_leaf(2, instant_refund_script)
            .expect("Failed to add instant refund leaf");

        taproot_builder
            .finalize(&secp, internal_key)
            .expect("Failed to finalize taproot builder")
    }

    /// Helper function to create P2TR HTLC address and spend info
    fn create_p2tr_htlc_address(
        payment_hash: &[u8; 32],
        initiator_xonly_pubkey: &XOnlyPublicKey,
        responder_xonly_pubkey: &XOnlyPublicKey,
        timelock: u32,
        network: Network,
    ) -> (Address, TaprootSpendInfo) {
        let secp = Secp256k1::new();
        let spend_info = create_p2tr_htlc_spend_info(
            payment_hash,
            initiator_xonly_pubkey,
            responder_xonly_pubkey,
            timelock,
        );

        let address = Address::p2tr(
            &secp,
            spend_info.internal_key(),
            spend_info.merkle_root(),
            network,
        );

        (address, spend_info)
    }

    /// Helper function to create a P2TR HTLC redeem transaction (with preimage)
    fn create_p2tr_htlc_redeem_transaction(
        previous_output: OutPoint,
        previous_value: Amount,
        htlc_address: &Address,
        payment_hash: &[u8; 32],
        preimage: &[u8; 32],
        responder_xonly_pubkey: &XOnlyPublicKey,
        responder_keypair: &Keypair,
        spend_info: &TaprootSpendInfo,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
    ) -> Transaction {
        let secp = Secp256k1::new();

        // Create unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Get redeem script and control block
        let redeem_script = create_p2tr_htlc_redeem_script(payment_hash, responder_xonly_pubkey);
        let script_ver = (redeem_script.clone(), LeafVersion::TapScript);
        let control_block = spend_info
            .control_block(&script_ver)
            .expect("Failed to get control block");

        // Create prevouts for sighash
        let prevouts = vec![TxOut {
            value: previous_value,
            script_pubkey: htlc_address.script_pubkey(),
        }];
        let prevouts = Prevouts::All(&prevouts);

        // Compute taproot script spend sighash
        let leaf_hash = TapLeafHash::from_script(&redeem_script, LeafVersion::TapScript);
        let mut sighash_cache = SighashCache::new(&mut tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, TapSighashType::Default)
            .expect("Failed to create taproot sighash");

        // Sign with schnorr signature
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr_no_aux_rand(&msg, responder_keypair);

        // Build witness stack: [signature] [preimage] [script] [control_block]
        let mut witness = bitcoin::Witness::new();
        witness.push(signature.as_ref());
        witness.push(preimage);
        witness.push(redeem_script.as_bytes());
        witness.push(&control_block.serialize());

        tx.input[0].witness = witness;
        tx
    }

    /// Helper function to create a P2TR HTLC refund transaction (after timelock)
    fn create_p2tr_htlc_refund_transaction(
        previous_output: OutPoint,
        previous_value: Amount,
        htlc_address: &Address,
        timelock: u32,
        initiator_xonly_pubkey: &XOnlyPublicKey,
        initiator_keypair: &Keypair,
        spend_info: &TaprootSpendInfo,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
    ) -> Transaction {
        let secp = Secp256k1::new();

        // Create unsigned transaction with timelock in sequence
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence(timelock), // Set sequence for CSV
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Get refund script and control block
        let refund_script = create_p2tr_htlc_refund_script(timelock, initiator_xonly_pubkey);
        let script_ver = (refund_script.clone(), LeafVersion::TapScript);
        let control_block = spend_info
            .control_block(&script_ver)
            .expect("Failed to get control block");

        // Create prevouts for sighash
        let prevouts = vec![TxOut {
            value: previous_value,
            script_pubkey: htlc_address.script_pubkey(),
        }];
        let prevouts = Prevouts::All(&prevouts);

        // Compute taproot script spend sighash
        let leaf_hash = TapLeafHash::from_script(&refund_script, LeafVersion::TapScript);
        let mut sighash_cache = SighashCache::new(&mut tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, TapSighashType::Default)
            .expect("Failed to create taproot sighash");

        // Sign with schnorr signature
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        let signature = secp.sign_schnorr_no_aux_rand(&msg, initiator_keypair);

        // Build witness stack: [signature] [script] [control_block]
        let mut witness = bitcoin::Witness::new();
        witness.push(signature.as_ref());
        witness.push(refund_script.as_bytes());
        witness.push(&control_block.serialize());

        tx.input[0].witness = witness;
        tx
    }

    /// Helper function to create a P2TR HTLC instant refund transaction (requires both signatures)
    fn create_p2tr_htlc_instant_refund_transaction(
        previous_output: OutPoint,
        previous_value: Amount,
        htlc_address: &Address,
        initiator_xonly_pubkey: &XOnlyPublicKey,
        responder_xonly_pubkey: &XOnlyPublicKey,
        initiator_keypair: &Keypair,
        responder_keypair: &Keypair,
        spend_info: &TaprootSpendInfo,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
    ) -> Transaction {
        let secp = Secp256k1::new();

        // Create unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Get instant refund script and control block
        let instant_refund_script = create_p2tr_htlc_instant_refund_script(initiator_xonly_pubkey, responder_xonly_pubkey);
        let script_ver = (instant_refund_script.clone(), LeafVersion::TapScript);
        let control_block = spend_info
            .control_block(&script_ver)
            .expect("Failed to get control block");

        // Create prevouts for sighash
        let prevouts = vec![TxOut {
            value: previous_value,
            script_pubkey: htlc_address.script_pubkey(),
        }];
        let prevouts = Prevouts::All(&prevouts);

        // Compute taproot script spend sighash
        let leaf_hash = TapLeafHash::from_script(&instant_refund_script, LeafVersion::TapScript);
        let mut sighash_cache = SighashCache::new(&mut tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(0, &prevouts, leaf_hash, TapSighashType::Default)
            .expect("Failed to create taproot sighash");

        // Sign with both keypairs
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        
        let initiator_signature = secp.sign_schnorr_no_aux_rand(&msg, initiator_keypair);
        let responder_signature = secp.sign_schnorr_no_aux_rand(&msg, responder_keypair);

        // Build witness stack: [responder_sig] [initiator_sig] [script] [control_block]
        // Note: Order matters for OP_CHECKSIGADD - last signature pushed is checked first
        let mut witness = bitcoin::Witness::new();
        witness.push(responder_signature.as_ref());
        witness.push(initiator_signature.as_ref());
        witness.push(instant_refund_script.as_bytes());
        witness.push(&control_block.serialize());

        tx.input[0].witness = witness;
        tx
    }

    // ==================== P2SH HTLC Helper Functions ====================

    use bitcoin::script::PushBytesBuf;

    /// Helper function to create P2SH HTLC script
    /// Script structure:
    /// IF (redeem path)
    ///   SHA256 <payment_hash> EQUALVERIFY <responder_pubkey> CHECKSIG
    /// ELSE
    ///   IF (instant refund path)
    ///     2 <initiator_pubkey> <responder_pubkey> 2 CHECKMULTISIG
    ///   ELSE (refund path)
    ///     <timelock> CSV DROP <initiator_pubkey> CHECKSIG
    ///   ENDIF
    /// ENDIF
    fn create_p2sh_htlc_script(
        payment_hash: &[u8; 32],
        initiator_pubkey: &PublicKey,
        responder_pubkey: &PublicKey,
        timelock: u32,
    ) -> ScriptBuf {
        let bitcoin_initiator_pubkey = BitcoinPublicKey::new(*initiator_pubkey);
        let bitcoin_responder_pubkey = BitcoinPublicKey::new(*responder_pubkey);

        ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_SHA256)
            .push_slice(payment_hash)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_key(&bitcoin_responder_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_int(2)
            .push_key(&bitcoin_initiator_pubkey)
            .push_key(&bitcoin_responder_pubkey)
            .push_int(2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(timelock as i64)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_key(&bitcoin_initiator_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script()
    }

    /// Helper function to create P2SH HTLC address
    fn create_p2sh_htlc_address(
        payment_hash: &[u8; 32],
        initiator_pubkey: &PublicKey,
        responder_pubkey: &PublicKey,
        timelock: u32,
        network: Network,
    ) -> (Address, ScriptBuf) {
        let redeem_script = create_p2sh_htlc_script(
            payment_hash,
            initiator_pubkey,
            responder_pubkey,
            timelock,
        );

        let address = Address::p2sh(&redeem_script, network)
            .expect("Failed to create P2SH address");

        (address, redeem_script)
    }

    /// Helper function to create a P2SH HTLC redeem transaction (with preimage)
    fn create_p2sh_htlc_redeem_transaction(
        previous_output: OutPoint,
        previous_value: Amount,
        htlc_address: &Address,
        redeem_script: &ScriptBuf,
        payment_hash: &[u8; 32],
        preimage: &[u8; 32],
        responder_secret_key: &SecretKey,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
    ) -> Transaction {
        let secp = Secp256k1::new();

        // Create unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(), // Will be filled after signing
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Create sighash for signing
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .legacy_signature_hash(0, redeem_script, EcdsaSighashType::All.to_u32())
            .expect("Failed to create sighash");

        // Sign the transaction
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let message = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        let signature = secp.sign_ecdsa(&message, responder_secret_key);
        let ecdsa_sig = EcdsaSignature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };

        // Create script_sig: <signature> <preimage> <1> <redeem_script>
        let sig_bytes = PushBytesBuf::try_from(ecdsa_sig.serialize().to_vec()).expect("Valid signature");
        let preimage_buf = PushBytesBuf::try_from(preimage.to_vec()).expect("Valid preimage");
        let redeem_script_buf = PushBytesBuf::try_from(redeem_script.to_bytes()).expect("Valid script");
        
        let script_sig = ScriptBuf::builder()
            .push_slice(sig_bytes)
            .push_slice(preimage_buf)
            .push_int(1) // IF branch (redeem path)
            .push_slice(redeem_script_buf)
            .into_script();

        // Update the transaction with the script_sig
        tx.input[0].script_sig = script_sig;

        tx
    }

    /// Helper function to create a P2SH HTLC refund transaction (after timelock)
    fn create_p2sh_htlc_refund_transaction(
        previous_output: OutPoint,
        previous_value: Amount,
        htlc_address: &Address,
        redeem_script: &ScriptBuf,
        timelock: u32,
        initiator_secret_key: &SecretKey,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
    ) -> Transaction {
        let secp = Secp256k1::new();

        // Create unsigned transaction with timelock in sequence
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(), // Will be filled after signing
                sequence: bitcoin::Sequence(timelock), // Set sequence for CSV
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Create sighash for signing
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .legacy_signature_hash(0, redeem_script, EcdsaSighashType::All.to_u32())
            .expect("Failed to create sighash");

        // Sign the transaction
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let message = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        let signature = secp.sign_ecdsa(&message, initiator_secret_key);
        let ecdsa_sig = EcdsaSignature {
            signature,
            sighash_type: EcdsaSighashType::All,
        };

        // Create script_sig: <signature> <0> <0> <redeem_script>
        // <0> for outer ELSE (not redeem), <0> for inner ELSE (timelock refund)
        let sig_bytes = PushBytesBuf::try_from(ecdsa_sig.serialize().to_vec()).expect("Valid signature");
        let redeem_script_buf = PushBytesBuf::try_from(redeem_script.to_bytes()).expect("Valid script");
        
        let script_sig = ScriptBuf::builder()
            .push_slice(sig_bytes)
            .push_int(0) // Inner ELSE (timelock refund)
            .push_int(0) // Outer ELSE (not redeem path)
            .push_slice(redeem_script_buf)
            .into_script();

        // Update the transaction with the script_sig
        tx.input[0].script_sig = script_sig;

        tx
    }

    /// Helper function to create a P2SH HTLC instant refund transaction (requires both signatures)
    fn create_p2sh_htlc_instant_refund_transaction(
        previous_output: OutPoint,
        previous_value: Amount,
        htlc_address: &Address,
        redeem_script: &ScriptBuf,
        initiator_secret_key: &SecretKey,
        responder_secret_key: &SecretKey,
        output_value: Amount,
        output_script_pubkey: ScriptBuf,
    ) -> Transaction {
        let secp = Secp256k1::new();

        // Create unsigned transaction
        let mut tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(), // Will be filled after signing
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: output_script_pubkey,
            }],
        };

        // Create sighash for signing
        let mut sighash_cache = SighashCache::new(&tx);
        let sighash = sighash_cache
            .legacy_signature_hash(0, redeem_script, EcdsaSighashType::All.to_u32())
            .expect("Failed to create sighash");

        // Sign with both keys
        let raw_hash = sighash.to_raw_hash();
        let sighash_slice: &[u8] = raw_hash.as_ref();
        let sighash_bytes: [u8; 32] = sighash_slice.try_into().expect("Hash should be 32 bytes");
        let message = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
        
        let initiator_signature = secp.sign_ecdsa(&message, initiator_secret_key);
        let initiator_ecdsa_sig = EcdsaSignature {
            signature: initiator_signature,
            sighash_type: EcdsaSighashType::All,
        };

        let responder_signature = secp.sign_ecdsa(&message, responder_secret_key);
        let responder_ecdsa_sig = EcdsaSignature {
            signature: responder_signature,
            sighash_type: EcdsaSighashType::All,
        };

        // Create script_sig: <0> <initiator_sig> <responder_sig> <1> <0> <redeem_script>
        // <0> dummy for CHECKMULTISIG
        // <initiator_sig> and <responder_sig> for 2-of-2 multisig
        // <1> for inner IF (instant refund)
        // <0> for outer ELSE (not redeem path)
        let init_sig_bytes = PushBytesBuf::try_from(initiator_ecdsa_sig.serialize().to_vec()).expect("Valid signature");
        let resp_sig_bytes = PushBytesBuf::try_from(responder_ecdsa_sig.serialize().to_vec()).expect("Valid signature");
        let redeem_script_buf = PushBytesBuf::try_from(redeem_script.to_bytes()).expect("Valid script");
        
        let script_sig = ScriptBuf::builder()
            .push_int(0) // Dummy for CHECKMULTISIG
            .push_slice(init_sig_bytes)
            .push_slice(resp_sig_bytes)
            .push_int(1) // Inner IF (instant refund)
            .push_int(0) // Outer ELSE (not redeem path)
            .push_slice(redeem_script_buf)
            .into_script();

        // Update the transaction with the script_sig
        tx.input[0].script_sig = script_sig;

        tx
    }

    #[test]
    fn test_validate_transaction_with_valid_inputs_for_p2pkh() {
        // Create a temporary store
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Generate a key pair for P2PKH
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Create P2PKH script for the output
        let p2pkh_script = create_p2pkh_script(&public_key);

        // Create first transaction with a P2PKH output (this will be the UTXO we spend from)
        let tx1 = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000000), // 0.01 BTC
                script_pubkey: p2pkh_script.clone(),
            }],
        };

        let txid1 = tx1.compute_txid();

        // Create a share block containing tx1 to store it in the database
        let share = TestShareBlockBuilder::new()
            .add_transaction(tx1.clone())
            .build();
        
        store.add_share(share, 0);

        // Create the outpoint referencing tx1's output
        let outpoint = OutPoint::new(txid1, 0); 

        // Generate a new key pair for the output of tx2
        let recipient_secret_key = SecretKey::from_slice(&[0xab; 32]).expect("32 bytes, within curve order");
        let recipient_public_key = PublicKey::from_secret_key(&secp, &recipient_secret_key);
        let recipient_p2pkh_script = create_p2pkh_script(&recipient_public_key);

        // Create a signed P2PKH transaction that spends from tx1
        let tx2 = create_p2pkh_transaction(
            outpoint,
            Amount::from_sat(1000000),
            p2pkh_script.clone(),
            Amount::from_sat(900000), // 0.009 BTC (leaving some for fees)
            recipient_p2pkh_script.clone(),
            &secret_key,
        );

        // Validate tx2 - this should succeed because tx1's output exists in the store
        // and tx2 is properly signed
        let result = validate_raw_transaction(&tx2, &store);
        assert!(result.is_ok(), "Transaction validation should succeed with properly signed P2PKH transaction");

        // changing the outpoint and trying to spend it 
        let outpoint2 = OutPoint::new(txid1, 1);
        let tx3 = create_p2pkh_transaction(
            outpoint2,
            Amount::from_sat(1000000),
            p2pkh_script.clone(),
            Amount::from_sat(900000), // 0.009 BTC (leaving some for fees)
            recipient_p2pkh_script.clone(),
            &secret_key,
        );
        let result2 = validate_raw_transaction(&tx3, &store);
        assert!(result2.is_err(), "Transaction validation should fail with invalid outpoint");

        // changing the signer and trying to spend it 
        let secret_key2 = SecretKey::new(&mut rand::thread_rng());
        let tx4 = create_p2pkh_transaction(
            outpoint,
            Amount::from_sat(1000000),
            p2pkh_script.clone(),
            Amount::from_sat(900000), // 0.009 BTC (leaving some for fees)
            recipient_p2pkh_script,
            &secret_key2,
        );
        let result3 = validate_raw_transaction(&tx4, &store);
        assert!(result3.is_err(), "Transaction validation should fail with invalid signer");
    
    }

    #[test]
    fn test_validate_transaction_with_valid_inputs_for_p2tr() {
        // Create a temporary store
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Generate a keypair for P2TR
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp,&mut rand::thread_rng());
        let (internal_key, _parity) = keypair.x_only_public_key();

        // Create P2TR script for the output
        let p2tr_script = create_p2tr_script(&secp, &internal_key);

        // Create first transaction with a P2TR output (this will be the UTXO we spend from)
        let tx1 = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000000), // 0.01 BTC
                script_pubkey: p2tr_script.clone(),
            }],
        };

        let txid1 = tx1.compute_txid();

        // Create a share block containing tx1 to store it in the database
        let share = TestShareBlockBuilder::new()
            .add_transaction(tx1.clone())
            .build();
        
        store.add_share(share, 0);

        // Create the outpoint referencing tx1's output
        let outpoint = OutPoint::new(txid1, 0);

        // Generate a new keypair for the output of tx2
        let recipient_keypair = Keypair::from_seckey_slice(&secp, &[0xab; 32]).expect("32 bytes, within curve order");
        let (recipient_internal_key, _parity) = recipient_keypair.x_only_public_key();
        let recipient_p2tr_script = create_p2tr_script(&secp, &recipient_internal_key);

        // Create a signed P2TR transaction that spends from tx1
        let tx2 = create_p2tr_keypath_transaction(
            outpoint,
            Amount::from_sat(1000000),
            p2tr_script.clone(),
            Amount::from_sat(900000), // 0.009 BTC (leaving some for fees)
            recipient_p2tr_script.clone(),
            &keypair,
        );

        // Validate tx2 - this should succeed because tx1's output exists in the store
        // and tx2 is properly signed with Schnorr signature
        let result = validate_raw_transaction(&tx2, &store);
        assert!(result.is_ok(), "Transaction validation should succeed with properly signed P2TR transaction");

        // changing the outpoint and trying to spend it 
        let outpoint2 = OutPoint::new(txid1, 1);
        let tx3 = create_p2tr_keypath_transaction(
            outpoint2,
            Amount::from_sat(1000000),
            p2tr_script.clone(),
            Amount::from_sat(900000), // 0.009 BTC (leaving some for fees)
            recipient_p2tr_script.clone(),
            &keypair,
        );
        let result2 = validate_raw_transaction(&tx3, &store);
        assert!(result2.is_err(), "Transaction validation should fail with invalid outpoint");

        // changing the signer and trying to spend it 
        let keypair2 = Keypair::new(&secp,&mut rand::thread_rng());
        let tx4 = create_p2tr_keypath_transaction(
            outpoint,
            Amount::from_sat(1000000),
            p2tr_script.clone(),
            Amount::from_sat(900000), // 0.009 BTC (leaving some for fees)
            recipient_p2tr_script.clone(),
            &keypair2,
        );
        let result3 = validate_raw_transaction(&tx4, &store);
        assert!(result3.is_err(), "Transaction validation should fail with invalid signer");

    }
    #[test]
    fn test_validate_transaction_with_valid_inputs_for_p2tr_htlc_redeem() {
        // Create a temporary store
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Generate a keypair for P2TR
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp,&mut rand::thread_rng());
        let (internal_key, _parity) = keypair.x_only_public_key();

        // Create P2TR htlc script for the output
        let payment_hash =hex::decode("7915795b88df5d718a5741601c1492dda3a821047f19bb8662675a7017b8c4f2").expect("Valid payment hash").try_into().expect("32 bytes");
        let initiator_keypair = Keypair::new(&secp,&mut rand::thread_rng());
        let responder_keypair = Keypair::new(&secp,&mut rand::thread_rng());
        let (initiator_xonly_pubkey, _parity) = initiator_keypair.x_only_public_key();
        let (responder_xonly_pubkey, _parity) = responder_keypair.x_only_public_key();
        let timelock = 144; // ~1 day in blocks
        let htlc_address = create_p2tr_htlc_address(&payment_hash, &initiator_xonly_pubkey, &responder_xonly_pubkey, timelock, Network::Bitcoin);


        // Create first transaction with a P2TR output (this will be the UTXO we spend from)
        let tx1 = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(1000000), // 0.01 BTC
                script_pubkey:htlc_address.0.script_pubkey(),
            }],
        };

        let txid1 = tx1.compute_txid();

        let outpoint = OutPoint::new(txid1, 0);

        // Create a share block containing tx1 to store it in the database
        let share = TestShareBlockBuilder::new()
            .add_transaction(tx1.clone())
            .build();
        
        store.add_share(share, 0);

        let preimage = hex::decode("4e354fd328ed29baaef6424a058de1e36d9f072729b62828873caeb4ce497814").expect("Valid payment hash").try_into().expect("32 bytes");

        // constructing the redeem transaction for the htlc 
        let redeem_transaction = create_p2tr_htlc_redeem_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &htlc_address.0,
            &payment_hash,
            &preimage,
            &responder_xonly_pubkey,
            &responder_keypair,
            &htlc_address.1,
            Amount::from_sat(900000),
            htlc_address.0.script_pubkey().clone(),
        );

        // validating the redeem transaction
        let result = validate_raw_transaction(&redeem_transaction, &store);
        assert!(result.is_ok(), "Transaction validation should succeed with properly signed P2TR HTLC redeem transaction: {:?}", result);

        //changing the signature and trying to redeem it 
        let redeem_transaction = create_p2tr_htlc_redeem_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &htlc_address.0,
            &payment_hash,
            &preimage,
            &responder_xonly_pubkey, // Using correct pubkey for script, but wrong keypair for signing
            &initiator_keypair,
            &htlc_address.1,
            Amount::from_sat(900000),
            htlc_address.0.script_pubkey().clone(),
        );

        let result2 = validate_raw_transaction(&redeem_transaction, &store);
        println!("result2: {:?}", result2);
        assert!(result2.is_err(), "Transaction validation should fail with invalid signature");

 
        // change the preimage and trying to redeem it 
        let preimage = hex::decode("4e354fd328ed29baaef6424a058de1e36d9f072729b62828873caeb4ce497815").expect("Valid payment hash").try_into().expect("32 bytes");

        let redeem_transaction = create_p2tr_htlc_redeem_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &htlc_address.0,
            &payment_hash,
            &preimage,
            &responder_xonly_pubkey,
            &responder_keypair,
            &htlc_address.1,
            Amount::from_sat(900000),
            htlc_address.0.script_pubkey().clone(),
        );

        let result3 = validate_raw_transaction(&redeem_transaction, &store);
        assert!(result3.is_err(), "Transaction validation should fail with invalid preimage"); // This is failing as of now

        // trying to refund the htlc
        let refund_transaction = create_p2tr_htlc_refund_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &htlc_address.0,
            timelock,
            &initiator_xonly_pubkey,
            &initiator_keypair,
            &htlc_address.1,
            Amount::from_sat(900000),
            htlc_address.0.script_pubkey().clone(),
        );

        let result5 = validate_raw_transaction(&refund_transaction, &store);
        assert!(result5.is_ok(), "Transaction validation should fail with invalid refund");

    }

    #[test]
    fn test_validate_transaction_with_valid_inputs_for_p2sh() {
        // Create a temporary store
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Generate a keypair for P2SH
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp,&mut rand::thread_rng());

        // creating a p2pkh
         // Create a temporary store
         let temp_dir = tempdir().unwrap();
         let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();
 
         // Generate a key pair for P2PKH
         let secp = Secp256k1::new();
         let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
         let public_key = PublicKey::from_secret_key(&secp, &secret_key);
 
         // Create p2sh script for the output
         let payment_hash =hex::decode("8daf20cef6bda0556306fa77141a573d9f445b53fff070f5c2e6b022fb75880c").expect("Valid payment hash").try_into().expect("32 bytes");
         let initiator_keypair = Keypair::new(&secp,&mut rand::thread_rng());
         let initiator_pubkey = initiator_keypair.public_key();
         let responder_keypair = Keypair::new(&secp,&mut rand::thread_rng());
         let responder_pubkey = responder_keypair.public_key();

         let p2sh_script = create_p2sh_htlc_address(
            &payment_hash,
            &initiator_pubkey,
            &responder_pubkey,
            144,
            Network::Bitcoin,
         );
 
         // Create first transaction with a P2PKH output (this will be the UTXO we spend from)
         let tx1 = Transaction {
             version: bitcoin::transaction::Version(2),
             lock_time: bitcoin::absolute::LockTime::ZERO,
             input: vec![],
             output: vec![TxOut {
                 value: Amount::from_sat(1000000), // 0.01 BTC
                 script_pubkey: p2sh_script.0.script_pubkey().clone(),
             }],
         };
 
         let txid1 = tx1.compute_txid();
 
         // Create a share block containing tx1 to store it in the database
         let share = TestShareBlockBuilder::new()
             .add_transaction(tx1.clone())
             .build();
         
         store.add_share(share, 0);
 
        // Create the outpoint referencing tx1's output
        let outpoint = OutPoint::new(txid1, 0); 

        // constructing the redeem transaction for the htlc
        let preimage = hex::decode("e2033db8b6ce237e6e26b84bb80c6d3b7a75dd51bcbf0652e24859eaaaad0a31").expect("Valid payment hash").try_into().expect("32 bytes");
        let redeem_transaction = create_p2sh_htlc_redeem_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            &payment_hash,
            &preimage,
            &responder_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result = validate_raw_transaction(&redeem_transaction, &store);
        assert!(result.is_ok(), "Transaction validation should succeed with properly signed P2SH HTLC redeem transaction: {:?}", result);

        // changing the signature and trying to redeem it 
        let redeem_transaction = create_p2sh_htlc_redeem_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            &payment_hash,
            &preimage,
            &initiator_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result2 = validate_raw_transaction(&redeem_transaction, &store);
        assert!(result2.is_err(), "Transaction validation should fail with invalid signature");

        // changing the preimage and trying to redeem it 
        let preimage = hex::decode("e2033db8b6ce237e6e26b84bb80c6d3b7a75dd51bcbf0652e24859eaaaad0a32").expect("Valid payment hash").try_into().expect("32 bytes");
        let redeem_transaction = create_p2sh_htlc_redeem_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            &payment_hash,
            &preimage,
            &responder_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result3 = validate_raw_transaction(&redeem_transaction, &store);
        assert!(result3.is_err(), "Transaction validation should fail with invalid preimage");

        // trying for instant refund
        let instant_refund_transaction = create_p2sh_htlc_instant_refund_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            &initiator_keypair.secret_key(),
            &responder_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result4 = validate_raw_transaction(&instant_refund_transaction, &store);
        assert!(result4.is_ok(), "Transaction validation should succeed with properly signed P2SH HTLC instant refund transaction: {:?}", result4);

        // changing the signature and trying to redeem it 
        let instant_refund_transaction = create_p2sh_htlc_instant_refund_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            &initiator_keypair.secret_key(),
            &responder_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result5 = validate_raw_transaction(&instant_refund_transaction, &store);
        assert!(result5.is_ok(), "Transaction validation pass for instant refund");

        // instant refund with wrong signature
        let instant_refund_transaction = create_p2sh_htlc_instant_refund_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            &responder_keypair.secret_key(),
            &initiator_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result6 = validate_raw_transaction(&instant_refund_transaction, &store);
        assert!(result6.is_err(), "Transaction validation should fail with invalid signature");

        // constructing the refund transaction
        let refund_transaction = create_p2sh_htlc_refund_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            144,
            &initiator_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        
        let result7 = validate_raw_transaction(&refund_transaction, &store);
        assert!(result7.is_ok(), "Transaction validation should succeed with properly signed P2SH HTLC refund transaction: {:?}", result7);

        // checking for inalidate time lock 
        let refund_transaction = create_p2sh_htlc_refund_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            143,
            &initiator_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result8 = validate_raw_transaction(&refund_transaction, &store);
        assert!(result8.is_err(), "Transaction validation should fail with invalid time lock");

        // checking for invalid signature
        let refund_transaction = create_p2sh_htlc_refund_transaction(
            outpoint,
            Amount::from_sat(1000000),
            &p2sh_script.0,
            &p2sh_script.1,
            144,
            &responder_keypair.secret_key(),
            Amount::from_sat(900000),
            p2sh_script.0.script_pubkey().clone(),
        );
        let result9 = validate_raw_transaction(&refund_transaction, &store);
        assert!(result9.is_err(), "Transaction validation should fail with invalid signature");

    
    }

}


