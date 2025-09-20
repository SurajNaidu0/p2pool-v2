// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

use crate::bitcoin::p2tr2;
use crate::bitcoin::p2wsh2;
use crate::bitcoin::utils::Utxo;
use crate::swap::{HTLCType, Swap};
use ldk_node::bitcoin::{Address, KnownHrp, Transaction};
use std::error::Error;


pub fn generate_htlc_address(swap: &Swap) -> Result<Address, Box<dyn Error>> {
    // need to removed
    let network = KnownHrp::Testnets;
    match swap.from_chain.htlc_type {
        HTLCType::P2tr2 => {
            // Call P2TR2 address generation from p2tr2.rs
            let address = p2tr2::generate_p2tr_address(swap, network)?.0;
            return Ok(address);
        }
        HTLCType::P2wsh2 => {
            let address = p2wsh2::generate_p2wsh_address(&swap.from_chain, &swap.payment_hash, network)?;
            return Ok(address);
        }
    }
}

pub fn redeem_htlc_address(
    swap: &Swap,
    preimage: &str,
    receiver_private_key: &str,
    utxos: Vec<Utxo>,
    transfer_to_address: &Address,
) -> Result<Transaction, Box<dyn Error>> {
    // need to removed
    let network = KnownHrp::Testnets;
    match swap.from_chain.htlc_type {
        HTLCType::P2tr2 => {
            // Call P2TR2 address generation from p2tr2.rs
            p2tr2::redeem_taproot_htlc(
                swap,
                preimage,
                receiver_private_key,
                utxos,
                transfer_to_address,
                3,
                network,
            )
            .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        HTLCType::P2wsh2 => {
             p2wsh2::redeem_p2wsh_htlc(
                &swap.from_chain,
                &swap.payment_hash,
                preimage,
                receiver_private_key,
                utxos,
                transfer_to_address,
                3,
                network
            ).map_err(|e| Box::new(e) as Box<dyn Error>)
        }
    }
}

pub fn refund_htlc_address(
    swap: &Swap,
    sender_private_key: &str,
    utxos: Vec<Utxo>,
    transfer_to_address: &Address,
) -> Result<Transaction, Box<dyn Error>> {
    // need to removed
    let network = KnownHrp::Testnets;
    match swap.from_chain.htlc_type {
        HTLCType::P2tr2 => {
            // Call P2TR2 address generation from p2tr2.rs
            p2tr2::refund_taproot_htlc(
                swap,
                sender_private_key,
                utxos,
                transfer_to_address,
                3,
                network,
            )
            .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        HTLCType::P2wsh2 => {
            p2wsh2::refund_p2wsh_htlc(
                &swap.from_chain,
                &swap.payment_hash,
                sender_private_key,
                utxos,
                transfer_to_address,
                3,
                network
            )
            .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swap::{Bitcoin, Lightning, Swap};

    // Helper function to create a mock Bitcoin struct
    fn create_mock_bitcoin() -> Bitcoin {
        Bitcoin {
            initiator_pubkey: "0280b2aa1b37d358607896a0747f6104d576fd1b887792e3b2fdc37c7170a8a4d7".to_string(),
            responder_pubkey: "03d168e6449eae4d673b0020c7e7cbf0b4ba11fddf762450a1cce444b8206d3e0f".to_string(),
            timelock: 144,
            amount: 10000,
            htlc_type: HTLCType::P2wsh2,
        }
    }

    // Helper function to create a mock Swap struct
    fn create_mock_swap() -> Swap {
        Swap {
            payment_hash: "c3a704c5669f96c853fd03521e2318f784e1fe743568fdea9fe3eca2850b3368".to_string(),
            from_chain: create_mock_bitcoin(),
            to_chain: Lightning {
                timelock: 144,
                amount: 10000,
            },
        }
    }

    #[test]
    fn test_p2wsh_htlc_address() {
        let swap_struct = create_mock_swap();
        let address = generate_htlc_address(&swap_struct).expect("Error generating HTLC address");
        assert_eq!(address.to_string(), "tb1qvcdnft8sszsjrfy0k6dw8t3qkf76au6j7axycgy0qtwdyvtvn2rsumwnly");
    }

}


