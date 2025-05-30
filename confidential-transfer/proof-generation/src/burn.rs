#[cfg(target_arch = "wasm32")]
use solana_zk_sdk::encryption::grouped_elgamal::GroupedElGamalCiphertext3Handles;
use {
    crate::{
        encryption::BurnAmountCiphertext, errors::TokenProofGenerationError,
        try_combine_lo_hi_ciphertexts, try_split_u64, CiphertextValidityProofWithAuditorCiphertext,
    },
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
            pedersen::Pedersen,
        },
        zk_elgamal_proof_program::proof_data::{
            BatchedGroupedCiphertext3HandlesValidityProofData, BatchedRangeProofU128Data,
            CiphertextCommitmentEqualityProofData, ZkProofData,
        },
    },
};

const REMAINING_BALANCE_BIT_LENGTH: usize = 64;
const BURN_AMOUNT_LO_BIT_LENGTH: usize = 16;
const BURN_AMOUNT_HI_BIT_LENGTH: usize = 32;
/// The padding bit length in range proofs to make the bit-length power-of-2
const RANGE_PROOF_PADDING_BIT_LENGTH: usize = 16;

/// The proof data required for a confidential burn instruction
pub struct BurnProofData {
    pub equality_proof_data: CiphertextCommitmentEqualityProofData,
    pub ciphertext_validity_proof_data_with_ciphertext:
        CiphertextValidityProofWithAuditorCiphertext,
    pub range_proof_data: BatchedRangeProofU128Data,
}

pub fn burn_split_proof_data(
    current_available_balance_ciphertext: &ElGamalCiphertext,
    current_decryptable_available_balance: &AeCiphertext,
    burn_amount: u64,
    source_elgamal_keypair: &ElGamalKeypair,
    source_aes_key: &AeKey,
    supply_elgamal_pubkey: &ElGamalPubkey,
    auditor_elgamal_pubkey: Option<&ElGamalPubkey>,
) -> Result<BurnProofData, TokenProofGenerationError> {
    let default_auditor_pubkey = ElGamalPubkey::default();
    let auditor_elgamal_pubkey = auditor_elgamal_pubkey.unwrap_or(&default_auditor_pubkey);

    // split the burn amount into low and high bits
    let (burn_amount_lo, burn_amount_hi) = try_split_u64(burn_amount, BURN_AMOUNT_LO_BIT_LENGTH)
        .ok_or(TokenProofGenerationError::IllegalAmountBitLength)?;


    let (burn_amount_ciphertext_lo, burn_amount_opening_lo) = BurnAmountCiphertext::new(
        burn_amount_lo,
        source_elgamal_keypair.pubkey(),
        supply_elgamal_pubkey,
        auditor_elgamal_pubkey,
    );
    
    let (burn_amount_ciphertext_hi, burn_amount_opening_hi) = BurnAmountCiphertext::new(
        burn_amount_hi,
        source_elgamal_keypair.pubkey(),
        supply_elgamal_pubkey,
        auditor_elgamal_pubkey,
    );
    
    
    #[cfg(not(target_arch = "wasm32"))]
    let grouped_ciphertext_hi = burn_amount_ciphertext_hi.0;
    
    #[cfg(target_arch = "wasm32")]
    let grouped_ciphertext_hi = GroupedElGamalCiphertext3Handles::encryption_with_u64(
        source_elgamal_keypair.pubkey(),
        supply_elgamal_pubkey,
        auditor_elgamal_pubkey,
        burn_amount_hi,
        &burn_amount_opening_hi,
    );

    #[cfg(not(target_arch = "wasm32"))]
    let grouped_ciphertext_lo = burn_amount_ciphertext_lo.0;

    #[cfg(target_arch = "wasm32")]
    let grouped_ciphertext_lo = GroupedElGamalCiphertext3Handles::encryption_with_u64(
        source_elgamal_keypair.pubkey(),
        supply_elgamal_pubkey,
        auditor_elgamal_pubkey,
        burn_amount_lo,
        &burn_amount_opening_lo,
    );

    // decrypt the current available balance at the source
    let current_decrypted_available_balance = current_decryptable_available_balance
        .decrypt(source_aes_key)
        .ok_or(TokenProofGenerationError::IllegalAmountBitLength)?;

    // compute the remaining balance ciphertext
    let burn_amount_ciphertext_source_lo = burn_amount_ciphertext_lo
        .0
        .to_elgamal_ciphertext(0)
        .unwrap();
    let burn_amount_ciphertext_source_hi = burn_amount_ciphertext_hi
        .0
        .to_elgamal_ciphertext(0)
        .unwrap();

    #[allow(clippy::arithmetic_side_effects)]
    let new_available_balance_ciphertext = current_available_balance_ciphertext
        - try_combine_lo_hi_ciphertexts(
            &burn_amount_ciphertext_source_lo,
            &burn_amount_ciphertext_source_hi,
            BURN_AMOUNT_LO_BIT_LENGTH,
        )
        .ok_or(TokenProofGenerationError::IllegalAmountBitLength)?;

    // compute the remaining balance at the source
    let remaining_balance = current_decrypted_available_balance
        .checked_sub(burn_amount)
        .ok_or(TokenProofGenerationError::NotEnoughFunds)?;

    let (new_available_balance_commitment, new_available_balance_opening) =
        Pedersen::new(remaining_balance);

    // generate equality proof data
    let equality_proof_data = CiphertextCommitmentEqualityProofData::new(
        source_elgamal_keypair,
        &new_available_balance_ciphertext,
        &new_available_balance_commitment,
        &new_available_balance_opening,
        remaining_balance,
    )
    .map_err(TokenProofGenerationError::from)?;

    // generate ciphertext validity data
    let ciphertext_validity_proof_data = BatchedGroupedCiphertext3HandlesValidityProofData::new(
        source_elgamal_keypair.pubkey(),
        supply_elgamal_pubkey,
        auditor_elgamal_pubkey,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        burn_amount_lo,
        burn_amount_hi,
        &burn_amount_opening_lo,
        &burn_amount_opening_hi,
    )
    .map_err(TokenProofGenerationError::from)?;

    let burn_amount_auditor_ciphertext_lo = ciphertext_validity_proof_data
        .context_data()
        .grouped_ciphertext_lo
        .try_extract_ciphertext(2)
        .map_err(|_| TokenProofGenerationError::CiphertextExtraction)?;

    let burn_amount_auditor_ciphertext_hi = ciphertext_validity_proof_data
        .context_data()
        .grouped_ciphertext_hi
        .try_extract_ciphertext(2)
        .map_err(|_| TokenProofGenerationError::CiphertextExtraction)?;

    let ciphertext_validity_proof_data_with_ciphertext =
        CiphertextValidityProofWithAuditorCiphertext {
            proof_data: ciphertext_validity_proof_data,
            ciphertext_lo: burn_amount_auditor_ciphertext_lo,
            ciphertext_hi: burn_amount_auditor_ciphertext_hi,
        };

    // generate range proof data
    let (padding_commitment, padding_opening) = Pedersen::new(0_u64);
    let range_proof_data = BatchedRangeProofU128Data::new(
        vec![
            &new_available_balance_commitment,
            burn_amount_ciphertext_lo.get_commitment(),
            burn_amount_ciphertext_hi.get_commitment(),
            &padding_commitment,
        ],
        vec![remaining_balance, burn_amount_lo, burn_amount_hi, 0],
        vec![
            REMAINING_BALANCE_BIT_LENGTH,
            BURN_AMOUNT_LO_BIT_LENGTH,
            BURN_AMOUNT_HI_BIT_LENGTH,
            RANGE_PROOF_PADDING_BIT_LENGTH,
        ],
        vec![
            &new_available_balance_opening,
            &burn_amount_opening_lo,
            &burn_amount_opening_hi,
            &padding_opening,
        ],
    )
    .map_err(TokenProofGenerationError::from)?;

    Ok(BurnProofData {
        equality_proof_data,
        ciphertext_validity_proof_data_with_ciphertext,
        range_proof_data,
    })
}
