//! Offchain helper for fetching required accounts to build instructions

pub use spl_transfer_hook_interface::offchain::{AccountDataResult, AccountFetchError};
use {
    crate::{
        extension::{transfer_fee, transfer_hook, StateWithExtensions},
        state::Mint,
    },
    solana_instruction::Instruction,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
    spl_transfer_hook_interface::offchain::add_extra_account_metas_for_execute,
    std::future::Future,
};

/// Offchain helper to create a `TransferChecked` instruction with all
/// additional required account metas for a transfer, including the ones
/// required by the transfer hook.
///
/// To be client-agnostic and to avoid pulling in the full solana-sdk, this
/// simply takes a function that will return its data as `Future<Vec<u8>>` for
/// the given address. Can be called in the following way:
///
/// ```rust,ignore
/// let instruction = create_transfer_checked_instruction_with_extra_metas(
///     &spl_token_2022::id(),
///     &source,
///     &mint,
///     &destination,
///     &authority,
///     &[],
///     amount,
///     decimals,
///     |address| self.client.get_account(&address).map_ok(|opt| opt.map(|acc| acc.data)),
/// )
/// .await?
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn create_transfer_checked_instruction_with_extra_metas<F, Fut>(
    token_program_id: &Pubkey,
    source_pubkey: &Pubkey,
    mint_pubkey: &Pubkey,
    destination_pubkey: &Pubkey,
    authority_pubkey: &Pubkey,
    signer_pubkeys: &[&Pubkey],
    amount: u64,
    decimals: u8,
    fetch_account_data_fn: F,
) -> Result<Instruction, AccountFetchError>
where
    F: Fn(Pubkey) -> Fut,
    Fut: Future<Output = AccountDataResult>,
{
    let mut transfer_instruction = crate::instruction::transfer_checked(
        token_program_id,
        source_pubkey,
        mint_pubkey,
        destination_pubkey,
        authority_pubkey,
        signer_pubkeys,
        amount,
        decimals,
    )?;

    add_extra_account_metas(
        &mut transfer_instruction,
        source_pubkey,
        mint_pubkey,
        destination_pubkey,
        authority_pubkey,
        amount,
        fetch_account_data_fn,
    )
    .await?;

    Ok(transfer_instruction)
}

/// Offchain helper to create a `TransferCheckedWithFee` instruction with all
/// additional required account metas for a transfer, including the ones
/// required by the transfer hook.
///
/// To be client-agnostic and to avoid pulling in the full solana-sdk, this
/// simply takes a function that will return its data as `Future<Vec<u8>>` for
/// the given address. Can be called in the following way:
///
/// ```rust,ignore
/// let instruction = create_transfer_checked_with_fee_instruction_with_extra_metas(
///     &spl_token_2022::id(),
///     &source,
///     &mint,
///     &destination,
///     &authority,
///     &[],
///     amount,
///     decimals,
///     fee,
///     |address| self.client.get_account(&address).map_ok(|opt| opt.map(|acc| acc.data)),
/// )
/// .await?
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn create_transfer_checked_with_fee_instruction_with_extra_metas<F, Fut>(
    token_program_id: &Pubkey,
    source_pubkey: &Pubkey,
    mint_pubkey: &Pubkey,
    destination_pubkey: &Pubkey,
    authority_pubkey: &Pubkey,
    signer_pubkeys: &[&Pubkey],
    amount: u64,
    decimals: u8,
    fee: u64,
    fetch_account_data_fn: F,
) -> Result<Instruction, AccountFetchError>
where
    F: Fn(Pubkey) -> Fut,
    Fut: Future<Output = AccountDataResult>,
{
    let mut transfer_instruction = transfer_fee::instruction::transfer_checked_with_fee(
        token_program_id,
        source_pubkey,
        mint_pubkey,
        destination_pubkey,
        authority_pubkey,
        signer_pubkeys,
        amount,
        decimals,
        fee,
    )?;

    add_extra_account_metas(
        &mut transfer_instruction,
        source_pubkey,
        mint_pubkey,
        destination_pubkey,
        authority_pubkey,
        amount,
        fetch_account_data_fn,
    )
    .await?;

    Ok(transfer_instruction)
}

/// Offchain helper to add required account metas to an instruction, including
/// the ones required by the transfer hook.
///
/// To be client-agnostic and to avoid pulling in the full solana-sdk, this
/// simply takes a function that will return its data as `Future<Vec<u8>>` for
/// the given address. Can be called in the following way:
///
/// ```rust,ignore
/// let mut transfer_instruction = spl_token_2022::instruction::transfer_checked(
///     &spl_token_2022::id(),
///     source_pubkey,
///     mint_pubkey,
///     destination_pubkey,
///     authority_pubkey,
///     signer_pubkeys,
///     amount,
///     decimals,
/// )?;
/// add_extra_account_metas(
///     &mut transfer_instruction,
///     source_pubkey,
///     mint_pubkey,
///     destination_pubkey,
///     authority_pubkey,
///     amount,
///     fetch_account_data_fn,
/// ).await?;
/// ```
pub async fn add_extra_account_metas<F, Fut>(
    instruction: &mut Instruction,
    source_pubkey: &Pubkey,
    mint_pubkey: &Pubkey,
    destination_pubkey: &Pubkey,
    authority_pubkey: &Pubkey,
    amount: u64,
    fetch_account_data_fn: F,
) -> Result<(), AccountFetchError>
where
    F: Fn(Pubkey) -> Fut,
    Fut: Future<Output = AccountDataResult>,
{
    let mint_data = fetch_account_data_fn(*mint_pubkey)
        .await?
        .ok_or(ProgramError::InvalidAccountData)?;
    let mint = StateWithExtensions::<Mint>::unpack(&mint_data)?;

    if let Some(program_id) = transfer_hook::get_program_id(&mint) {
        add_extra_account_metas_for_execute(
            instruction,
            &program_id,
            source_pubkey,
            mint_pubkey,
            destination_pubkey,
            authority_pubkey,
            amount,
            fetch_account_data_fn,
        )
        .await?;
    }

    Ok(())
}
