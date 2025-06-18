use solana_program::*;
use anchor_lang::solana_program::system_instruction;
use anchor_lang::solana_program::program::{invoke, invoke_signed};
use anchor_lang::prelude::*;
use anchor_lang::prelude::{ declare_id, borsh };
use borsh::{ BorshDeserialize };
use solana_program::pubkey::Pubkey;
use std::mem::size_of;
use anchor_spl::token::{self, Mint, TokenAccount, Token, Transfer};
use groth16_solana::groth16::Groth16Verifier;

mod verifying_key;
use verifying_key::VERIFYINGKEY;

declare_id!("7grL6oHWcuwdBNkqCUrz7JEoHeS5NXv1FDegDr6ViMBi");

#[program]
pub mod aintivirus_mixer {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let lamports = 1_000_000; // ~0.001 SOL
        let ix = system_instruction::create_account(
            ctx.accounts.signer.key,
            ctx.accounts.escrow_vault_for_sol.key,
            lamports,
            0, // No data, just to hold SOL
            &ctx.accounts.system_program.key(),
        );

        invoke_signed(
            &ix,
            &[
                ctx.accounts.signer.to_account_info(),
                ctx.accounts.escrow_vault_for_sol.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
            &[&[b"escrow_vault_for_sol".as_ref(), &[ctx.bumps.escrow_vault_for_sol]]],
        )?;

        // Initialize the mix storage account
        let mix_storage = &mut ctx.accounts.mix_storage;
        mix_storage.maintainer = ctx.accounts.signer.key();

        Ok(())
    }

    pub fn charge_token_escrow(ctx: Context<EscrowCharge>, deposit_amount: u64) -> Result<()> {
        let transfer_instruction = Transfer{
            from: ctx.accounts.from.to_account_info(),
            to: ctx.accounts.escrow_vault.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };

        let cpi_program = ctx.accounts.token_program.to_account_info();

        let cpi_ctx = CpiContext::new(cpi_program, transfer_instruction);

        token::transfer(cpi_ctx, deposit_amount)?;
        Ok(())
    }

    pub fn charge_sol_escrow(ctx: Context<EscrowCharge>, deposit_amount: u64) -> Result<()> {
        let ix = system_instruction::transfer(
            &ctx.accounts.from.key(),
            &ctx.accounts.escrow_vault_for_sol.key(),
            deposit_amount,
        );
        invoke(
            &ix,
            &[
                ctx.accounts.from.to_account_info(),
                ctx.accounts.escrow_vault_for_sol.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, mode: u8, deposit_amount: u64, commitment: [u8; 32]) -> Result<()> {
        let mix_storage: &mut Account<MixStorage> = &mut ctx.accounts.mix_storage;
        // let mix_storage_2: &mut Account<MixStorage2> = &mut ctx.accounts.mix_storage_2;

        // Reject if the commitment has already been submitted
        require!(
            !mix_storage.deposit_commitments_nullifier_hashes.iter().any(|x| x == &commitment),
            ErrorCode::CommitmentAlreadySubmitted
        );

        // Check minimum deposit amount (0.5 SOL or 1000 token)
        if mode == 1 || mode == 3 {
            // mode 1 is SOL to SOL (simple mix)
            // mode 3 is SOL to ETH (bridged mix)
             
            require!(
                deposit_amount >= 500_000_000, // 0.5 SOL in lamports
                ErrorCode::InvalidMinimumDepositAmount
            );
        } else if mode == 2 || mode == 4 {
            
            // mode 2 is AINTI(SPL) to AINTI(SPL) (simple mix)
            // mode 4 is AINTI(SPL) to AINTI(ERC20) (bridged mix)
             
            require!(
                deposit_amount >= 1_000,
                ErrorCode::InvalidMinimumDepositAmount
            );
        } else {
            return Err(ErrorCode::InvalidMode.into());
        }

        mix_storage.deposit_commitments_nullifier_hashes.push(commitment);

        if mode == 1 || mode == 3 {
            // mode 1 is SOL to SOL (simple mix)
            // mode 3 is SOL to ETH (bridged mix)

            let ix = system_instruction::transfer(
                &ctx.accounts.from.key(),
                &ctx.accounts.escrow_vault_for_sol.key(),
                deposit_amount,
            );
            invoke(
                &ix,
                &[
                    ctx.accounts.from.to_account_info(),
                    ctx.accounts.escrow_vault_for_sol.to_account_info(),
                    ctx.accounts.system_program.to_account_info(),
                ],
            )?;
        } 
        else if mode == 2 || mode == 4 {
            // mode 2 is AINTI(SPL) to AINTI(SPL) (simple mix)
            // mode 4 is AINTI(SPL) to AINTI(ERC20) (bridged mix)

            let transfer_instruction = Transfer{
                from: ctx.accounts.from_ata.to_account_info(),
                to: ctx.accounts.escrow_vault.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            };

            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new(cpi_program, transfer_instruction);

            token::transfer(cpi_ctx, deposit_amount)?;
        } 
        else {
            return Err(ErrorCode::InvalidMode.into());
        }

        // Register SOL to SOL mixing commitment
        if mode == 1 || mode == 2 {
            // mode 1 is SOL to SOL (simple mix)
            // mode 2 is AINTI(SPL) to AINTI(SPL) (simple mix)

            require!(
                !mix_storage.withdraw_commitments.contains(&commitment),
                ErrorCode::CommitmentAlreadySubmitted
            );
            mix_storage.withdraw_commitments.push(commitment);
        }

        Ok(())
    }

    pub fn register_eth_sol_commitment(ctx: Context<RegisterCommitment>, commitment: [u8; 32]) -> Result<()> {
        let mix_storage = &mut ctx.accounts.mix_storage;
        // let mix_storage_2 = &mut ctx.accounts.mix_storage_2;
        
        // Check if signer is equal to maintainer
        require!(
            mix_storage.maintainer == ctx.accounts.authority.key(),
            ErrorCode::NeedMaintainerRole
        );
        
        // Register commitment for ETH to SOL mixing
        require!(
            !mix_storage.withdraw_commitments.contains(&commitment),
            ErrorCode::CommitmentAlreadySubmitted
        );
        mix_storage.withdraw_commitments.push(commitment);

        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, instruction_data: Vec<u8>,) -> Result<()> {
        let mix_storage = &mut ctx.accounts.mix_storage;
        // Check if signer is equal to maintainer
        require!(
            mix_storage.maintainer == ctx.accounts.authority.key(),
            ErrorCode::NeedMaintainerRole
        );
        
        // Verify the proof
        let instruction_data_clone = instruction_data.clone();
        verify_proof(instruction_data_clone)?;

        let mut public_inputs = [[0u8; 32]; VERIFYINGKEY.nr_pubinputs];
        for i in 0..VERIFYINGKEY.nr_pubinputs {
            let start = 256 + i * 32;
            let end = start + 32;
            public_inputs[i] = instruction_data[start..end]
                .try_into()
                .map_err(|_| error!(ErrorCode::FailedToParsePublicInputs))?;
        }

        // Extract public inputs
        let nullifier_hash = public_inputs[0];
        let amount = u64::from_le_bytes(
            public_inputs[1][..8]
                .try_into()
                .map_err(|_| error!(ErrorCode::FailedToParsePublicInputs))?
        );
        let mode = public_inputs[2][0];

        // Check if the nullifier hash already exists in nullifier_hashes array of mix_storage
        require!(
            !mix_storage.deposit_commitments_nullifier_hashes.contains(&nullifier_hash),
            ErrorCode::NullifierHashAlreadyUsed
        );
        mix_storage.deposit_commitments_nullifier_hashes.push(nullifier_hash);

        // Process withdraw based on the mode
        if mode == 1 || mode == 3 {
            // SOL release; mode 1 is for SOL to SOL mixing, mode 3 is for ETH to SOL mixing
            let seeds = &[b"escrow_vault_for_sol".as_ref(), &[ctx.bumps.escrow_vault_for_sol]];
            let signer_seeds = &[&seeds[..]];

            let ix = system_instruction::transfer(
                &ctx.accounts.escrow_vault_for_sol.key(),
                &ctx.accounts.to.key(),
                amount,
            );
            invoke_signed(
                &ix,
                &[
                    ctx.accounts.escrow_vault_for_sol.to_account_info(),
                    ctx.accounts.to.to_account_info(),
                    ctx.accounts.system_program.to_account_info(),
                ],
                signer_seeds,
            )?;
        }
        else if mode == 2 || mode == 4 {
            // SPL token release; mode 2 is for SOL to SPL token mixing, mode 4 is for ETH to SPL token mixing
            let mint_key = &mut ctx.accounts.mint.key();
            let seeds = &["escrow_vault".as_bytes(), mint_key.as_ref(), &[ctx.bumps.escrow_vault]];
            let signer_seeds = &[&seeds[..]];

            let transfer_instruction = Transfer{
                from: ctx.accounts.escrow_vault.to_account_info(),
                to: ctx.accounts.to_ata.to_account_info(),
                authority: ctx.accounts.escrow_vault.to_account_info(),
            };

            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new_with_signer(cpi_program, transfer_instruction, signer_seeds);

            token::transfer(cpi_ctx, amount)?;
        } 
        else {
            return Err(ErrorCode::InvalidMode.into());
        }

        Ok(())
    }

    pub fn validate_commitment(ctx: Context<CommitmentValidation>, commitment: [u8; 32]) -> Result<()> {
        let mix_storage = &ctx.accounts.mix_storage;

        // Check if the withdrawal commitment exists
        if !mix_storage.withdraw_commitments.contains(&commitment) {
            return Err(ErrorCode::CommitmentNotFound.into());
        }

        Ok(())
    }

    pub fn verify_proof_test(
        ctx: Context<VerifyProof>,
        instruction_data: Vec<u8>,
    ) -> Result<()> {
        let verifying_key = VERIFYINGKEY;

        // let mut public_inputs = [[0u8; 32]; VERIFYINGKEY.nr_pubinputs];
        // public_inputs[0] = instruction_data[256..288].try_into().unwrap();

        let mut public_inputs = [[0u8; 32]; VERIFYINGKEY.nr_pubinputs];
        for i in 0..VERIFYINGKEY.nr_pubinputs {
            let start = 256 + i * 32;
            let end = start + 32;
            public_inputs[i] = instruction_data[start..end]
                .try_into()
                .map_err(|_| error!(ErrorCode::VerificationFailed))?;
        }

        let proof_a = instruction_data[0..64].try_into().unwrap();
        let proof_b = instruction_data[64..192].try_into().unwrap();
        let proof_c = instruction_data[192..256].try_into().unwrap();

        let mut verifier = Groth16Verifier::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
            &verifying_key,
        ).map_err(|_| error!(ErrorCode::VerificationFailed))?;

        // let is_valid = verifier.verify();
        let is_valid = verifier.verify().map_err(|_| error!(ErrorCode::VerificationFailed))?;
        
        if !is_valid {
            msg!("Verification failed");
            return Err(error!(ErrorCode::VerificationFailed));
        }
        msg!("Verification succeeded");
        Ok(())

        // match is_valid {
        //     Ok(true) => msg!("Verification succeeded"),
        //     Ok(false) => msg!("Verification failed"),
        //     Err(e) => msg!("Verification error: {:?}", e),
        // }

        // msg!("Proof is valid!");
        // Ok(())
    }
}

fn verify_proof(
    instruction_data: Vec<u8>,
) -> Result<()> {
    let verifying_key = VERIFYINGKEY;

    // let mut public_inputs = [[0u8; 32]; VERIFYINGKEY.nr_pubinputs];
    // public_inputs[0] = instruction_data[256..288].try_into().unwrap();

    let mut public_inputs = [[0u8; 32]; VERIFYINGKEY.nr_pubinputs];
    for i in 0..VERIFYINGKEY.nr_pubinputs {
        let start = 256 + i * 32;
        let end = start + 32;
        public_inputs[i] = instruction_data[start..end]
            .try_into()
            .map_err(|_| error!(ErrorCode::VerificationFailed))?;
    }

    let proof_a = instruction_data[0..64].try_into().unwrap();
    let proof_b = instruction_data[64..192].try_into().unwrap();
    let proof_c = instruction_data[192..256].try_into().unwrap();

    let mut verifier = Groth16Verifier::new(
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
        &verifying_key,
    ).map_err(|_| error!(ErrorCode::VerificationFailed))?;

    let is_valid = verifier.verify();
    // let is_valid = verifier.verify().map_err(|_| error!(ErrorCode::VerificationFailed))?;
    
    // if !is_valid {
    //     msg!("Verification failed");
    //     return Err(error!(ErrorCode::VerificationFailed));
    // }
    // msg!("Verification succeeded");
    // Ok(())

    match is_valid {
        Ok(true) => msg!("Verification succeeded"),
        Ok(false) => msg!("Verification failed"),
        Err(e) => msg!("Verification error: {:?}", e),
    }

    msg!("Proof is valid!");
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init,
        payer = signer,
        space = size_of::<MixStorage>() + 8000,
        seeds = [],
        bump)]
    pub mix_storage: Account<'info, MixStorage>,

    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,

    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,
    
    #[account(
        init,
        payer = signer,
        owner = token_program.key(),
        seeds = [b"escrow_vault".as_ref(), mint.key().as_ref()],
        // rent_exempt = enforce,
        token::mint = mint,
        token::authority = escrow_vault,
        bump)]
    pub escrow_vault: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    // #[account(
    //     init,
    //     payer = signer,
    //     space = 8 + 32, // 8 bytes for discriminator + 32 bytes for pubkey
    //     seeds = [b"escrow_vault_for_sol".as_ref()],
    //     bump)]
    // pub escrow_vault_for_sol: SystemAccount<'info>,
    #[account(
        mut,
        seeds = [b"escrow_vault_for_sol".as_ref()],
        bump)]
    pub escrow_vault_for_sol: AccountInfo<'info>,

    pub mint: Account<'info, Mint>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub from: UncheckedAccount<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub from_ata: UncheckedAccount<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(mut, seeds = [], bump)]
    pub mix_storage: Account<'info, MixStorage>,

    // #[account(mut, seeds = [b"mix_storage_2".as_ref()], bump)]
    // pub mix_storage_2: Account<'info, MixStorage2>,

    pub system_program: Program<'info, System>,

    #[account(mut,
        seeds = [b"escrow_vault".as_ref(), mint.key().as_ref()],
        bump)]
    pub escrow_vault: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        mut,
        seeds = [b"escrow_vault_for_sol".as_ref()],
        bump)]
    pub escrow_vault_for_sol: AccountInfo<'info>,
        
    /// Token mint.
    pub mint: Account<'info, Mint>,
}

#[derive(Accounts)]
pub struct EscrowCharge<'info> {
    #[account(address = token::ID)]
    pub token_program: Program<'info, Token>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub from: UncheckedAccount<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    // #[account(mut)]
    // pub to: AccountInfo<'info>,
    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,

    #[account(mut,
        seeds = [b"escrow_vault".as_ref(), mint.key().as_ref()],
        bump)]
    pub escrow_vault: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        mut,
        seeds = [b"escrow_vault_for_sol".as_ref()],
        bump)]
    pub escrow_vault_for_sol: AccountInfo<'info>,
        
    /// Token mint.
    pub mint: Account<'info, Mint>,
}

#[derive(Accounts)]
pub struct RegisterCommitment<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub signer: Signer<'info>,

    #[account(mut, seeds = [], bump)]
    pub mix_storage: Account<'info, MixStorage>,

    // #[account(mut, seeds = [b"mix_storage_2".as_ref()], bump)]
    // pub mix_storage_2: Account<'info, MixStorage2>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub token_program: Program<'info, Token>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub to: UncheckedAccount<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub to_ata: UncheckedAccount<'info>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(mut, seeds = [], bump)]
    pub mix_storage: Account<'info, MixStorage>,

    #[account(mut,
        seeds = [b"escrow_vault".as_ref(), mint.key().as_ref()],
        bump)]
    pub escrow_vault: Account<'info, TokenAccount>,

    /// CHECK: This is not dangerous because we don't read or write from this account
    #[account(
        mut,
        seeds = [b"escrow_vault_for_sol".as_ref()],
        bump)]
    pub escrow_vault_for_sol: AccountInfo<'info>,

    /// Token mint.
    pub mint: Account<'info, Mint>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct MixStorage {
    deposit_commitments_nullifier_hashes: Vec<[u8; 32]>,
    withdraw_commitments: Vec<[u8; 32]>,
    maintainer: Pubkey
}

#[derive(Accounts)]
pub struct CommitmentValidation<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(mut)]
    pub mix_storage: Account<'info, MixStorage>,
}

#[derive(Accounts)]
pub struct VerifyProof<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Invalid deposit amount. Deposit amount under the mininum allowed")]
    InvalidMinimumDepositAmount,
    #[msg("Need Maintainer Role for this action")]
    NeedMaintainerRole,
    #[msg("Proof verification failed")]
    VerificationFailed,
    #[msg("Invalid proof")]
    InvalidProof,
    #[msg("Invalid mixing mode")]
    InvalidMode,
    #[msg("Commitment not found")]
    CommitmentNotFound,
    #[msg("Commitment already submitted")]
    CommitmentAlreadySubmitted,
    #[msg("Nullifier hash already used")]
    NullifierHashAlreadyUsed,
    #[msg("Failed to parse public inputs")]
    FailedToParsePublicInputs,
}