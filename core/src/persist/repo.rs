use crate::persist::prisma::{user, user_transaction};
use crate::persist::PersistCtx;
use prisma_client_rust::QueryError;
use thiserror::Error;

pub async fn register_user(ctx: &PersistCtx, user_addr: String) -> anyhow::Result<()> {
    let _ = ctx
        .client
        .user()
        .upsert(
            user::address::equals(user_addr.clone()),
            user::create(user_addr, vec![]),
            vec![],
        )
        .exec()
        .await?;
    Ok(())
}

pub async fn get_user(ctx: &PersistCtx, user_addr: String) -> anyhow::Result<Option<user::Data>> {
    let user = ctx
        .client
        .user()
        .find_unique(user::address::equals(user_addr))
        .with(user::transactions::fetch(vec![]))
        .exec()
        .await?;
    Ok(user)
}

pub async fn register_user_with_deposit(
    ctx: &PersistCtx,
    user_addr: String,
    deposit: f64,
) -> anyhow::Result<()> {
    let _ = ctx
        .client
        .user()
        .upsert(
            user::address::equals(user_addr.clone()),
            user::create(user_addr, vec![user::deposit::set(deposit)]),
            vec![user::deposit::set(deposit), user::version::increment(1)],
        )
        .exec()
        .await?;
    Ok(())
}

pub async fn add_user_deposit(
    ctx: &PersistCtx,
    user_addr: String,
    deposit: f64,
) -> anyhow::Result<()> {
    let _ = ctx
        .client
        .user()
        .update(
            user::address::equals(user_addr),
            vec![user::deposit::increment(deposit)],
        )
        .exec()
        .await?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum SubmitPaymentTxnError {
    #[error("Internal query error occurred: {0:?}")]
    QueryError(#[from] QueryError),

    #[error("User is not registered yet!")]
    UserNotRegistered,

    #[error("Not enough deposit available!")]
    NotEnoughDeposit,

    #[error("Found conflicting transactions!")]
    ConflictingTransactions,
}

pub async fn submit_payment_transaction(
    ctx: &PersistCtx,
    user_addr: String,
    transaction_id: String,
    amount: f64,
) -> Result<(), SubmitPaymentTxnError> {
    ctx.client
        ._transaction()
        .run::<SubmitPaymentTxnError, _, _, _>(|client| async move {
            let Some(user) = client
                .user()
                .find_unique(user::address::equals(user_addr.clone()))
                // Fetching the user's not-yet-finalized transactions
                .with(user::transactions::fetch(vec![
                    user_transaction::finalized::equals(false),
                    user_transaction::tx_id::not(transaction_id.clone()),
                ]))
                .exec()
                .await?
            else {
                return Err(SubmitPaymentTxnError::UserNotRegistered);
            };

            let transactions = user.transactions.unwrap();
            let not_usable_deposit = transactions.iter().map(|tx| tx.amount).sum::<f64>();

            if not_usable_deposit + amount > user.deposit {
                return Err(SubmitPaymentTxnError::NotEnoughDeposit);
            }

            client
                .user_transaction()
                .upsert(
                    user_transaction::tx_id::equals(transaction_id.clone()),
                    user_transaction::create(
                        transaction_id,
                        amount,
                        user::address::equals(user_addr.clone()),
                        vec![],
                    ),
                    vec![],
                )
                .exec()
                .await?;

            // For now, we implement the optimistic lock strategy using the user's version, because prisma
            //  doesn't support SELECT FOR UPDATE yet.
            let updated_user = client
                .user()
                .update(
                    user::address::equals(user_addr),
                    vec![user::version::increment(1)],
                )
                .exec()
                .await?;

            // There was a conflicting version, so we return error here...
            if updated_user.version != user.version + 1 {
                return Err(SubmitPaymentTxnError::ConflictingTransactions);
            }

            Ok(())
        })
        .await?;

    Ok(())
}

pub async fn fail_transaction(
    ctx: &PersistCtx,
    user_addr: String,
    transaction_id: String,
) -> Result<(), anyhow::Error> {
    ctx.client
        ._transaction()
        .run::<QueryError, _, _, _>(|client| async move {
            let updated_tx = client
                .user_transaction()
                .update(
                    user_transaction::tx_id::equals(transaction_id),
                    vec![
                        user_transaction::finalized::set(true),
                        user_transaction::failed::set(true),
                    ],
                )
                .exec()
                .await?;

            client
                .user()
                .update(
                    user::address::equals(user_addr),
                    vec![user::deposit::decrement(updated_tx.amount)],
                )
                .exec()
                .await?;

            Ok(())
        })
        .await?;

    Ok(())
}
