//! for cancellation safety to use with web frameworks
use std::{borrow::Cow, future::Future, pin::Pin};

use sqlx_core::{
    database::Database, pool::Pool, transaction::Transaction,
};

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PgRetryStrategy {
    /// retry on 40001 `serialization_failure`,
    /// and 40P01 `deadlock_detected`
    #[default]
    Default,
    /// other than [`Default`],
    /// also retry 23505 `unique_violation`,
    /// and 23P01 `exclusion_violation`
    UniqueKey,
}

impl PgRetryStrategy {
    fn is_code_retryable(self, code: &str) -> bool {
        let def = matches!(code, "40001" | "40P01");
        match self {
            Self::Default => def,
            Self::UniqueKey => def || matches!(code, "23505" | "23P01"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Sqlx(#[from] sqlx_core::Error),
    #[error("when awaiting the spawned task: {0}")]
    Tokio(#[from] tokio::task::JoinError),
    #[error("retry limit reached")]
    RetryLimit,
}

impl Error {
    #[must_use]
    pub const fn as_sqlx(&self) -> Option<&sqlx_core::Error> {
        match self {
            Self::Sqlx(err) => Some(err),
            _ => None,
        }
    }
}

pub trait CustomError: From<Error> {
    fn as_transaction_err(&self) -> Option<&Error>;

    fn as_transaction_db_err(&self) -> Option<&sqlx_core::Error> {
        self.as_transaction_err()?.as_sqlx()
    }

    fn is_transaction_retryable_pg(
        &self,
        strategy: PgRetryStrategy,
    ) -> bool {
        matches!(
            self.as_transaction_db_err(),
            Some(sqlx_core::Error::Database(db_err))
                if db_err.code()
                    .is_some_and(|it| strategy.is_code_retryable(&it))
        )
    }
}

impl CustomError for Error {
    fn as_transaction_err(&self) -> Option<&Error> {
        Some(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PgBegin {
    #[default]
    ReadCommitted,
    ReadCommittedRo,
    RepeatableRead,
    RepeatableReadRo,
    Serializable,
    SerializableRo,
    SerializableRoDeferrable,
}

impl From<PgBegin> for Cow<'static, str> {
    fn from(value: PgBegin) -> Self {
        match value {
            PgBegin::ReadCommitted => "BEGIN",
            PgBegin::ReadCommittedRo => {
                "BEGIN \
                    READ ONLY"
            }
            PgBegin::RepeatableRead => {
                "BEGIN \
                    ISOLATION LEVEL REPEATABLE READ"
            }
            PgBegin::RepeatableReadRo => {
                "BEGIN \
                    ISOLATION LEVEL REPEATABLE READ, \
                    READ ONLY"
            }
            PgBegin::Serializable => {
                "BEGIN \
                    ISOLATION LEVEL SERIALIZABLE"
            }
            PgBegin::SerializableRo => {
                "BEGIN \
                    ISOLATION LEVEL SERIALIZABLE, \
                    READ ONLY"
            }
            PgBegin::SerializableRoDeferrable => {
                "BEGIN \
                    ISOLATION LEVEL SERIALIZABLE, \
                    READ ONLY, DEFERRABLE"
            }
        }
        .into()
    }
}

pub trait PoolExt<DB: Database>: sealed::Sealed {
    fn spawn_begin(
        self,
    ) -> impl Future<Output = Result<Transaction<'static, DB>, Error>> + Send;

    fn spawn_begin_with(
        self,
        statement: impl Into<Cow<'static, str>>,
    ) -> impl Future<Output = Result<Transaction<'static, DB>, Error>> + Send;

    fn spawn_begin_ret(
        self,
    ) -> impl Future<
        Output = Result<(Transaction<'static, DB>, Pool<DB>), Error>,
    > + Send;

    fn spawn_begin_ret_with(
        self,
        statement: impl Into<Cow<'static, str>>,
    ) -> impl Future<
        Output = Result<(Transaction<'static, DB>, Pool<DB>), Error>,
    > + Send;

    fn spawn_transaction_retry_pg_with<R, E, F>(
        self,
        statement: impl Into<Cow<'static, str>>,
        max_retries: u64,
        retry_strategy: PgRetryStrategy,
        callback: F,
    ) -> impl Future<Output = Result<R, E>> + Send
    where
        Self: Sized,
        R: Send,
        E: CustomError + Send,
        for<'c> F: Fn(
                &'c mut Transaction<'static, DB>,
            )
                -> Pin<Box<dyn Future<Output = Result<R, E>> + 'c + Send>>
            + Send;

    fn spawn_transaction_retry_pg_ret_with<R, E, F>(
        self,
        statement: impl Into<Cow<'static, str>>,
        max_retries: u64,
        retry_strategy: PgRetryStrategy,
        callback: F,
    ) -> impl Future<Output = Result<(R, Pool<DB>), E>> + Send
    where
        Self: Sized,
        R: Send,
        E: CustomError + Send,
        for<'c> F: Fn(
                &'c mut Transaction<'static, DB>,
            )
                -> Pin<Box<dyn Future<Output = Result<R, E>> + 'c + Send>>
            + Send;
}

impl<DB: Database> sealed::Sealed for Pool<DB> {}

impl<DB: Database> PoolExt<DB> for Pool<DB> {
    async fn spawn_begin(
        self,
    ) -> Result<Transaction<'static, DB>, Error> {
        Ok(self.spawn_begin_ret().await?.0)
    }

    fn spawn_begin_with(
        self,
        statement: impl Into<Cow<'static, str>>,
    ) -> impl Future<Output = Result<Transaction<'static, DB>, Error>>
    {
        let statement = statement.into();
        async move { Ok(self.spawn_begin_ret_with(statement).await?.0) }
    }

    async fn spawn_begin_ret(
        self,
    ) -> Result<(Transaction<'static, DB>, Self), Error> {
        let fut = async move { Ok((self.begin().await?, self)) };
        spawn_await(fut).await
    }

    fn spawn_begin_ret_with(
        self,
        statement: impl Into<Cow<'static, str>>,
    ) -> impl Future<Output = Result<(Transaction<'static, DB>, Self), Error>>
    {
        let statement = statement.into();
        let fut =
            async move { Ok((self.begin_with(statement).await?, self)) };
        spawn_await(fut)
    }

    fn spawn_transaction_retry_pg_with<R, E, F>(
        self,
        statement: impl Into<Cow<'static, str>>,
        max_retries: u64,
        retry_strategy: PgRetryStrategy,
        callback: F,
    ) -> impl Future<Output = Result<R, E>> + Send
    where
        Self: Sized,
        R: Send,
        E: CustomError + Send,
        for<'c> F: Fn(
                &'c mut Transaction<'static, DB>,
            )
                -> Pin<Box<dyn Future<Output = Result<R, E>> + 'c + Send>>
            + Send,
    {
        let statement = statement.into();

        async move {
            Ok(self
                .spawn_transaction_retry_pg_ret_with(
                    statement,
                    max_retries,
                    retry_strategy,
                    callback,
                )
                .await?
                .0)
        }
    }

    fn spawn_transaction_retry_pg_ret_with<R, E, F>(
        self,
        statement: impl Into<Cow<'static, str>>,
        max_retries: u64,
        retry_strategy: PgRetryStrategy,
        callback: F,
    ) -> impl Future<Output = Result<(R, Self), E>> + Send
    where
        Self: Sized,
        R: Send,
        E: CustomError + Send,
        for<'c> F: Fn(
                &'c mut Transaction<'static, DB>,
            )
                -> Pin<Box<dyn Future<Output = Result<R, E>> + 'c + Send>>
            + Send,
    {
        let statement = statement.into();

        async move {
            let mut retry_count = 0;
            let mut pool = self;
            loop {
                if retry_count > 0 {
                    tracing::trace!("retrying, count: {retry_count}");
                }

                let (mut transaction, p) =
                    pool.spawn_begin_ret_with(statement.clone()).await?;
                pool = p;
                let res = callback(&mut transaction).await;

                match res {
                    Ok(ret) => {
                        let res = transaction.spawn_commit().await;
                        match res {
                            Ok(()) => return Ok((ret, pool)),
                            Err(err)
                                if err.is_transaction_retryable_pg(
                                    retry_strategy,
                                ) =>
                            {
                                // retry
                            }
                            Err(err) => return Err(err.into()),
                        }
                    }
                    Err(err)
                        if err.is_transaction_retryable_pg(
                            retry_strategy,
                        ) =>
                    {
                        // retry
                    }
                    Err(err) => {
                        transaction.spawn_rollback().await?;

                        return Err(err);
                    }
                }

                if retry_count >= max_retries {
                    return Err(Error::RetryLimit.into());
                }

                retry_count += 1;
            }
        }
    }
}

pub trait TransactionExt<DB: Database>: sealed::Sealed {
    fn spawn_commit(
        self,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    fn spawn_rollback(
        self,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

impl<DB: Database> sealed::Sealed for Transaction<'static, DB> {}

impl<DB: Database> TransactionExt<DB> for Transaction<'static, DB> {
    async fn spawn_commit(self) -> Result<(), Error> {
        spawn_await(self.commit()).await
    }

    async fn spawn_rollback(self) -> Result<(), Error> {
        spawn_await(self.rollback()).await
    }
}

async fn spawn_await<T: Send + 'static>(
    fut: impl Future<Output = Result<T, sqlx_core::Error>> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn(fut).await?.map_err(Into::into)
}
