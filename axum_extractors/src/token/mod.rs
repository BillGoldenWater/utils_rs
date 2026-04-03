use std::{borrow::Cow, marker::PhantomData};

use axum::{
    Extension, RequestPartsExt,
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::{StatusCode, header},
    response::IntoResponse,
};
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use cookie::{Cookie, SameSite};
use ed25519_dalek::{SigningKey, VerifyingKey};
use problem_details::ProblemDetails;
use serde::{Serialize, de::DeserializeOwned};
use signed_data::SignedData;
use simple_deref::impl_deref;
use time::OffsetDateTime;

pub trait CustomToken<S>
where
    S: Send + Sync,
{
    const COOKIE_NAME: &'static str;
    const SECURE: bool = true;
    const HTTP_ONLY: bool = true;
    const SAME_SITE: SameSite = SameSite::Strict;
    const PATH: &'static str = "/";

    fn get_expires_when(&self) -> OffsetDateTime;
    fn signing_key_from_state(state: &S) -> Cow<'_, SigningKey>;
    fn verifying_key_from_state(state: &S) -> Cow<'_, VerifyingKey> {
        Cow::Owned(Self::signing_key_from_state(state).verifying_key())
    }
}

/// when extracting, expires time returned by [`CustomToken::get_expires_when`] will be verified
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Token<T, S> {
    inner: T,
    _state: PhantomData<S>,
}

impl<T, S> Token<T, S>
where
    T: CustomToken<S>,
    S: Send + Sync,
{
    #[must_use]
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            _state: PhantomData,
        }
    }

    /// # Errors
    ///
    /// if [`T`] failed to serialize
    pub fn to_cookie_with(
        &self,
        state: &S,
    ) -> Result<Cookie<'static>, signed_data::Error>
    where
        T: Serialize,
    {
        let expires_when = self.get_expires_when();
        let key = T::signing_key_from_state(state);

        let token = SignedData::sign(&self.inner, &key)?
            .to_base64(&BASE64_URL_SAFE_NO_PAD);
        Ok(Cookie::build((T::COOKIE_NAME, token.into_string()))
            .expires(expires_when)
            .secure(T::SECURE)
            .http_only(T::HTTP_ONLY)
            .same_site(T::SAME_SITE)
            .path(T::PATH)
            .build())
    }
}

impl_deref!(impl<T, S> ref Token<T, S> => T = .inner);

impl<T, S> OptionalFromRequestParts<S> for Token<T, S>
where
    T: DeserializeOwned + CustomToken<S>,
    S: Send + Sync,
{
    type Rejection = TokenRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let Some(cookies) = parts.headers.get(header::COOKIE) else {
            return Ok(None);
        };

        let cookies = cookies.to_str()?;

        let token = Cookie::split_parse_encoded(cookies)
            .try_fold(None, |state, cookie| match state {
                None => {
                    let cookie = cookie?;
                    if cookie.name() == T::COOKIE_NAME {
                        Ok(Some(Box::<str>::from(cookie.value_trimmed())))
                    } else {
                        Ok(None)
                    }
                }
                _ => Ok(state),
            })
            .map_err(TokenRejection::CookieParse)?;
        let Some(token) = token else { return Ok(None) };

        let token = SignedData::<T>::try_from_base64(
            &*token,
            &BASE64_URL_SAFE_NO_PAD,
        )?;

        let key = T::verifying_key_from_state(state);
        let token = token.to_verified(&key)?;

        if token.get_expires_when() < OffsetDateTime::now_utc() {
            return Err(TokenRejection::Expired);
        }

        Ok(Some(Self::new(token)))
    }
}

impl<T, S> FromRequestParts<S> for Token<T, S>
where
    T: DeserializeOwned + CustomToken<S> + 'static,
    S: Send + Sync + 'static,
{
    type Rejection = TokenRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extract_with_state::<Option<Self>, _>(state)
            .await?
            .ok_or(TokenRejection::Missing)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenRejection {
    #[error("when decoding as utf8: {0}")]
    CookieEncoding(#[from] axum::http::header::ToStrError),
    #[error("when parsing cookies: {0}")]
    CookieParse(#[from] cookie::ParseError),
    #[error("when handling as signed data: {0}")]
    SignedData(#[from] signed_data::Error),
    #[error("missing token")]
    Missing,
    #[error("expired")]
    Expired,
}

impl IntoResponse for TokenRejection {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::CookieEncoding(_) => (
                Extension(
                    ProblemDetails::from_status_code(
                        StatusCode::BAD_REQUEST,
                    )
                    .with_detail("invalid cookie encoding"),
                ),
                (StatusCode::BAD_REQUEST, "invalid cookie encoding"),
            )
                .into_response(),
            Self::CookieParse(parse_error) => {
                let detail =
                    format!("invalid cookie syntax: {parse_error}");
                (
                    Extension(
                        ProblemDetails::from_status_code(
                            StatusCode::BAD_REQUEST,
                        )
                        .with_detail(&detail),
                    ),
                    (StatusCode::BAD_REQUEST, detail),
                )
                    .into_response()
            }
            Self::SignedData(error) => {
                tracing::debug!("signed data error: {error}");
                (
                    Extension(
                        ProblemDetails::from_status_code(
                            StatusCode::UNAUTHORIZED,
                        )
                        .with_detail("invalid token"),
                    ),
                    (StatusCode::UNAUTHORIZED, "invalid token"),
                )
                    .into_response()
            }
            Self::Missing => (
                Extension(
                    ProblemDetails::from_status_code(
                        StatusCode::UNAUTHORIZED,
                    )
                    .with_detail("missing token"),
                ),
                (StatusCode::UNAUTHORIZED, "missing token"),
            )
                .into_response(),
            Self::Expired => (
                Extension(
                    ProblemDetails::from_status_code(
                        StatusCode::UNAUTHORIZED,
                    )
                    .with_detail("token exipred"),
                ),
                (StatusCode::UNAUTHORIZED, "token expired"),
            )
                .into_response(),
        }
    }
}
