use axum::{
    RequestExt,
    body::{Bytes, HttpBody},
    extract::{
        FromRequest, OptionalFromRequest, rejection::BytesRejection,
    },
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use mime::Mime;
use serde::{Serialize, de::DeserializeOwned};
use simple_deref::impl_deref;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct Cbor<T>(pub T);

impl_deref!(impl<T> ref Cbor<T> => T = .0);

impl<T> From<T> for Cbor<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T, S> OptionalFromRequest<S> for Cbor<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = CborRejection;

    async fn from_request(
        req: axum::extract::Request,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let hdrs = req.headers();
        if req.body().is_end_stream() {
            return Ok(None);
        }

        let content_type = hdrs
            .get(header::CONTENT_TYPE)
            .ok_or(ContentTypeError::Missing)?;

        let content_type = content_type
            .to_str()
            .map_err(ContentTypeError::InvalidValue)?;

        let mime = content_type
            .parse::<Mime>()
            .map_err(ContentTypeError::InvalidMime)?;

        let is_cbor = mime.type_() == mime::APPLICATION
            && (mime.subtype() == "cbor"
                || mime.suffix().is_some_and(|name| name == "cbor"));

        if !is_cbor {
            return Err(ContentTypeError::ExpectCbor.into());
        }

        let bytes = Bytes::from_request(req, &()).await?;

        ciborium::from_reader(AsRef::<[u8]>::as_ref(&bytes))
            .map_err(Into::into)
            .map(Self)
            .map(Some)
    }
}

impl<T, S> FromRequest<S> for Cbor<T>
where
    T: DeserializeOwned + 'static,
    S: Send + Sync,
{
    type Rejection = CborRejection;

    async fn from_request(
        req: axum::extract::Request,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        req.extract::<Option<Self>, _>()
            .await?
            .ok_or(CborRejection::Missing)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContentTypeError {
    #[error("missing header")]
    Missing,
    #[error("invalid value: {0:?}")]
    InvalidValue(header::ToStrError),
    #[error("invalid mime: {0:?}")]
    InvalidMime(mime::FromStrError),
    #[error("expect application/cbor")]
    ExpectCbor,
}

#[derive(Debug, thiserror::Error)]
pub enum CborRejection {
    #[error("invalid Content-Type: {0}")]
    ContentType(#[from] ContentTypeError),
    #[error("when reading body: {0}")]
    Bytes(#[from] BytesRejection),
    #[error("when parsing body as cbor: {0}")]
    Cbor(#[from] ciborium::de::Error<std::io::Error>),
    #[error("expect body")]
    Missing,
}

impl IntoResponse for CborRejection {
    fn into_response(self) -> Response {
        match self {
            Self::ContentType(content_type_error) => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                content_type_error.to_string(),
            )
                .into_response(),
            Self::Bytes(bytes_rejection) => {
                bytes_rejection.into_response()
            }
            Self::Cbor(error) => match error {
                ciborium::de::Error::Syntax(idx) => {
                    (StatusCode::BAD_REQUEST, format!("idx: {idx}"))
                        .into_response()
                }
                ciborium::de::Error::Semantic(idx, msg) => {
                    (StatusCode::BAD_REQUEST, format!("{msg}: {idx:?}"))
                        .into_response()
                }
                err => {
                    tracing::error!(
                        "unexpected error when parsing body as Cbor: {err:?}"
                    );
                    (StatusCode::INTERNAL_SERVER_ERROR).into_response()
                }
            },
            Self::Missing => {
                (StatusCode::BAD_REQUEST, "expect body").into_response()
            }
        }
    }
}

impl<T: Serialize> IntoResponse for Cbor<T> {
    fn into_response(self) -> Response {
        let mut buf = Vec::<u8>::with_capacity(128);
        let result = ciborium::into_writer(&*self, &mut buf);

        match result {
            Ok(()) => ([(header::CONTENT_TYPE, "application/cbor")], buf)
                .into_response(),
            Err(err) => {
                tracing::error!(
                    "unexpected error when serializing response data as cbor: {err}"
                );

                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
