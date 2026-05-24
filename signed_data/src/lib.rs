use std::marker::PhantomData;

use ed25519_dalek::{
    SIGNATURE_LENGTH, Signature, Signer, SigningKey, VerifyingKey,
    ed25519,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedData<T> {
    #[serde(with = "serde_bytes")]
    signature: [u8; SIGNATURE_LENGTH],
    #[serde(with = "serde_bytes")]
    data: Box<[u8]>,
    _data: PhantomData<T>,
}

impl<T> SignedData<T> {
    pub fn sign_raw(data: Box<[u8]>, key: &SigningKey) -> Self {
        let signature = key.sign(&data).to_bytes();
        Self {
            signature,
            data,
            _data: PhantomData::<T>,
        }
    }

    /// # Errors
    ///
    /// if [`T`] failed to serialize
    pub fn sign(data: &T, key: &SigningKey) -> Result<Self, Error>
    where
        T: Serialize,
    {
        let mut buf = Vec::<u8>::with_capacity(128);
        ciborium::into_writer(data, &mut buf)?;
        Ok(Self::sign_raw(buf.into_boxed_slice(), key))
    }

    fn verify(&self, key: &VerifyingKey) -> Result<(), Error> {
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.data, &signature)?;
        Ok(())
    }

    /// # Errors
    ///
    /// if signature is invalid,
    pub fn to_verified_raw(
        &self,
        key: &VerifyingKey,
    ) -> Result<&[u8], Error> {
        self.verify(key)?;
        Ok(&self.data)
    }

    /// # Errors
    ///
    /// if signature is invalid,
    pub fn into_verified_raw(
        self,
        key: &VerifyingKey,
    ) -> Result<Box<[u8]>, Error> {
        self.verify(key)?;
        Ok(self.data)
    }

    /// # Errors
    ///
    /// if signature is invalid,
    /// or failed to deserialize data into [`T`]
    pub fn to_verified(&self, key: &VerifyingKey) -> Result<T, Error>
    where
        T: DeserializeOwned,
    {
        let data = self.to_verified_raw(key)?;
        ciborium::from_reader(data).map_err(Into::into)
    }

    pub fn to_base64(&self, engine: &impl base64::Engine) -> Box<str> {
        let mut buf = vec![0_u8; self.signature.len() + self.data.len()]
            .into_boxed_slice();
        buf[..SIGNATURE_LENGTH].copy_from_slice(&self.signature);
        buf[SIGNATURE_LENGTH..].copy_from_slice(&self.data);

        engine.encode(&buf).into_boxed_str()
    }

    /// # Errors
    ///
    /// if not valid base64 for [`engine`]
    pub fn try_from_base64(
        encoded: impl AsRef<[u8]>,
        engine: &impl base64::Engine,
    ) -> Result<Self, Error> {
        let data = engine.decode(encoded)?;
        if data.len() < SIGNATURE_LENGTH {
            return Err(Error::InvalidLength(data.len()));
        }

        let mut signature = [0_u8; SIGNATURE_LENGTH];
        signature.copy_from_slice(&data[..SIGNATURE_LENGTH]);
        let data = Box::from(&data[SIGNATURE_LENGTH..]);

        Ok(Self {
            signature,
            data,
            _data: PhantomData::<T>,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("when serializing: {0:?}")]
    Serialize(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("when deserializing: {0:?}")]
    Deserialize(#[from] ciborium::de::Error<std::io::Error>),
    #[error("when verifying: {0:?}")]
    Verify(#[from] ed25519::Error),
    #[error("when decoding base64: {0:?}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("invalid length, expect >=64, got {0}")]
    InvalidLength(usize),
}

pub trait ToSigned {
    /// # Errors
    ///
    /// if [`T`] failed to serialize
    fn to_signed(
        &self,
        key: &SigningKey,
    ) -> Result<SignedData<Self>, Error>
    where
        Self: Sized;
}

impl<T> ToSigned for T
where
    T: Serialize,
{
    fn to_signed(
        &self,
        key: &SigningKey,
    ) -> Result<SignedData<Self>, Error>
    where
        Self: Sized,
    {
        SignedData::sign(self, key)
    }
}

#[cfg(test)]
mod tests {
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;

    use super::*;

    #[test]
    fn sign_and_verify() {
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestData {
            something: u64,
        }
        let data = TestData { something: 1234 };

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let signed = data.to_signed(&signing_key).unwrap();
        let encoded = signed.to_base64(&BASE64_URL_SAFE_NO_PAD);
        let decoded = SignedData::<TestData>::try_from_base64(
            encoded.as_bytes(),
            &BASE64_URL_SAFE_NO_PAD,
        )
        .unwrap();
        let verified = decoded.to_verified(&verifying_key).unwrap();
        assert_eq!(data, verified);
    }

    #[test]
    fn sign_and_verify_0() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let signed = SignedData::<()>::sign_raw([].into(), &signing_key);
        let verified = signed.into_verified_raw(&verifying_key).unwrap();
        assert_eq!(&*verified, &[]);
    }

    #[test]
    fn tampered_data() {
        let data = 1234_u64;

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut signed = data.to_signed(&signing_key).unwrap();

        let data = &mut signed.data[0];
        *data = data.wrapping_add(1);

        let res = signed.to_verified(&verifying_key);
        assert!(matches!(res, Err(Error::Verify(_))), "{res:?}");
    }

    #[test]
    fn tampered_signature() {
        let data = 1234_u64;

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut signed = data.to_signed(&signing_key).unwrap();

        let signature = &mut signed.signature[0];
        *signature = signature.wrapping_add(1);

        let res = signed.to_verified(&verifying_key);
        assert!(matches!(res, Err(Error::Verify(_))), "{res:?}");
    }

    #[test]
    fn mismatched_key() {
        let data = 1234_u64;

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signing_key2 = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key2.verifying_key();

        let signed = data.to_signed(&signing_key).unwrap();
        let res = signed.to_verified(&verifying_key);
        assert!(matches!(res, Err(Error::Verify(_))), "{res:?}");
    }
}
