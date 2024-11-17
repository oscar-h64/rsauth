use crate::types::Claims;
use anyhow::Result;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

//--------------------------------------------------------------------------------------------------
// Access Token Type
//--------------------------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct AccessToken(String);

impl AccessToken {
    pub fn encode_new(claims: Claims, encoding_key: &EncodingKey) -> Result<Self> {
        let token = encode(&Header::new(Algorithm::ES256), &claims, encoding_key)?;

        Ok(AccessToken(token))
    }
}

//--------------------------------------------------------------------------------------------------
