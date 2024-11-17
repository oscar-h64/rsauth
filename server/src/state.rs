use crate::db::DbConnectionPool;
use crate::handler_proxy::PrivateKeyAccess;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsauth::extract::PublicKeyProvider;
use std::sync::Arc;

//--------------------------------------------------------------------------------------------------
// State given to the handlers
//--------------------------------------------------------------------------------------------------

pub type StateRef = Arc<State>;

#[derive(Clone)]
pub struct State {
    db_connection: DbConnectionPool,
    private_key: EncodingKey,
    public_key: DecodingKey,
}

impl State {
    pub fn new(
        db_connection: DbConnectionPool,
        private_key: EncodingKey,
        public_key: DecodingKey,
    ) -> Self {
        Self {
            db_connection,
            private_key,
            public_key,
        }
    }

    pub fn private_key(&self, _private_key_access: PrivateKeyAccess) -> &EncodingKey {
        &self.private_key
    }

    pub fn db_connection(&self) -> &DbConnectionPool {
        &self.db_connection
    }
}

impl PublicKeyProvider for State {
    fn public_key(&self) -> &DecodingKey {
        &self.public_key
    }
}

//--------------------------------------------------------------------------------------------------
