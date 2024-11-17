use crate::internal::unixtime::UnixTimestamp;
use crate::{ClientId, RoleId};
use serde::Deserialize;

//--------------------------------------------------------------------------------------------------
// JWT Claims object
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct Claims {
    sub: ClientId,
    exp: UnixTimestamp,
    nbf: UnixTimestamp,
    iat: UnixTimestamp,
    roles: Vec<RoleId>,
}

impl Claims {
    pub(crate) fn sub(&self) -> &ClientId {
        &self.sub
    }

    pub(crate) fn exp(&self) -> UnixTimestamp {
        self.exp
    }

    pub(crate) fn nbf(&self) -> UnixTimestamp {
        self.nbf
    }

    pub(crate) fn iat(&self) -> UnixTimestamp {
        self.iat
    }

    pub(crate) fn roles(&self) -> &Vec<RoleId> {
        &self.roles
    }
}

//--------------------------------------------------------------------------------------------------
