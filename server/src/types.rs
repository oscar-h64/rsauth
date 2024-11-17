use crate::db::SeedPermission;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{password_hash, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum_extra::headers::authorization::Basic;
use diesel::backend::Backend;
use diesel::deserialize::FromSql;
use diesel::serialize::{Output, ToSql};
use diesel::sql_types::Text;
use diesel::{AsExpression, FromSqlRow};
use rsauth::internal::unixtime::UnixTimestamp;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Macro to derive simple ToSql/FromSql needed for String newtypes that are used in the DB
//--------------------------------------------------------------------------------------------------

macro_rules! derive_to_from_sql {
    ($ty:ident) => {
        impl<DB: Backend> ToSql<Text, DB> for $ty
        where
            String: ToSql<Text, DB>,
        {
            fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, DB>) -> diesel::serialize::Result {
                self.0.to_sql(out)
            }
        }

        impl<DB: Backend> FromSql<Text, DB> for $ty
        where
            String: FromSql<Text, DB>,
        {
            fn from_sql(bytes: DB::RawValue<'_>) -> diesel::deserialize::Result<Self> {
                String::from_sql(bytes).map($ty)
            }
        }
    };
}

//--------------------------------------------------------------------------------------------------
// New types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, AsExpression, FromSqlRow, PartialEq, Eq, Hash)]
#[diesel(sql_type = Text)]
pub struct ClientId(String);

derive_to_from_sql!(ClientId);

impl ClientId {
    pub fn from_uuid(_perm: SeedPermission, uuid: uuid::Uuid) -> Self {
        ClientId(uuid.to_string())
    }
}

#[derive(Deserialize)]
pub struct ClientSecret(String);

// Allow us to get a ClientId/ClientSecret from a basic auth header, without having to expose a
// from String type implementation
impl From<&Basic> for ClientId {
    fn from(b: &Basic) -> Self {
        ClientId(b.username().to_string())
    }
}

impl From<&Basic> for ClientSecret {
    fn from(b: &Basic) -> Self {
        ClientSecret(b.password().to_string())
    }
}

impl ClientSecret {
    pub fn from_uuid(_perm: SeedPermission, uuid: uuid::Uuid) -> Self {
        ClientSecret(uuid.to_string())
    }
}

#[derive(Debug, AsExpression, FromSqlRow)]
#[diesel(sql_type = Text)]
pub struct ClientSecretHash(String);

derive_to_from_sql!(ClientSecretHash);

impl From<PasswordHash<'_>> for ClientSecretHash {
    fn from(p: PasswordHash) -> Self {
        ClientSecretHash(p.to_string())
    }
}

impl ClientSecretHash {
    pub fn validate(&self, secret: ClientSecret) -> password_hash::Result<bool> {
        let hash = PasswordHash::new(&self.0)?;

        match Argon2::default().verify_password(secret.0.as_bytes(), &hash) {
            Ok(()) => Ok(true),
            Err(password_hash::Error::Password) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn from_secret(secret: ClientSecret) -> password_hash::Result<Self> {
        let salt = SaltString::generate(&mut OsRng);

        let hash = Argon2::default().hash_password(secret.0.as_bytes(), &salt)?;

        Ok(ClientSecretHash(hash.to_string()))
    }
}

#[derive(Deserialize, Serialize, Debug, AsExpression, FromSqlRow, PartialEq, Eq, Hash)]
#[diesel(sql_type = Text)]
pub struct RoleId(String);

impl<T: rsauth::Role> From<T> for RoleId {
    fn from(_: T) -> Self {
        RoleId(T::role_id().to_string())
    }
}

derive_to_from_sql!(RoleId);

#[derive(Debug, Deserialize, Serialize, AsExpression, FromSqlRow)]
#[diesel(sql_type = Text)]
pub struct RoleDescription(String);

impl RoleDescription {
    pub fn seed_client_admin_description(_perm: SeedPermission) -> Self {
        RoleDescription("Administrative power to manage clients".to_string())
    }
}

derive_to_from_sql!(RoleDescription);

//--------------------------------------------------------------------------------------------------
// JWT Claims object
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
pub struct Claims {
    sub: ClientId,
    exp: UnixTimestamp,
    nbf: UnixTimestamp,
    iat: UnixTimestamp,
    roles: Vec<RoleId>,
}

// Make sure we only assemble it here, so we can be sure it's valid
impl Claims {
    pub fn new(sub: ClientId, roles: Vec<RoleId>) -> Self {
        let now = UnixTimestamp::now();
        Claims {
            sub,
            exp: now.add_one_hour(),
            nbf: now,
            iat: now,
            roles,
        }
    }
}

//--------------------------------------------------------------------------------------------------
