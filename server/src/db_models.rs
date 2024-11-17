use crate::types::{ClientId, ClientSecretHash, RoleDescription, RoleId};
use diesel::prelude::*;
use time::OffsetDateTime;

//--------------------------------------------------------------------------------------------------
// Database Models
//--------------------------------------------------------------------------------------------------

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::clients)]
#[diesel(primary_key(client_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Client {
    pub client_id: ClientId,
    pub client_secret_hash: ClientSecretHash,
    pub disabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Queryable, Selectable, Identifiable)]
#[diesel(table_name = crate::schema::roles)]
#[diesel(primary_key(role_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Role {
    pub role_id: RoleId,
    pub description: Option<RoleDescription>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Queryable, Selectable, Identifiable, Associations)]
#[diesel(belongs_to(Client))]
#[diesel(belongs_to(Role))]
#[diesel(table_name = crate::schema::client_roles)]
#[diesel(primary_key(client_id, role_id))]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ClientRole {
    pub client_id: ClientId,
    pub role_id: RoleId,
    pub added_at: OffsetDateTime,
}

//--------------------------------------------------------------------------------------------------
