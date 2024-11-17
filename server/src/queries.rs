use crate::db::DbConnectionPool;
use crate::db_models::{Client, ClientRole, Role};
use crate::types::{ClientId, ClientSecretHash, RoleDescription, RoleId};
use diesel::dsl::insert_into;
use diesel::{
    AsChangeset, BelongingToDsl, ExpressionMethods, OptionalExtension, QueryDsl, SelectableHelper,
};
use diesel_async::*;

//--------------------------------------------------------------------------------------------------
// Get client by ID
//--------------------------------------------------------------------------------------------------

pub async fn get_client_by_id(
    client_id: &ClientId,
    db_connection_pool: &DbConnectionPool,
) -> Result<Option<Client>, anyhow::Error> {
    use crate::schema::clients::dsl::clients;

    let mut db_connection = db_connection_pool.get().await?;
    let client = clients
        .find(client_id)
        .first::<Client>(&mut db_connection)
        .await
        .optional()?;

    Ok(client)
}

//--------------------------------------------------------------------------------------------------
// Get roles for client
//--------------------------------------------------------------------------------------------------

pub async fn get_role_ids_for_client(
    client: &Client,
    db_connection_pool: &DbConnectionPool,
) -> Result<Vec<RoleId>, anyhow::Error> {
    use crate::schema::client_roles;

    let mut db_connection = db_connection_pool.get().await?;
    let role_ids = ClientRole::belonging_to(client)
        .select(client_roles::role_id)
        .load::<RoleId>(&mut db_connection)
        .await?;

    Ok(role_ids)
}

//--------------------------------------------------------------------------------------------------
// Get client roles for client
//--------------------------------------------------------------------------------------------------

pub async fn get_client_roles_for_client(
    client: &Client,
    db_connection_pool: &DbConnectionPool,
) -> Result<Vec<ClientRole>, anyhow::Error> {
    let mut db_connection = db_connection_pool.get().await?;
    let role_ids = ClientRole::belonging_to(client)
        .select(ClientRole::as_select())
        .load::<ClientRole>(&mut db_connection)
        .await?;

    Ok(role_ids)
}

//--------------------------------------------------------------------------------------------------
// Get client role
//--------------------------------------------------------------------------------------------------

pub async fn get_client_role(
    client_id: &ClientId,
    role_id: &RoleId,
    db_connection_pool: &DbConnectionPool,
) -> Result<Option<ClientRole>, anyhow::Error> {
    use crate::schema::client_roles::dsl::client_roles;

    let mut db_connection = db_connection_pool.get().await?;
    let client_role = client_roles
        .find((client_id, role_id))
        .first::<ClientRole>(&mut db_connection)
        .await
        .optional()?;

    Ok(client_role)
}

//--------------------------------------------------------------------------------------------------
// Add client role
//--------------------------------------------------------------------------------------------------

pub async fn add_client_role(
    new_client_id: &ClientId,
    new_role_id: &RoleId,
    db_connection_pool: &DbConnectionPool,
) -> Result<ClientRole, anyhow::Error> {
    use crate::schema::client_roles::dsl::*;

    let mut db_connection = db_connection_pool.get().await?;
    let client_role = insert_into(client_roles)
        .values((client_id.eq(new_client_id), role_id.eq(new_role_id)))
        .get_result(&mut db_connection)
        .await?;

    Ok(client_role)
}

//--------------------------------------------------------------------------------------------------
// Delete client role
//--------------------------------------------------------------------------------------------------

pub async fn delete_client_role(
    client_id: &ClientId,
    role_id: &RoleId,
    db_connection_pool: &DbConnectionPool,
) -> Result<(), anyhow::Error> {
    use crate::schema::client_roles::dsl::client_roles;

    let mut db_connection = db_connection_pool.get().await?;
    diesel::delete(client_roles.find((client_id, role_id)))
        .execute(&mut db_connection)
        .await?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Get all clients
//--------------------------------------------------------------------------------------------------

pub async fn get_all_clients(
    db_connection_pool: &DbConnectionPool,
) -> Result<Vec<Client>, anyhow::Error> {
    use crate::schema::clients::dsl::clients;

    let mut db_connection = db_connection_pool.get().await?;
    let clients_list = clients
        .select(Client::as_select())
        .load::<Client>(&mut db_connection)
        .await?;

    Ok(clients_list)
}

//--------------------------------------------------------------------------------------------------
// Create client
//--------------------------------------------------------------------------------------------------

pub async fn create_client(
    new_client_id: &ClientId,
    new_client_secret_hash: &ClientSecretHash,
    new_disabled: bool,
    db_connection_pool: &DbConnectionPool,
) -> Result<Client, anyhow::Error> {
    use crate::schema::clients::dsl::*;

    let mut db_connection = db_connection_pool.get().await?;
    let client = insert_into(clients)
        .values((
            client_id.eq(new_client_id),
            client_secret_hash.eq(new_client_secret_hash),
            disabled.eq(new_disabled),
        ))
        .get_result(&mut db_connection)
        .await?;

    Ok(client)
}

//--------------------------------------------------------------------------------------------------
// Update client
//--------------------------------------------------------------------------------------------------

#[derive(AsChangeset)]
#[diesel(table_name = crate::schema::clients)]
pub struct UpdateClientChangeset {
    pub client_secret_hash: Option<ClientSecretHash>,
    pub disabled: Option<bool>,
}

pub async fn update_client(
    client: &Client,
    changeset: &UpdateClientChangeset,
    db_connection_pool: &DbConnectionPool,
) -> Result<Client, anyhow::Error> {
    let mut db_connection = db_connection_pool.get().await?;
    let client = diesel::update(client)
        .set(changeset)
        .get_result(&mut db_connection)
        .await?;

    Ok(client)
}

//--------------------------------------------------------------------------------------------------
// Get role by ID
//--------------------------------------------------------------------------------------------------

pub async fn get_role_by_id(
    role_id: &RoleId,
    db_connection_pool: &DbConnectionPool,
) -> Result<Option<Role>, anyhow::Error> {
    use crate::schema::roles::dsl::roles;

    let mut db_connection = db_connection_pool.get().await?;
    let role = roles
        .find(role_id)
        .first::<Role>(&mut db_connection)
        .await
        .optional()?;

    Ok(role)
}

//--------------------------------------------------------------------------------------------------
// Get all roles
//--------------------------------------------------------------------------------------------------

pub async fn get_all_roles(
    db_connection_pool: &DbConnectionPool,
) -> Result<Vec<Role>, anyhow::Error> {
    use crate::schema::roles::dsl::roles;

    let mut db_connection = db_connection_pool.get().await?;
    let roles_list = roles
        .select(Role::as_select())
        .load::<Role>(&mut db_connection)
        .await?;

    Ok(roles_list)
}

//--------------------------------------------------------------------------------------------------
// Create role
//--------------------------------------------------------------------------------------------------

pub async fn create_role(
    new_role_id: &RoleId,
    new_description: &Option<RoleDescription>,
    db_connection_pool: &DbConnectionPool,
) -> Result<Role, anyhow::Error> {
    use crate::schema::roles::dsl::*;

    let mut db_connection = db_connection_pool.get().await?;
    let role = insert_into(roles)
        .values((role_id.eq(new_role_id), description.eq(new_description)))
        .get_result(&mut db_connection)
        .await?;

    Ok(role)
}

//--------------------------------------------------------------------------------------------------
// Update role
//--------------------------------------------------------------------------------------------------

pub async fn update_role(
    role: &Role,
    new_description: &Option<RoleDescription>,
    db_connection_pool: &DbConnectionPool,
) -> Result<Role, anyhow::Error> {
    use crate::schema::roles::dsl::*;

    let mut db_connection = db_connection_pool.get().await?;
    let role = diesel::update(role)
        .set(description.eq(new_description))
        .get_result(&mut db_connection)
        .await?;

    Ok(role)
}

//--------------------------------------------------------------------------------------------------
// Get client count
//--------------------------------------------------------------------------------------------------

pub async fn get_client_count(db_connection_pool: &DbConnectionPool) -> Result<i64, anyhow::Error> {
    use crate::schema::clients::dsl::clients;

    let mut db_connection = db_connection_pool.get().await?;
    let client_count = clients.count().get_result(&mut db_connection).await?;

    Ok(client_count)
}

//--------------------------------------------------------------------------------------------------
// Get role count
//--------------------------------------------------------------------------------------------------

pub async fn get_role_count(db_connection_pool: &DbConnectionPool) -> Result<i64, anyhow::Error> {
    use crate::schema::roles::dsl::roles;

    let mut db_connection = db_connection_pool.get().await?;
    let role_count = roles.count().get_result(&mut db_connection).await?;

    Ok(role_count)
}

//--------------------------------------------------------------------------------------------------
