use crate::client_admin_role::ClientAdminRole;
use crate::queries::{
    add_client_role, create_client, create_role, get_client_count, get_role_count,
};
use crate::types::{ClientId, ClientSecret, ClientSecretHash, RoleDescription};
use bb8::Pool;
use diesel::{Connection, PgConnection};
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::AsyncPgConnection;
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use tracing::info;

//--------------------------------------------------------------------------------------------------
// DB Pool Type
//--------------------------------------------------------------------------------------------------

pub type DbConnectionPool = Pool<AsyncDieselConnectionManager<AsyncPgConnection>>;

//--------------------------------------------------------------------------------------------------
// Migrations
//--------------------------------------------------------------------------------------------------

const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

pub async fn run_migrations(connection_string: String) -> anyhow::Result<()> {
    // Get a connection and run migrations - we cannot use diesel_async because it doesn't have
    // run_pending_migrations
    let db_conn = &mut PgConnection::establish(&connection_string)?;
    let migrations_done = db_conn
        .run_pending_migrations(MIGRATIONS)
        .expect("Failed to run migrations");
    if migrations_done.is_empty() {
        info!("No migrations to run");
    } else {
        info!("Ran migrations: {:?}", migrations_done);
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Seeding
//--------------------------------------------------------------------------------------------------

// Used to prevent other code from creating IDs/secrets from UUIDs
#[allow(dead_code)]
pub struct SeedPermission(bool);

pub async fn seed_db(connection_pool: &DbConnectionPool) -> anyhow::Result<()> {
    // Get all the clients and roles
    let client_count = get_client_count(connection_pool).await?;
    let role_count = get_role_count(connection_pool).await?;

    if client_count > 0 || role_count > 0 {
        info!(
            "Database has {} clients and {} roles, no seeding required",
            client_count, role_count
        );
        return Ok(());
    }

    info!("Database empty - seeding");

    // Create a client
    let client_id_uuid = uuid::Uuid::new_v4();
    let client_secret_uuid = uuid::Uuid::new_v4();
    let client_id = ClientId::from_uuid(SeedPermission(true), client_id_uuid);
    let client_secret = ClientSecret::from_uuid(SeedPermission(true), client_secret_uuid);

    info!(
        "NOTE CAREFULLY: Admin client created with ID {:?} and secret {:?}.",
        client_id_uuid, client_secret_uuid
    );

    let secret_hash = ClientSecretHash::from_secret(client_secret).expect("Failed to hash secret");

    create_client(&client_id, &secret_hash, false, connection_pool).await?;

    // Create a role
    let role_id = ClientAdminRole.into();
    let role_description = RoleDescription::seed_client_admin_description(SeedPermission(true));

    create_role(&role_id, &Some(role_description), connection_pool).await?;

    // Grant the role to the client
    add_client_role(&client_id, &role_id, connection_pool).await?;

    info!("Seeding complete");

    Ok(())
}

//--------------------------------------------------------------------------------------------------
