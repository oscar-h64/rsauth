use serde::Deserialize;

//--------------------------------------------------------------------------------------------------
// Config to be read from file
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct Config {
    #[serde(default)]
    pub debug: bool,
    pub http_port: Option<u16>,
    pub postgres_connection_string: String,
    pub private_key_path: String,
    pub public_key_path: String,
}

//--------------------------------------------------------------------------------------------------
