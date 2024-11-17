use serde::Deserialize;
use std::fmt::Display;

//--------------------------------------------------------------------------------------------------

// Note: this is a different ClientId and RoleId to the one defined in server

#[derive(Deserialize, Clone, Debug)]
pub struct ClientId(String);

impl Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.clone())
    }
}

#[derive(Deserialize, Clone)]
pub(crate) struct RoleId(String);

impl RoleId {
    pub(crate) fn in_role_set(&self, role_set: &[&'static str]) -> bool {
        role_set.iter().any(|role| role == &self.0)
    }
}

//--------------------------------------------------------------------------------------------------
