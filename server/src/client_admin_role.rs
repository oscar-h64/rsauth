//--------------------------------------------------------------------------------------------------
// client_admin Role
//--------------------------------------------------------------------------------------------------

pub struct ClientAdminRole;

impl rsauth::Role for ClientAdminRole {
    fn role_id() -> &'static str {
        "client_admin"
    }
}

//--------------------------------------------------------------------------------------------------
