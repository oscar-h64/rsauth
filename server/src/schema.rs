// @generated automatically by Diesel CLI.

diesel::table! {
    client_roles (client_id, role_id) {
        client_id -> Text,
        role_id -> Text,
        added_at -> Timestamptz,
    }
}

diesel::table! {
    clients (client_id) {
        client_id -> Text,
        client_secret_hash -> Text,
        disabled -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    roles (role_id) {
        role_id -> Text,
        description -> Nullable<Text>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(client_roles -> clients (client_id));
diesel::joinable!(client_roles -> roles (role_id));

diesel::allow_tables_to_appear_in_same_query!(client_roles, clients, roles,);
