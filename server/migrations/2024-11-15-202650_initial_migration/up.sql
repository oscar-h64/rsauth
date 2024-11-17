create table clients (
    client_id text primary key,
    client_secret_hash text not null,
    disabled boolean not null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now()
);

select diesel_manage_updated_at('clients');

create table roles (
    role_id text primary key,
    description text null,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now()
);

select diesel_manage_updated_at('roles');

create table client_roles (
    client_id text not null,
    role_id text not null,
    added_at timestamp with time zone not null default now(),
    primary key (client_id, role_id),
    foreign key (client_id) references clients (client_id),
    foreign key (role_id) references roles (role_id)
);

-- we don't need an index on client_id because it's the first column in the primary key
create index client_roles_role_id_idx on client_roles (role_id);
