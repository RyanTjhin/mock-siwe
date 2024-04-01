create table
contributors (
  id integer primary key,  
  telegram_handle text,
  discord_handle text,
  address text unique not null,
  non_evm_identifier jsonb[]
);
