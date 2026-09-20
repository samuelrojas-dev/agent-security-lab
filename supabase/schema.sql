-- Run in the Supabase SQL editor (use a practice project, not production data).

create table if not exists products (
  id            bigint generated always as identity primary key,
  name          text    not null,
  description   text,
  price         numeric not null,   -- public: list price (COP)
  stock         integer not null,   -- public
  cost_price    numeric not null,   -- INTERNAL
  margin_pct    numeric not null,   -- INTERNAL
  supplier_id   text    not null,   -- INTERNAL
  supplier_notes text               -- INTERNAL
);

-- Layer 1: the base table is closed to the anon role.
alter table products enable row level security;
-- (no policies for anon on purpose: anon cannot read `products`)

-- Layer 2: the agent only ever sees this view (public columns only).
create or replace view products_public as
  select id, name, description, price, stock from products;

revoke all on products from anon, authenticated;
grant select on products_public to anon;

-- Server-side role used only by the evaluator and the intentionally vulnerable modes.
-- (Explicit grant, so this works even if "Automatically expose new tables" is disabled.)
grant select on products to service_role;
grant select on products_public to service_role;
