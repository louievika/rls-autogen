# rls-autogen

One Postgres migration that turns on row level security for every new table in a Supabase project's `public` schema and adds owner-only policies when the table has an owner column.

## Problem

On Supabase, the default privileges in `public` give `anon` and `authenticated` full access to every new table, and `public` is exposed through the Data API. Row level security is off until someone runs `alter table ... enable row level security` and writes policies. That step is easy to forget, and nothing in Postgres warns you.

## Why it matters

A table without RLS in an exposed schema can be read and written by anyone holding the public anon key, which ships in every client. One forgotten table is enough to leak or lose data. Making RLS the default turns that mistake into a table that returns no rows, which shows up in testing instead of in production.

## What it does

An event trigger named `rls_autogen` runs after `CREATE TABLE`, `CREATE TABLE AS` and `SELECT INTO`. Create a table as usual:

```sql
create table public.demo_posts (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  body    text not null
);
```

You get:

- row level security enabled on `public.demo_posts` (not forced);
- four policies for the `authenticated` role, each with the predicate `(select auth.uid()) = user_id`:
  `owner_select` (using), `owner_insert` (with check), `owner_update` (using and with check), `owner_delete` (using).

These policies are for reading and writing. The owner can read, add, change and delete their own rows, and can change any column of their own row; the check on update only stops them from giving the row to another user. Any signed-in user can add rows that they own. If the owner should only read a table, drop the other three policies:

```sql
drop policy owner_insert on public.demo_posts;
drop policy owner_update on public.demo_posts;
drop policy owner_delete on public.demo_posts;
```

The policies are permissive. Postgres combines permissive policies with OR, so adding a narrower policy of your own does not take anything away from these. Drop the ones you do not want, or add a restrictive policy (`create policy ... as restrictive`).

### Owner column

The owner column is a `uuid` column with a single-column foreign key to `auth.users(id)`. If there are several, `user_id` is used, then `owner_id`. If none can be chosen, the table gets RLS and no policies.

Only when the table has no such foreign key column, a name fallback applies: a `uuid` column named exactly `user_id`, else exactly `owner_id`, is the owner column, but only if that column has no foreign key at all. If it has a foreign key to another table (or any foreign key other than a single-column key to `auth.users(id)`), it is not the owner column: the table gets RLS and no policies, and a notice says the column references another table and that you add the policies yourself. A foreign key column always wins over the name fallback. A `user_id` or `owner_id` column of another type (`text`, `bigint` and so on) is not used.

In both rules a `uuid` column may also be a domain over `uuid`, at any depth.

If no owner column is found, the table gets RLS and no policies, so it is deny-all for `anon` and `authenticated` until you add your own. The same happens when `auth.users` does not exist. A notice says which case applied.

### Other details

Policies that already exist under one of the four names are left as they are. Grants are not changed. Partitioned tables and partitions created with `partition of` are both handled. `CREATE TABLE AS` and `SELECT INTO` are covered.

### Extension tables

A table that an extension script creates in `public`, during `create extension` or `alter extension ... update`, is handled in one of two ways, depending on whether the event trigger fires for the role that runs the script:

- The trigger fires: the table gets RLS enabled and no policies: no owner column is guessed on an extension's table. A `WARNING` names the table and the extension and says it is locked with no policies. It is a warning, not a notice, because Postgres hides messages below `WARNING` while an extension script runs. If `anon` or `authenticated` need the table, add a policy yourself. This includes a function that reads such a table while running as an API role, for example a coordinate transform reading its reference table: it gets no rows until you add a read policy for that role. PostgreSQL documents no exception by role, so this holds when a superuser runs the script too; it documents event triggers as off only in single-user mode or with `event_triggers = off` (PostgreSQL 17 and later).
- The trigger does not fire: some managed platforms skip event triggers for superuser or reserved roles. There, a table created by such a role, including by an extension script the platform runs as such a role, is not touched and no message is shown. It keeps RLS off.

After installing an extension, check its tables and secure them yourself. To list the tables in `public` that have RLS off:

```sql
select c.oid::regclass as table_name, c.relowner::regrole as owner
  from pg_catalog.pg_class c
 where c.relnamespace = 'public'::regnamespace
   and c.relkind in ('r', 'p')
   and not c.relrowsecurity;
```

### Tables the trigger did not see

Existing tables, or a table that got its owner foreign key later through `alter table`, need one manual call:

```sql
select maintenance.apply_owner_policies('public.demo_posts');
```

Run it as the table owner. It is idempotent. It changes only the table you name.

On a partitioned table that already has partitions, the call enables RLS and adds policies on the parent only. Its existing partitions keep RLS off, and a query on a partition itself does not apply the parent's policies. To cover the parent and every partition at every level:

```sql
select maintenance.apply_owner_policies(relid)
  from pg_catalog.pg_partition_tree('public.demo_parted');
```

A partition created later with `create table ... partition of` is covered by the trigger.

### More schemas

To watch more schemas than `public`, add them to the `c_schemas` array at the top of `maintenance.rls_autogen()`.

## Requirements

- The roles `anon`, `authenticated` and `postgres`. The file revokes access from `anon` and `authenticated`, names `authenticated` in the policies, and grants to `postgres`. It does not create them. If one is missing, the file stops with `role "..." does not exist`: for `anon` or `authenticated` at the first `revoke`, for `postgres` at the first `grant`.
- `auth.users` is optional. Without it, every new table gets RLS and no policies, and a notice says so.
- `auth.uid()` is needed as soon as a table has an owner column. If `auth.users` exists but `auth.uid()` does not, a `create table` with an owner column fails with `function auth.uid() does not exist`, and the table is not created. Tables without an owner column are not affected.
- The role that runs the file must be allowed to create event triggers. In plain PostgreSQL that is a superuser.

## Install

Before you install: the file creates a schema named `maintenance` if it does not exist, then revokes all access to it from `public`, `anon` and `authenticated`. If you already have a schema with that name, those roles lose access to it and to everything in it, and functions named `maintenance.apply_owner_policies(regclass)` and `maintenance.rls_autogen()` are replaced.

Copy `migrations/20261114000000_rls_autogen.sql` into `supabase/migrations/` and apply it as you apply other migrations, for example:

```sh
supabase db push
```

Or run the file as the `postgres` role, in one transaction:

```sh
psql "$DATABASE_URL" -1 -v ON_ERROR_STOP=1 -f migrations/20261114000000_rls_autogen.sql
```

It creates a schema `maintenance` with two functions, and one event trigger named `rls_autogen`. The file is safe to run again. A re-run drops and recreates the event trigger. When the file runs in one transaction, as above, no table can be created between the two steps, and an error rolls back the whole file. If your migration tool does not run each file in one transaction, use the `psql` command.

## Opt out

Opt out for the tables created in one transaction:

```sql
begin;
set local maintenance.rls_autogen = 'off';
create table public.demo_lookup (code text primary key, label text not null);
commit;
```

`off`, `false` and `0` (any case) switch it off. Any other value, or no value, means on.

Only `set local` inside a transaction is the supported form. Set at any other level, a plain `set`, `alter role ... set`, `alter database ... set` or the connection options (`PGOPTIONS`), the switch keeps the trigger off for every later table on that connection, role or database, until it is cleared. A `set` left on a pooled connection carries over to the next client that gets that connection.

Each table the trigger skips because the switch is off raises a `WARNING` that names the table and says RLS was NOT enabled because `maintenance.rls_autogen` is off. When the value also comes from the role, the database, the connection options or the server configuration, the warning says it is set beyond this transaction and gives the `alter role ... reset` and `alter database ... reset` commands; `reset maintenance.rls_autogen` does not clear such a value. A plain `set` and `set local` cannot be told apart from SQL, so for those the warning says that only `set local` is supported and that `reset maintenance.rls_autogen` clears a plain `set`.

To check the current value (empty or null means on):

```sql
select pg_catalog.current_setting('maintenance.rls_autogen', true);
```

To find a value stored for a role, a database, a role in one database, or all roles:

```sql
select coalesce(r.rolname, '(all roles)') as role,
       coalesce(d.datname, '(all databases)') as database,
       s.setconfig
  from pg_catalog.pg_db_role_setting s
  left join pg_catalog.pg_roles r on r.oid = s.setrole
  left join pg_catalog.pg_database d on d.oid = s.setdatabase
 where pg_catalog.array_to_string(s.setconfig, ',') like '%maintenance.rls_autogen=%';
```

A value set server-wide is not in that list. To find it (superuser):

```sql
select sourcefile, setting
  from pg_catalog.pg_file_settings
 where name = 'maintenance.rls_autogen';
```

To clear a value, run the line that matches where it is stored. Some of these need superuser rights.

```sql
reset maintenance.rls_autogen;                                          -- a plain set on this connection
alter role demo_role reset maintenance.rls_autogen;                     -- one role, every database
alter role demo_role in database demo_db reset maintenance.rls_autogen; -- one role in one database
alter database demo_db reset maintenance.rls_autogen;                   -- one database, every role (same as alter role all in database)
alter role all reset maintenance.rls_autogen;                           -- all roles, every database
alter system reset maintenance.rls_autogen;                             -- server-wide (postgresql.auto.conf)
select pg_catalog.pg_reload_conf();                                     -- after alter system
```

The two commands in the warning do not clear a value stored for a role in one database, for all roles, or server-wide. A value in `postgresql.conf` or in the connection options (`PGOPTIONS`, the `options` part of a connection string) has to be removed there. Reconnect afterwards: role and database values are read when a session starts.

## Verify

After installing, run the self-check as `postgres`:

```sh
psql "$DATABASE_URL" -f test/verify.sql
```

Run it as a role the trigger fires for, such as the role that creates your tables. Check 0 creates a probe table and stops with `FAIL 0` and the reason when the trigger did not fire for the role running the check, for example on a platform that skips event triggers for superuser or reserved roles.

Run it with a plain `search_path`. Check b reads the policy predicates back as text, and when `auth` is on the `search_path` Postgres prints `uid()` instead of `auth.uid()`, so check b fails. See the current path with `show search_path;`. If it lists `auth`, run:

```sh
PGOPTIONS='-c search_path=public' psql "$DATABASE_URL" -f test/verify.sql
```

Or paste it into the SQL editor and choose "Run without RLS" when asked. If the path lists `auth`, put `set search_path = public;` above the pasted script. A good run shows Success; the PASS notices appear only in psql. It takes a few seconds.

It runs in one transaction that ends in `rollback`, so it leaves nothing behind. Inside that transaction it creates:

- tables and domains named `public.demo_*`, and the schemas `demo_other_schema` and `demo_staging`; it stops with an error if one already exists;
- a temporary table `demo_temp` and two temporary helper functions;
- two `auth.users` rows with random ids;
- the first of the extensions `pg_partman` and `postgis` that is available and not installed yet, in `public` (check h10, below).

It acts as `anon` and as two signed-in users the way the Data API does (`set local role` plus `request.jwt.claims`). It checks: RLS on, the four policies, anon denied, owner allowed on their own rows only, another user denied, no-owner tables deny-all, the opt-out (with `set local`, and check g2: a plain `set` also skips every later table until `reset`), owner column choice, the name fallback (`user_id` or `owner_id` without a foreign key, non-uuid columns ignored, foreign key wins, a `user_id` with a foreign key to another table gets no policies), domains over `uuid`, quoted and unusual table names, re-runs, existing policies kept, `CREATE TABLE AS`, `SELECT INTO`, partitions, that other schemas and temporary tables are left alone, and that tables created by an extension get RLS and no policies (check h10).

For h10 it checks every table the extension it created put in `public`, by what happened to it. RLS on and no policies is a pass, whoever owns the table. Any policy is a FAIL. RLS off is a FAIL when the table is owned by the current role, because h10 first creates a probe table to show the trigger fires for that role. RLS off on a table owned by another role means the script ran as that role and the trigger did not fire for it; that table is recorded as not a test of the trigger. It tries `postgis` only if `pg_partman` tested no table. Any error from that `create extension` is a FAIL. Check h11 pins a documented limit: a table moved into `public` with `set schema` and a partition attached with `attach partition` keep RLS off until the manual call.

Each check prints one line: `NOTICE:  PASS <check>: ...`, `NOTICE:  SKIP <check>: ...`, or `ERROR:  FAIL <check>: ...`. The tables the opt-out checks create on purpose (checks g, g2, h6 and h11) each print a `WARNING:  rls_autogen: RLS was NOT enabled on ...` line; that is expected, and SQL cannot assert a warning, so read it in the output. A good run prints one `NOTICE:  PASS ...` line per check and ends with:

```
NOTICE:  ALL CHECKS PASSED
ROLLBACK
```

If neither extension is available and not installed yet, or each one created ran its script as another role for whom the trigger did not fire (the SKIP line names each table and that role), h10 prints `NOTICE:  SKIP h10: ...` instead of a PASS, and the last line reads `NOTICE:  ALL CHECKS PASSED (1 skipped: h10)`. That is not a full pass: extension tables were not tested.

A failing check stops with `ERROR:  FAIL <check>: <reason>`, and every later statement reports `current transaction is aborted` until the final `ROLLBACK`. Add `-v ON_ERROR_STOP=1` to make psql exit non-zero on failure. Any trigger you have on `auth.users` runs for the two test rows and is rolled back with them.

Verification performed on an isolated Supabase project with disposable credentials. Results reproducible with the included test script.

Screenshots of an install and a self-check run are in [`proofs/`](proofs/).

## Limits and security notes

### Not covered

- Views (`create view`). A view runs with its owner's rights unless it is created `with (security_invoker = true)`, so a view over a protected table can show every row to `anon`. Create views with `with (security_invoker = true)` (PostgreSQL 15 and later), or revoke access to the view from `anon` and `authenticated`.
- Materialized views (`create materialized view`). RLS cannot be enabled on a materialized view, and its rows are read with no policy check. Revoke access to it from `anon` and `authenticated`, or create it in a schema the Data API does not expose.
- Foreign tables (`create foreign table`, `import foreign schema`). RLS cannot be enabled on a foreign table. Revoke access to it from `anon` and `authenticated`, or create it in a schema the Data API does not expose.
- A table created inside `create schema demo_schema create table ...`. The command tag is `CREATE SCHEMA`, so the trigger does not fire. Schema elements can only go into the new schema, so this cannot happen in `public`; it matters when you add schemas to the watched list. Create the schema first, then its tables.
- `alter table ... set schema public` does not fire the trigger, so a table moved into `public` keeps RLS off. Run the manual call on it, or enable RLS and add policies on it yourself.
- `alter table ... attach partition` does not fire the trigger, so an attached partition keeps RLS off, and a query on the partition itself does not apply the parent's policies. Run the manual call on the partition, or enable RLS and add policies on it yourself. A partition created with `create table ... partition of` is covered.
- A foreign key added later with `alter table` does not fire the trigger. Run the manual call.
- Tables that existed before the migration are not changed. Run the manual call. For a partitioned table, see "Tables the trigger did not see".

### Name fallback

- The name fallback trusts the column name. A `uuid` column called `user_id` or `owner_id` without any foreign key is treated as the owner, whatever it really holds. If such a column means something else in your table, add a foreign key to the real owner column, or opt out and write your own policies.
- A `user_id` or `owner_id` column whose foreign key to another table is added after `create table` already got the four name fallback policies, and neither the new foreign key nor the manual call removes them; drop them yourself. A schema restore does exactly this; see the next section.

### Dump and restore

A dump creates each table first and adds its foreign keys, `enable row level security` and policies later. Restored into a database that has the trigger:

- each table gets RLS as soon as it is created, before its foreign keys exist, so the name fallback adds `owner_*` policies to `user_id` and `owner_id` columns, including ones whose foreign key points to another table;
- the dump's own `create policy owner_*` statements for those tables then fail with `already exists`; with `--single-transaction` or `ON_ERROR_STOP` the first one stops the restore;
- tables that had RLS off in the source come back with RLS on and locked;
- RLS that the trigger put on an extension's table is not in the dump, so that table comes back with RLS off unless the trigger fires again during the restore.

Restore with the trigger disabled, then enable it and review:

```sql
alter event trigger rls_autogen disable;
-- restore here
alter event trigger rls_autogen enable;
```

Run these as the trigger's owner (the role that installed it) or a superuser. The event trigger belongs to one database. While it is disabled, no table created in that database by any session is covered. After the restore, list tables with RLS off with the query under "Extension tables", and secure the extension tables again.

### Roles the trigger does not fire for

- On hosted Supabase, event triggers do not fire for superuser or reserved roles (`supabase_admin`, `service_role`, `anon`, `authenticated` and others). Tables those roles create are not changed, including tables from an extension script run as such a role; see "Extension tables".

### By design

- Table owners, roles with `BYPASSRLS` and `service_role` bypass RLS by design. On Supabase this includes `postgres`.
- RLS is enabled, not forced, so the table owner is not restricted.
- Policies only cover the owner case. Anything shared or public needs its own policies.
- The functions run as the caller (`security invoker`), with an empty `search_path` and quoted identifiers. `public`, `anon` and `authenticated` have no access to the `maintenance` schema or its functions; only their owner and `postgres` do. A role that is not `postgres` and creates a table in `public` gets an error and must be granted `usage` on `maintenance` and `execute` on `maintenance.apply_owner_policies(regclass)`, or opt out for that transaction.

## License

MIT. See [`LICENSE`](LICENSE).
