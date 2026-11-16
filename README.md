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

Only when the table has no such foreign key column, a name fallback applies: it takes the `uuid` column named exactly `user_id` or, only if there is no `uuid` column `user_id`, the one named exactly `owner_id`. The column it takes is the owner column only if it has no foreign key at all, so a `user_id` with any foreign key means no policies, even if a plain `owner_id` exists beside it. If it has a foreign key to another table (or any foreign key other than a single-column key to `auth.users(id)`), it is not the owner column: the table gets RLS and no policies, and a notice says the column references another table and that you add the policies yourself. A foreign key column always wins over the name fallback. A `user_id` or `owner_id` column of another type (`text`, `bigint` and so on) is not used.

In both rules a `uuid` column may also be a domain over `uuid`, at any depth.

If no owner column is found, the table gets RLS and no policies, so it is deny-all for `anon` and `authenticated` until you add your own. The same happens when `auth.users` does not exist. A notice says which case applied. A table with an owner column also gets RLS and no policies when something the policies need is missing (see "Requirements"); a `WARNING` names the table and the reason.

### Other details

Policies that already exist under one of the four names are left as they are. Grants are not changed. Partitioned tables and partitions created with `partition of` are both handled. `CREATE TABLE AS` and `SELECT INTO` are covered.

### Extension tables

A table that an extension script creates in `public`, during `create extension` or `alter extension ... update`, is handled in one of two ways, depending on whether the event trigger fires for the role that runs the script:

- The trigger fires: the table gets RLS enabled and no policies: no owner column is guessed on an extension's table. A `WARNING` names the table and the extension and says it is locked with no policies. It is a warning, not a notice, because Postgres hides messages below `WARNING` while an extension script runs. If `anon` or `authenticated` need the table, add a policy yourself. This includes a function that reads such a table while running as an API role, for example a coordinate transform reading its reference table: it gets no rows until you add a read policy for that role. PostgreSQL documents no exception by role, so this holds when a superuser runs the script too; it documents event triggers as off only in single-user mode or with `event_triggers = off` (PostgreSQL 17 and later).
- The trigger does not fire: on some managed platforms the trigger may not fire for superuser or reserved roles. There, a table created by such a role, including by an extension script the platform runs as such a role, is not touched and no message is shown. It keeps RLS off.

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

Run it as the table owner. It is idempotent. It changes only the table you name. An owner other than `postgres` first needs these two grants:

```sql
grant usage on schema maintenance to demo_role;
grant execute on function maintenance.apply_owner_policies(regclass) to demo_role;
```

Run the first as the owner of schema `maintenance` and the second as the owner of the functions, which is the role that installed the file; a superuser can run both. They are the same role unless the schema existed before the install. The `WARNING` described below names both roles.

Without usage on schema `auth`, a table that role creates with an owner column gets RLS and no policies, and a `WARNING` says why. A table without an owner column gets RLS and no policies as usual, with the usual notice and no `WARNING`.

A role other than `postgres` that creates tables in `public` needs, for full behaviour:

- `create` on schema `public`, to create the table at all;
- usage on schema `maintenance` and execute on `maintenance.apply_owner_policies(regclass)` (the two grants above), for the trigger to add owner policies;
- usage on schema `auth` (on Supabase, through membership in `authenticated`), for the policies themselves;
- usage on schema `maintenance` and execute on `maintenance.skip_rls_autogen()`, to opt out:

```sql
grant execute on function maintenance.skip_rls_autogen() to demo_role;
```

Without the two maintenance grants, its `create table` still succeeds: the trigger enables RLS on the new table itself (the creator owns it), adds no policies, and a `WARNING` names the table, the missing grants and the fix: the two grants above, then, as that role, `select maintenance.apply_owner_policies('public.demo_table');`. The table is locked until then. Without usage on schema `maintenance` and execute on `maintenance.skip_rls_autogen()`, the role cannot opt out: the trigger ignores the token even when the role sets it by hand, protects the table and raises a `WARNING` naming the role and the missing grant (see "Opt out"). The login role needs the same two grants: a session that logs in as one role and switches with `set role` to another can opt out only when both roles have them.

On a partitioned table that already has partitions, the call enables RLS and adds policies on the parent only. Its existing partitions keep RLS off, and a query on a partition itself does not apply the parent's policies. To cover the parent and every partition at every level:

```sql
select maintenance.apply_owner_policies(t.relid)
  from pg_catalog.pg_partition_tree('public.demo_parted') t
  join pg_catalog.pg_class c on c.oid = t.relid
 where c.relkind in ('r', 'p');
```

The filter leaves out partitions that are not tables, such as foreign tables, on which RLS cannot be enabled. A partition owned by another role must be done by that role.

A partition created later with `create table ... partition of` is covered by the trigger.

### More schemas

To watch more schemas than `public`, add them to the `c_schemas` array at the top of `maintenance.rls_autogen()`.

## Requirements

- The roles `anon`, `authenticated` and `postgres` are expected, not created. The file revokes access from `anon` and `authenticated` and grants to `postgres`; for a role that does not exist it skips that step and prints a notice.
- `auth.users` is optional. Without it, every new table gets RLS and no policies, and a notice says so.
- Owner policies need the function `auth.uid()` returning `uuid`, the role `authenticated` with usage on schema `auth` and execute on `auth.uid()` (the policies call it as `authenticated`), and usage on schema `auth` for the role that creates the table. If one is missing, a table with an owner column gets RLS and no policies, and a `WARNING` names the table and the reason. Tables without an owner column are not affected.
- PostgreSQL 13 or later (the opt-out uses `pg_current_xact_id()`).
- The role that runs the file must be allowed to create event triggers. In plain PostgreSQL that is a superuser.

## Install

Before you install: the file creates a schema named `maintenance` if it does not exist, then revokes all access to it from `public`, `anon` and `authenticated`. If you already have a schema with that name, those roles lose access to it and to everything in it, and functions named `maintenance.apply_owner_policies(regclass)`, `maintenance.skip_rls_autogen()` and `maintenance.rls_autogen()` are replaced.

Copy `migrations/20261115000000_rls_autogen.sql` into `supabase/migrations/` and apply it as you apply other migrations, for example:

```sh
supabase db push
```

Or run the file as the `postgres` role, in one transaction:

```sh
psql "$DATABASE_URL" -1 -v ON_ERROR_STOP=1 -f migrations/20261115000000_rls_autogen.sql
```

It creates a schema `maintenance` with three functions, and one event trigger named `rls_autogen`. The file is safe to run again. A re-run drops and recreates the event trigger, enabled. The trigger is set to `enable always`, so it also fires when `session_replication_role` is `replica`, as data-load and restore scripts often set it. When the file runs in one transaction, as above, no table can be created between the two steps, and an error rolls back the whole file. If your migration tool does not run each file in one transaction, use the `psql` command.

If you installed 1.0.0 (`20261114000000_rls_autogen.sql`), add the new file next to it and do not edit the old one; applied over 1.0.0 it ends in the same state as a fresh install. The opt-out changed: see "Opt out" and `CHANGELOG.md`.

## Opt out

Opt out for the tables created in one transaction:

```sql
begin;
select maintenance.skip_rls_autogen();
create table public.demo_lookup (code text primary key, label text not null);
commit;
```

Every table created in `public` for the rest of that transaction is skipped, including tables an extension script creates, and each one raises a `WARNING` that names it. The function sets `maintenance.rls_autogen`, for that transaction only, to the token `skip:<transaction id>:<start time>`, where the start time is the transaction's start in whole microseconds since 1970 (the same in every time zone and locale, and inside savepoints). The trigger skips a table only when the value is exactly that token for the transaction it runs in and both `current_user` and `session_user` have usage on schema `maintenance` and execute on `maintenance.skip_rls_autogen()`. A session that logs in as one role and switches with `set role` needs the two grants on both roles; inside a function that runs with its owner's rights, `current_user` is the function's owner, so the owner needs them too. The next transaction is protected again, also on a pooled connection. Call it inside the transaction that creates the tables: run on its own in autocommit mode, it is its own transaction and skips nothing. Called before a savepoint, it still applies after `rollback to savepoint`; called inside a savepoint that is rolled back, it is undone. To protect later tables in the same transaction again, run `set local maintenance.rls_autogen = '';`.

Any other value is ignored: `off`, a value left by an earlier transaction, a plain `set`, a value set for a role or a database, in the server configuration or in the connection options, and the exact token, set by the function or by hand, when `current_user` or `session_user` lacks those two grants. The table is protected as usual, and each statement that creates a table in a watched schema raises one `WARNING` saying the value was ignored (when a role lacks the grants, which role and which grant). A stored value no longer turns anything off; clear it (for example `alter role demo_role reset maintenance.rls_autogen`) to stop the warning.

Setting the value by hand to the exact token, in the same transaction, is the same as calling the function: accepted when both `current_user` and `session_user` have the two grants, ignored otherwise. Transaction ids count up, so a value stored ahead of time for a role or a database can name a later transaction id; to match, it would also have to contain the microsecond start time of a transaction that has not started yet.

## Verify

After installing, run the self-check as `postgres`, the same role as the install:

```sh
psql "$DATABASE_URL" -f test/verify.sql
```

The install gives `postgres` the `maintenance` grants the check needs, and the trigger must fire for that role. Check 0 stops with `FAIL 0` when the trigger is missing or not enabled always (`evtenabled = 'A'`). It creates a probe table and stops with `FAIL 0` and the reason when the trigger did not fire for the role running the check, for example on a platform where the trigger may not fire for superuser or reserved roles. It also stops with `FAIL 0` when the login role lacks usage on schema `maintenance` or execute on `maintenance.skip_rls_autogen()`, and naming the missing grant when the role running the check lacks usage on schema `maintenance` or execute on `maintenance.apply_owner_policies(regclass)` or `maintenance.skip_rls_autogen()`, and when one of the three functions does not run with exactly `search_path = pg_catalog, pg_temp`.

Or paste it into the SQL editor and choose "Run without RLS" when asked. The editor shows only the result of the last statement, the `rollback`, so it shows Success for a full pass and for a run with a skipped check alike; the PASS, SKIP and final lines appear only in psql. It takes a few seconds.

It runs in one transaction that ends in `rollback`, so it leaves nothing behind. Inside that transaction it creates:

- tables and domains named `public.demo_*`, two tables in `public` with quoted names, `"demo_Mixed Case"` and the injection test table `"demo_x""); drop table public.demo_posts; --"`, the schemas `demo_other_schema` and `demo_staging`, the role `demo_role` with `create` on `public` and the function `public.demo_definer_make(text)` it owns (check g3), after check j0 the two maintenance grants above and, for check j2, membership in `authenticated` and execute on `maintenance.skip_rls_autogen()`; if one of these already exists, the run stops at the statement that creates it with the Postgres `already exists` error (`FAIL 0: ...` for the probe table of check 0), possibly after some PASS lines, and never prints `ALL CHECKS PASSED`;
- a temporary table `demo_temp` and two temporary helper functions;
- two `auth.users` rows with random ids;
- the first of the extensions `pg_partman` and `postgis` that is available, not installed yet and can be created, in `public` (check h10, below).

It acts as `anon` and as two signed-in users the way the Data API does (`set local role` plus `request.jwt.claims`). It checks: RLS on, the four policies, anon denied, owner allowed on their own rows only, another user denied, no-owner tables deny-all, the opt-out (check g: `maintenance.skip_rls_autogen()` skips, also inside and after savepoints, and a call rolled back with its savepoint is undone; check g1: the exact token set by hand by `demo_role`, which lacks the opt-out grants, is ignored and its tables are locked, while the role running the check, which has them, is skipped; check g2: a token with another transaction id, one with this id and another start time, one without the time, and `off`, `false` or `0` set with `set local` or a plain `set`, are ignored and the table is protected; check g3: after the role running the check calls `maintenance.skip_rls_autogen()`, a table created inside a function owned by `demo_role`, which runs with its owner's rights, is still locked), owner column choice, the name fallback (`user_id` or `owner_id` without a foreign key, non-uuid columns ignored, foreign key wins, a `user_id` with a foreign key to another table gets no policies), domains over `uuid`, quoted and unusual table names, re-runs, existing policies kept, `CREATE TABLE AS`, `SELECT INTO`, partitions, that other schemas and temporary tables are left alone, that tables created by an extension get RLS and no policies (check h10), that a table created with `session_replication_role = replica` gets RLS and the four policies (check h12), that a role without the two maintenance grants creates tables without error and gets RLS and no policies (check j0), that a role with them but without usage on schema `auth` does too (check j1), and the manual call by an owner other than `postgres` with the two grants, also on the tables j0 locked, plus that role's own opt-out with execute on `maintenance.skip_rls_autogen()` and its hand-set token ignored without it (check j2).

For h10 it checks every table the extension it created put in `public`, by what happened to it. RLS on and no policies is a pass, whoever owns the table. Any policy is a FAIL. RLS off is a FAIL when the table is owned by the current role, because h10 first creates a probe table to show the trigger fires for that role (a platform that reassigns ownership of extension tables after creating them gives this result too). RLS off on a table owned by another role means the script ran as that role and the trigger did not fire for it; that table is recorded as not a test of the trigger. It tries `postgis` only if `pg_partman` tested no table. An error the trigger raises during `create extension` is a FAIL; any other error (a missing dependency, for example) marks that extension unusable, and the next one is tried. Check h11 pins a documented limit: a table moved into `public` with `set schema` and a partition attached with `attach partition` keep RLS off until the manual call.

Each check prints one line: `NOTICE:  PASS <check>: ...`, `NOTICE:  SKIP <check>: ...`, or `ERROR:  FAIL <check>: ...`. The tables the opt-out checks skip on purpose (checks g, g1, h6, h11 and j2) each print a `WARNING:  rls_autogen: RLS is not enabled on ...` line, each statement in check g2, the hand-set token statements in checks g1 and j2 and the function call in check g3 print `WARNING:  rls_autogen: ignored maintenance.rls_autogen = ...`, checks g1 and j0 print `WARNING:  rls_autogen: ... is locked (RLS on, no policies): owner policies were not added because role demo_role lacks ...` for their two tables each and check g3 for its one table, and checks j1 and j2 print `WARNING:  rls_autogen: ... has owner column user_id, but role demo_role has no usage on schema auth ...`; that is expected, and SQL cannot assert a warning, so read it in the output. A good run prints one `NOTICE:  PASS ...` line per check and ends with:

```
NOTICE:  ALL CHECKS PASSED
ROLLBACK
```

If neither extension is available, not installed yet and can be created, or each one created ran its script as another role for whom the trigger did not fire (the SKIP line names each table and that role), h10 prints `NOTICE:  SKIP h10: ...` instead of a PASS. Check h12 prints `NOTICE:  SKIP h12: ...` when the role running the check may not set `session_replication_role`; check 0 has still checked that the trigger is enabled always. Check j2 prints `NOTICE:  SKIP j2: ...` when the role running the check cannot `grant authenticated to demo_role`. These are the only three checks that can skip. The last line then reads one of:

```
NOTICE:  ALL CHECKS PASSED (1 skipped: h10)
NOTICE:  ALL CHECKS PASSED (1 skipped: h12)
NOTICE:  ALL CHECKS PASSED (1 skipped: j2)
NOTICE:  ALL CHECKS PASSED (2 skipped: h10, h12)
NOTICE:  ALL CHECKS PASSED (2 skipped: h10, j2)
NOTICE:  ALL CHECKS PASSED (2 skipped: h12, j2)
NOTICE:  ALL CHECKS PASSED (3 skipped: h10, h12, j2)
```

None of these is a full pass: a skipped check was not tested (h10: extension tables; h12: a table created in replica mode; j2: the manual call that adds policies for an owner other than `postgres`).

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

Restore with the trigger disabled, then enable it again and review. Setting `session_replication_role = replica` does not stop it: the trigger is enabled always and fires in replica mode too. Re-enable it with `enable always`; a plain `enable` would let replica mode skip it again:

```sql
alter event trigger rls_autogen disable;
-- restore here
alter event trigger rls_autogen enable always;
```

Do not re-run the migration file during the restore: it re-creates the trigger enabled. Run these as the trigger's owner (the role that installed it) or a superuser. The event trigger belongs to one database. While it is disabled, no table created in that database by any session is covered. After the restore, list tables with RLS off with the query under "Extension tables", and secure the extension tables again.

### Roles the trigger does not fire for

- On hosted platforms such as Supabase, the trigger may not fire for superuser or reserved roles. A table it does not see keeps RLS off, including a table from an extension script run as such a role. Check with the RLS-off query under "Extension tables".

### By design

- Table owners, roles with `BYPASSRLS` and `service_role` bypass RLS by design. On Supabase this includes `postgres`.
- RLS is enabled, not forced, so the table owner is not restricted.
- Policies only cover the owner case. Anything shared or public needs its own policies.
- The functions run as the caller (`security invoker`), with `search_path` pinned to `pg_catalog, pg_temp` (the temporary schema last), schema-qualified names and types, and quoted identifiers.
- The install revokes all access to schema `maintenance` and its three functions from `public`, `anon` and `authenticated`, and grants usage on the schema and execute on `apply_owner_policies` and `skip_rls_autogen` to `postgres`. It does not revoke from other roles: on a `maintenance` schema that existed before, earlier grants or default privileges can give other roles access. To list every role that holds usage on the schema or execute on one of the three functions, directly, through role membership or as a superuser:

```sql
select 'schema maintenance' as object, r.rolname as role
  from pg_catalog.pg_roles r
 where pg_catalog.has_schema_privilege(r.oid, 'maintenance', 'USAGE')
union all
select p.oid::regprocedure::text, r.rolname
  from pg_catalog.pg_proc p
  cross join pg_catalog.pg_roles r
 where p.pronamespace = 'maintenance'::regnamespace
   and p.proname in ('apply_owner_policies', 'skip_rls_autogen', 'rls_autogen')
   and pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')
 order by 1, 2;
```

- A role that is not `postgres` and creates a table in `public` without the grants listed under "Tables the trigger did not see" gets the table with RLS on, no policies and a `WARNING` with the fix. That fails closed on purpose: no default grant is widened.
- The opt-out covers every table created in `public` for the rest of its transaction, extension tables included. The grants control it: the trigger honours the token only when both `current_user` and `session_user` have usage on schema `maintenance` and execute on `maintenance.skip_rls_autogen()`, however the value was set. Otherwise the table is protected (fail closed). Inside a function that runs with its owner's rights, the two checks see the function's owner and the login role: when both have the grants, the token set in that session also counts for tables the function creates for a caller without them. Who may call such a function is its owner's choice.
- A table's owner can still run `alter table ... disable row level security` on their own table; no trigger can prevent that (accepted).

## License

MIT. See [`LICENSE`](LICENSE).
