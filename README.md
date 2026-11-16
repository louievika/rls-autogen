# rls-autogen

One Postgres migration that turns on row level security for every new table in a Supabase project's `public` schema and adds owner-only policies when the table has an owner column.

## Problem

On Supabase, the default privileges in `public` give `anon` and `authenticated` full access to every new table, and `public` is exposed through the Data API. Row level security is off until someone runs `alter table ... enable row level security` and writes policies. That step is easy to forget, and nothing in Postgres warns you.

## Why it matters

A table without RLS in an exposed schema can be read and written by anyone holding the public anon key, which ships in every client. One forgotten table is enough to leak or lose data. Making RLS the default turns that mistake into a table that returns no rows, which shows up in testing instead of in production.

## Install

Copy `migrations/20261114000000_rls_autogen.sql` into `supabase/migrations/` and apply it as you apply other migrations, for example:

```sh
supabase db push
```

Or run the file once as the `postgres` role:

```sh
psql "$DATABASE_URL" -f migrations/20261114000000_rls_autogen.sql
```

It creates a schema `maintenance` with two functions, and one event trigger named `rls_autogen`. The file is safe to run again.

## Usage

Create a table as usual:

```sql
create table public.posts (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  body    text not null
);
```

You get:

- row level security enabled on `public.posts` (not forced);
- four policies for the `authenticated` role, each with the predicate `(select auth.uid()) = user_id`:
  `owner_select` (using), `owner_insert` (with check), `owner_update` (using and with check), `owner_delete` (using).

The owner column is a `uuid` column with a single-column foreign key to `auth.users(id)`. If there are several, `user_id` is used, then `owner_id`. If none can be chosen, the table gets RLS and no policies.

Only when the table has no such foreign key column, a name fallback applies: a `uuid` column named exactly `user_id`, else exactly `owner_id`, is the owner column, but only if that column has no foreign key at all. If it has a foreign key to another table (or any foreign key other than a single-column key to `auth.users(id)`), it is not the owner column: the table gets RLS and no policies, and a notice says the column references another table and that you add the policies yourself. A foreign key column always wins over the name fallback. A `user_id` or `owner_id` column of another type (`text`, `bigint` and so on) is not used.

In both rules a `uuid` column may also be a domain over `uuid`, at any depth.

If no owner column is found, the table gets RLS and no policies, so it is deny-all for `anon` and `authenticated` until you add your own. The same happens when `auth.users` does not exist. A notice says which case applied.

Policies that already exist under one of the four names are left as they are. Grants are not changed. Partitioned tables and partitions created with `partition of` are both handled. `CREATE TABLE AS` and `SELECT INTO` are covered.

A table that an extension script creates in `public`, during `create extension` or `alter extension ... update`, is handled in one of two ways, depending on which role runs the script:

- The script runs as the role that ran the command, and that role is not a superuser: the trigger fires. The table gets RLS enabled and no policies: no owner column is guessed on an extension's table. A `WARNING` names the table and the extension and says it is locked with no policies. It is a warning, not a notice, because Postgres hides messages below `WARNING` while an extension script runs. If `anon` or `authenticated` need the table, add a policy yourself. This includes a function that reads such a table while running as an API role, for example a coordinate transform reading its reference table: it gets no rows until you add a read policy for that role.
- The script runs as a superuser: the table is not touched and no message is shown, because event triggers do not fire for superusers. It keeps RLS off. Check such tables and secure them yourself.

To list the tables in `public` that have RLS off:

```sql
select c.oid::regclass as table_name, c.relowner::regrole as owner
  from pg_catalog.pg_class c
 where c.relnamespace = 'public'::regnamespace
   and c.relkind in ('r', 'p')
   and not c.relrowsecurity;
```

Opt out for the tables created in one transaction:

```sql
begin;
set local maintenance.rls_autogen = 'off';
create table public.public_lookup (code text primary key, label text not null);
commit;
```

`off`, `false` and `0` (any case) switch it off. Any other value, or no value, means on.

Existing tables, or a table that got its owner foreign key later through `alter table`, need one manual call:

```sql
select maintenance.apply_owner_policies('public.posts');
```

Run it as the table owner. It is idempotent.

To watch more schemas than `public`, add them to the `c_schemas` array at the top of `maintenance.rls_autogen()`.

## Verify

After installing, run the self-check as `postgres`:

```sh
psql "$DATABASE_URL" -f test/verify.sql
```

Or paste it into the SQL editor and choose "Run without RLS" when asked. A good run shows Success; the PASS notices appear only in psql. It takes a few seconds.

It runs in one transaction that ends in `rollback`, so it leaves nothing behind. It creates tables and domains named `public.demo_*` and stops with an error if one already exists. It also creates two `auth.users` rows with random ids, then acts as `anon` and as two signed-in users the way the Data API does (`set local role` plus `request.jwt.claims`). It checks: RLS on, the four policies, anon denied, owner allowed on their own rows only, another user denied, no-owner tables deny-all, the opt-out, owner column choice, the name fallback (`user_id` or `owner_id` without a foreign key, non-uuid columns ignored, foreign key wins, a `user_id` with a foreign key to another table gets no policies), domains over `uuid`, quoted and unusual table names, re-runs, existing policies kept, `CREATE TABLE AS`, `SELECT INTO`, partitions, that other schemas and temporary tables are left alone, and that tables created by an extension get RLS and no policies (check h10). For h10 it creates the first of `pg_partman` and `postgis` that is available and not installed yet in `public`, inside the same transaction, and checks every table that extension put there. A table counts as a test of the trigger only when it is owned by the current role and that role is not a superuser, which shows the script ran as that role; a table owned by another role, such as a superuser, is recorded as not a test of the trigger. It tries `postgis` only if `pg_partman` tested no table. Any error from that `create extension` is a FAIL. Check h11 pins a documented limit: a table moved into `public` with `set schema` and a partition attached with `attach partition` keep RLS off until the manual call.

A good run prints one `NOTICE:  PASS ...` line per check and ends with:

```
NOTICE:  ALL CHECKS PASSED
ROLLBACK
```

If neither extension is available and not installed yet, or the one created ran its script as another role (the SKIP line names the table, its owner and the reason), h10 prints `NOTICE:  SKIP h10: ...` instead of a PASS, and the last line reads `NOTICE:  ALL CHECKS PASSED (1 skipped: h10)`. That is not a full pass: extension tables were not tested.

A failing check stops with `ERROR:  FAIL <check>: <reason>`, and every later statement reports `current transaction is aborted` until the final `ROLLBACK`. Add `-v ON_ERROR_STOP=1` to make psql exit non-zero on failure. Any trigger you have on `auth.users` runs for the two test rows and is rolled back with them.

Verification performed on an isolated Supabase project with disposable credentials. Results reproducible with the included test script.

Screenshots of a verification run are in [`proofs/`](proofs/).

## Security notes

- A foreign key added later with `alter table` does not fire the trigger. Run `select maintenance.apply_owner_policies('public.t');` by hand.
- A `user_id` or `owner_id` column whose foreign key to another table is added after `create table` (as a schema restore does) already got the four name fallback policies, and neither the new foreign key nor the call above removes them; drop them yourself.
- Tables that existed before the migration are not changed. Use the same call.
- `alter table ... set schema public` does not fire the trigger, so a table moved into `public` keeps RLS off. Run the same call on it, or enable RLS and add policies on it yourself.
- `alter table ... attach partition` does not fire the trigger, so an attached partition keeps RLS off, and a query on the partition itself does not apply the parent's policies. Run the same call on the partition, or enable RLS and add policies on it yourself. A partition created with `create table ... partition of` is covered.
- Extension tables, as described under Usage: when the extension's script runs as the calling role (not a superuser), its tables in `public` get RLS on, no policies and a `WARNING`. When the script runs as a superuser, its tables are not touched and no message is shown, because event triggers do not fire for superusers; find them with the query under Usage and secure them yourself.
- Table owners, roles with `BYPASSRLS` and `service_role` bypass RLS by design. On Supabase this includes `postgres`.
- On hosted Supabase, event triggers do not fire for superuser or reserved roles (`supabase_admin`, `service_role`, `anon`, `authenticated` and others). Tables those roles create are not changed.
- RLS is enabled, not forced, so the table owner is not restricted.
- The functions run as the caller (`security invoker`), with an empty `search_path` and quoted identifiers. `public`, `anon` and `authenticated` have no access to the `maintenance` schema or its functions; only their owner and `postgres` do. A role that is not `postgres` and creates a table in `public` gets an error and must be granted `usage` on `maintenance` and `execute` on `maintenance.apply_owner_policies(regclass)`, or opt out for that transaction.
- The name fallback trusts the column name. A `uuid` column called `user_id` or `owner_id` without any foreign key is treated as the owner, whatever it really holds. If such a column means something else in your table, add a foreign key to the real owner column, or opt out and write your own policies.
- Policies only cover the owner case. Anything shared or public needs its own policies.

## License

MIT. See [`LICENSE`](LICENSE).
