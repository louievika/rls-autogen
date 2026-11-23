# rls-autogen

One Postgres migration that turns on row level security for every new table in a Supabase project's `public` schema and adds owner-only policies when the table has an owner column.

## Problem

Supabase requires explicit grants to expose new tables through the Data API by default. Once you grant `anon` or `authenticated` access to a table in an exposed schema such as `public`, row level security (RLS) limits which rows those roles can access. When creating a table through SQL, enable RLS and add the policies your application needs. This migration automates that step for supported table creation commands in `public`. See the [Supabase Data API changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically).

## Why it matters

On a table without RLS, API roles can exercise their table grants across all rows. Enabling RLS as soon as a table is created limits access to the rows its policies allow. With no applicable policy, access is denied.

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

Only when the table has no such foreign key column, a name fallback applies: a `uuid` column named exactly `user_id`, else exactly `owner_id`, is the owner column. A foreign key column always wins over the name fallback. A `user_id` or `owner_id` column of another type (`text`, `bigint` and so on) is not used.

If no owner column is found, the table gets RLS and no policies, so it is deny-all for `anon` and `authenticated` until you add your own. A notice says which case applied.

Policies that already exist under one of the four names are left as they are. Grants are not changed. Partitioned tables and partitions are both handled. `CREATE TABLE AS` and `SELECT INTO` are covered.

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

Run it as the table owner. The helper preserves existing policies by name. If it previously generated policies from a fallback `user_id` or `owner_id` and the new foreign key identifies a different owner column, those policies still use the old column. Review the existing policies first. In one transaction, remove the generated policies that need to change and call the helper to recreate them. If all four policies were generated for the old owner column, use:

```sql
begin;
drop policy owner_select on public.posts;
drop policy owner_insert on public.posts;
drop policy owner_update on public.posts;
drop policy owner_delete on public.posts;
select maintenance.apply_owner_policies('public.posts');
commit;
```

Review any custom policies separately. If the table has multiple candidate foreign keys, the owner selection rules above still apply.

To watch more schemas than `public`, add them to the `c_schemas` array at the top of `maintenance.rls_autogen()`.

## Verify

After installing, run the self-check as `postgres`:

```sh
psql "$DATABASE_URL" -f test/verify.sql
```

Or paste it into the SQL editor and choose "Run without RLS" when asked. A good run shows Success; the PASS notices appear only in psql. It takes a few seconds.

It runs in one transaction that ends in `rollback`, so it leaves nothing behind. It creates tables named `public.demo_*` and stops with an error if one already exists. It also creates two `auth.users` rows with random ids, then acts as `anon` and as two signed-in users the way the Data API does (`set local role` plus `request.jwt.claims`). It checks: RLS on, the four policies, anon denied, owner allowed on their own rows only, another user denied, no-owner tables deny-all, the opt-out, owner column choice, the name fallback (`user_id` or `owner_id` without a foreign key, non-uuid columns ignored, foreign key wins), quoted and unusual table names, re-runs, existing policies kept, `CREATE TABLE AS`, `SELECT INTO`, partitions, and that other schemas and temporary tables are left alone.

A good run prints one `NOTICE:  PASS ...` line per check and ends with:

```
NOTICE:  ALL CHECKS PASSED
ROLLBACK
```

A failing check stops with `ERROR:  FAIL <check>: <reason>`, and every later statement reports `current transaction is aborted` until the final `ROLLBACK`. Add `-v ON_ERROR_STOP=1` to make psql exit non-zero on failure. Any trigger you have on `auth.users` runs for the two test rows and is rolled back with them.

Verification performed on an isolated Supabase project with disposable credentials. Results reproducible with the included test script.

Screenshots of a verification run are in [`proofs/`](proofs/).

## Security notes

- A foreign key added later with `alter table` does not fire the trigger. Run `select maintenance.apply_owner_policies('public.t');` by hand.
- Tables that existed before the migration are not changed. Use the same call.
- Table owners, roles with `BYPASSRLS` and `service_role` bypass RLS by design. On Supabase this includes `postgres`.
- On hosted Supabase, event triggers do not fire for superuser or reserved roles (`supabase_admin`, `service_role`, `anon`, `authenticated` and others). Tables those roles create are not changed.
- RLS is enabled, not forced, so the table owner is not restricted.
- The functions run as the caller (`security invoker`), with an empty `search_path` and quoted identifiers. `public`, `anon` and `authenticated` have no access to the `maintenance` schema or its functions; only their owner and `postgres` do. A role that is not `postgres` and creates a table in `public` gets an error and must be granted `usage` on `maintenance` and `execute` on `maintenance.apply_owner_policies(regclass)`, or opt out for that transaction.
- The name fallback trusts the column name. A `uuid` column called `user_id` or `owner_id` without a foreign key is treated as the owner, whatever it really holds. If such a column means something else in your table, add a foreign key to the real owner column, or opt out and write your own policies.
- Policies only cover the owner case. Anything shared or public needs its own policies.

## License

MIT. See [`LICENSE`](LICENSE).
