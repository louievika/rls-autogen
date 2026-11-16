# Changelog

All notable changes to this project are listed here. The format follows Keep a Changelog.

## 2.0.0 - 2026-11-15

### Security

- Breaking: the opt-out is now `select maintenance.skip_rls_autogen();` inside the transaction that creates the tables. It sets `maintenance.rls_autogen` to the token `skip:<transaction id>:<start time>`, the start time being the transaction's start in whole microseconds since 1970. The trigger skips a table only when the value is exactly that token for the transaction it runs in and the creating role has usage on schema `maintenance` and execute on `maintenance.skip_rls_autogen()`, so those grants control the opt-out, also for a token set by hand. `set local maintenance.rls_autogen = 'off'` and every other value (a token of an earlier transaction, a plain `set`, a role, database, server or connection value, the token from a role without the grants) are ignored: the table is protected and one WARNING per statement says the value was ignored, naming the missing grant where that is the reason. A value stored ahead of time would have to contain the microsecond start time of a transaction that has not started yet. This needs PostgreSQL 13 or later.
- Each table skipped by the opt-out raises a WARNING that names it and says the opt-out is set for this transaction.
- A table that an extension script creates in `public` gets RLS and no policies, and a WARNING names the table and the extension, when the trigger fires for the role that runs the script. No owner column is guessed on an extension's table.
- The name fallback (`user_id`, else `owner_id`) is used only when that column has no foreign key at all. A `user_id` or `owner_id` with a foreign key to another table is not an owner column: the table gets RLS, no policies and a notice naming the referenced table.
- A table with an owner column gets RLS, no policies and a WARNING with the reason when the creating role has no usage on schema `auth`, or when `auth.uid()` or the role `authenticated` is missing.
- A creating role without usage on schema `maintenance` and execute on `maintenance.apply_owner_policies(regclass)` no longer gets an error on `create table`. The trigger enables RLS on the new table itself, adds no policies, and raises a WARNING that names the table, the missing grants and the fix. No default grant is widened.

### Changed

- Domains over `uuid`, at any depth, count as `uuid` in both the foreign key rule and the name rule.
- `auth.users` and `auth.uid()` are found through the catalogs, so a caller without usage on schema `auth` gets no error from the lookup.
- Install skips the revoke or grant for a role that does not exist (`anon`, `authenticated` or `postgres`) and prints a notice. It grants execute on `maintenance.skip_rls_autogen()` to `postgres` and no longer grants execute on the event trigger function, which needs none.
- The hint on the trigger's remaining permission error names the likely cause (the role does not own the table) and no longer suggests turning the trigger off.

### Added

- The function `maintenance.skip_rls_autogen()`.
- Self-check: check 0 shows with a probe table that the trigger fires for the role running the file, and reports any error creating it as `FAIL 0`. New checks g1 (the token set by hand counts only with the opt-out grants), g2 (ignored opt-out values, including a token with the right transaction id and another start time), h10 (extension tables), h11 (`set schema` and `attach partition` stay uncovered until the manual call), i5 to i7 (foreign key to another table, domains over `uuid`), j0 (a role without the maintenance grants), j1 (a role without usage on schema `auth`) and j2 (the manual call by an owner other than `postgres`, and that role's opt-out with and without execute on `maintenance.skip_rls_autogen()`). Checks h10 and j2 print SKIP when they cannot run, and the last line then names the skipped checks.
- Self-check assertions fail on a missing row or a NULL value instead of passing.

### Documentation

- README: requirements, the shared `maintenance` schema, a one-transaction install, read and write owner policies and how to make a table read-only, the grants a role other than `postgres` needs, the opt-out, and every form of the self-check's last line.
- README: limits stated once: views, materialized views, foreign tables, `create schema`, `set schema`, `attach partition`, foreign keys added later, partitions and the manual call, dump and restore, and platforms that do not fire event triggers for some roles, with a query that lists tables in `public` with RLS off.
- Migration header: a summary, the known limits and the accepted risks, including that a table's owner can still disable RLS on their own table.

## 1.0.0 - 2026-11-14

- First version.
