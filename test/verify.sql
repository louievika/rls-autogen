-- rls_autogen self-check.
--
-- Run as postgres after applying migrations/20261115000000_rls_autogen.sql:
--   psql "$DATABASE_URL" -f test/verify.sql
-- or paste the whole file into the SQL editor.
-- The install gives postgres the maintenance grants this file needs, and the event
-- trigger must fire for that role. Some managed platforms skip event triggers for
-- superuser or reserved roles; check 0 stops with FAIL 0 and says so when the
-- trigger did not fire for the role running this file.
--
-- Everything runs in one transaction that ends in ROLLBACK, so nothing is left behind.
-- It creates tables and domains named public.demo_*, two more tables in public
-- with quoted names (public."demo_Mixed Case" and the injection test table
-- public."demo_x""); drop table public.demo_posts; --"), the schemas
-- demo_other_schema and demo_staging, the role demo_role (checks g1, g3 and j0 to j2), the
-- function public.demo_definer_make(text) (check g3), a temporary
-- table and two temporary functions, two throwaway rows in auth.users with random
-- ids, and the first of the extensions pg_partman and postgis that is available
-- and not installed yet and can be created (check h10).
-- Any trigger you have on auth.users runs for those two rows (and is rolled back with them).
-- It sets its own search_path for the transaction, so the caller's path does not matter.
--
-- Output, one line per check:
--   PASS <check>: ...   (NOTICE)
--   FAIL <check>: ...   (ERROR; the transaction is aborted)
--   SKIP <check>: ...   (NOTICE)
-- Check h10 (extension tables) prints SKIP h10 instead of PASS when neither pg_partman
-- nor postgis is available, not installed yet and can be created, or when each one
-- it creates ran its script as another role for whom the trigger did not fire
-- (not a test of the trigger). Check h12 prints SKIP h12 when this role may not set
-- session_replication_role. Check j2 prints SKIP j2 when this role cannot
-- grant authenticated to demo_role (its way to usage on schema auth).
-- h10, h12 and j2 are the only checks that can print SKIP. The last line of a good
-- run is one of:
--   NOTICE 'ALL CHECKS PASSED'
--   NOTICE 'ALL CHECKS PASSED (1 skipped: h10)'
--   NOTICE 'ALL CHECKS PASSED (1 skipped: h12)'
--   NOTICE 'ALL CHECKS PASSED (1 skipped: j2)'
--   NOTICE 'ALL CHECKS PASSED (2 skipped: h10, h12)'
--   NOTICE 'ALL CHECKS PASSED (2 skipped: h10, j2)'
--   NOTICE 'ALL CHECKS PASSED (2 skipped: h12, j2)'
--   NOTICE 'ALL CHECKS PASSED (3 skipped: h10, h12, j2)'
-- Only the first is a full pass; a skipped check was not tested.
-- Checks g, g1, h6, h11 and j2 opt out on purpose, so each table they skip prints
-- WARNING 'rls_autogen: RLS is not enabled on ...'. Checks g1, g2, g3 and j2 set
-- values that must be ignored, so each of those statements prints WARNING
-- 'rls_autogen: ignored maintenance.rls_autogen = ...'. Checks g1 and j0 print WARNING
-- 'rls_autogen: ... is locked (RLS on, no policies): owner policies were not added
-- because role demo_role lacks ...' for their two tables each, check g3 for its one
-- table. Checks j1 and j2
-- print WARNING 'rls_autogen: ... has owner column ..., but ...' for demo_role's
-- tables. All are expected.
-- The opt-out across transactions and in autocommit mode cannot be shown inside
-- this file's single transaction; check g2 uses a token with another transaction
-- id and one with another start time instead. Nor can a login role without the
-- opt-out grants: in this file session_user is always the role that logged in to run
-- it, so checks g1 and g3 show only the current_user side of the rule that both
-- current_user and session_user need the opt-out grants.

begin;
-- Predicate checks read policies back as text; pin the path so they print auth.uid().
set local search_path = public;

-- Act as a Supabase API role inside this transaction, the way PostgREST does it:
-- set local role plus the JWT claims that auth.uid() reads.
create function pg_temp.act_as(p_role text, p_sub text default null)
returns void
language plpgsql
as $$
begin
  perform pg_catalog.set_config('request.jwt.claims',
    case when p_sub is null then pg_catalog.json_build_object('role', p_role)::text
         else pg_catalog.json_build_object('sub', p_sub, 'role', p_role)::text end, true);
  perform pg_catalog.set_config('request.jwt.claim.sub', coalesce(p_sub, ''), true);
  perform pg_catalog.set_config('request.jwt.claim.role', p_role, true);
  perform pg_catalog.set_config('role', p_role, true);
end;
$$;

-- Policy summary for one table: 'cmd:name' sorted, e.g. 'a:owner_insert,d:owner_delete,...'.
create function pg_temp.policy_list(p_table regclass)
returns text
language sql
as $$
  select coalesce(pg_catalog.string_agg(p.polcmd::text || ':' || p.polname::text, ',' order by p.polcmd, p.polname), '')
    from pg_catalog.pg_policy p where p.polrelid = p_table;
$$;

-- Two throwaway users.
do $$
begin
  perform pg_catalog.set_config('verify.user_a', pg_catalog.gen_random_uuid()::text, true);
  perform pg_catalog.set_config('verify.user_b', pg_catalog.gen_random_uuid()::text, true);
  insert into auth.users (id) values
    (pg_catalog.current_setting('verify.user_a')::uuid),
    (pg_catalog.current_setting('verify.user_b')::uuid);
end;
$$;

-- 0. Setup: the trigger is installed, fires for the role running this file, that
-- role has the maintenance grants, the three functions pin their search_path, and
-- the role simulation works. Every later check needs the trigger to fire for
-- current_user, so a probe table shows that first and names the cause if not.
do $$
declare
  v_uid  uuid;
  v_rls  boolean;
  v_lack text[] := '{}';
  v_fn   text;
  v_cfg  text[];
begin
  if not exists (select 1 from pg_catalog.pg_event_trigger where evtname = 'rls_autogen') then
    raise exception 'FAIL 0: event trigger rls_autogen is missing';
  end if;
  -- 'A' (enable always): it fires also with session_replication_role = replica.
  if (select evtenabled from pg_catalog.pg_event_trigger where evtname = 'rls_autogen') is distinct from 'A' then
    raise exception 'FAIL 0: event trigger rls_autogen has evtenabled = %, expected A (alter event trigger rls_autogen enable always), so it does not fire in every session_replication_role mode',
      (select evtenabled from pg_catalog.pg_event_trigger where evtname = 'rls_autogen');
  end if;
  begin
    create table public.demo_probe_0 (id int);
  exception
    when insufficient_privilege then
      raise exception 'FAIL 0: the trigger could not secure a table created by %: %', current_user, sqlerrm;
    when others then
      raise exception 'FAIL 0: %', sqlerrm;
  end;
  select relrowsecurity into v_rls from pg_catalog.pg_class where oid = 'public.demo_probe_0'::regclass;
  drop table public.demo_probe_0;
  if v_rls is not true then
    raise exception 'FAIL 0: the trigger did not fire for a table created by role % (superuser: %, maintenance.rls_autogen: %). Some managed platforms skip event triggers for superuser or reserved roles; run this file as postgres, a role the trigger must fire for.',
      current_user,
      (select rolsuper from pg_catalog.pg_roles where rolname = current_user),
      coalesce(pg_catalog.current_setting('maintenance.rls_autogen', true), '(not set)');
  end if;
  -- The later checks call the functions as this role. Each function is looked up
  -- by its exact signature. A signature lookup raises its own error without usage
  -- on the schema, so it runs only with usage; without it, that grant is reported.
  if not pg_catalog.has_schema_privilege('maintenance', 'USAGE') then
    v_lack := v_lack || 'usage on schema maintenance'::text;
  else
    foreach v_fn in array array['maintenance.apply_owner_policies(regclass)',
                                'maintenance.skip_rls_autogen()'] loop
      if pg_catalog.to_regprocedure(v_fn) is null
         or not pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(v_fn), 'EXECUTE') then
        v_lack := v_lack || ('execute on ' || v_fn);
      end if;
    end loop;
  end if;
  if pg_catalog.cardinality(v_lack) > 0 then
    raise exception 'FAIL 0: role % lacks %; the owner of schema maintenance and of its functions (or a superuser) can grant them, or run this file as the role that installed it',
      current_user, pg_catalog.array_to_string(v_lack, ' and ');
  end if;
  -- The opt-out checks also need the login role to hold the opt-out grants.
  if not pg_catalog.has_schema_privilege(session_user, 'maintenance', 'USAGE')
     or not pg_catalog.has_function_privilege(session_user, 'maintenance.skip_rls_autogen()'::regprocedure,
                                              'EXECUTE') then
    raise exception 'FAIL 0: session user % lacks usage on schema maintenance or execute on maintenance.skip_rls_autogen(); the opt-out counts only when the session user has them too. Log in as a role that has them to run this file',
      session_user;
  end if;
  -- Each function runs with search_path pg_catalog, then pg_temp last.
  foreach v_fn in array array['maintenance.apply_owner_policies(regclass)',
                              'maintenance.skip_rls_autogen()', 'maintenance.rls_autogen()'] loop
    if pg_catalog.to_regprocedure(v_fn) is null then
      raise exception 'FAIL 0: function % does not exist', v_fn;
    end if;
    select p.proconfig into v_cfg
      from pg_catalog.pg_proc p
     where p.oid = pg_catalog.to_regprocedure(v_fn);
    if v_cfg is distinct from array['search_path=pg_catalog, pg_temp'] then
      raise exception 'FAIL 0: % has settings %, expected exactly {"search_path=pg_catalog, pg_temp"}',
        v_fn, coalesce(v_cfg::text, '(none)');
    end if;
  end loop;
  perform pg_temp.act_as('authenticated', pg_catalog.current_setting('verify.user_a'));
  select auth.uid() into v_uid;
  if v_uid is distinct from pg_catalog.current_setting('verify.user_a')::uuid
     or current_user <> 'authenticated' then
    raise exception 'FAIL 0: role simulation broken (current_user %, auth.uid() %)', current_user, v_uid;
  end if;
  reset role;
  raise notice 'PASS 0: event trigger installed, enabled always (evtenabled A), and fires for %, which, like the session user, has usage on schema maintenance and execute on apply_owner_policies and skip_rls_autogen; the three functions run with search_path pg_catalog, pg_temp; auth.uid() returns the simulated user', current_user;
end;
$$;

create table public.demo_posts (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users (id) on delete cascade,
  body    text not null default ''
);
-- Grant explicitly so the checks below test RLS, not missing grants.
grant select, insert, update, delete on public.demo_posts to anon, authenticated;
-- One row per user, written as postgres (table owner, bypasses RLS).
insert into public.demo_posts (user_id, body) values
  (current_setting('verify.user_a')::uuid, 'a-seed'),
  (current_setting('verify.user_b')::uuid, 'b-seed');

-- a. RLS enabled automatically.
do $$
begin
  if not exists (select 1 from pg_catalog.pg_class
                  where oid = 'public.demo_posts'::regclass and relrowsecurity and not relforcerowsecurity) then
    raise exception 'FAIL a: RLS is not enabled on public.demo_posts';
  end if;
  raise notice 'PASS a: RLS enabled on public.demo_posts (not forced)';
end;
$$;

-- b. Exactly four policies, one per command, all to authenticated, on user_id.
do $$
declare
  v_list text := pg_temp.policy_list('public.demo_posts');
  v_bad  int;
begin
  if v_list <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL b: unexpected policies: %', v_list;
  end if;
  select count(*) into v_bad
    from pg_catalog.pg_policy p
   where p.polrelid = 'public.demo_posts'::regclass
     and (p.polpermissive
              and p.polroles = array['authenticated'::regrole::oid]
              and case p.polcmd
                    when 'r' then p.polwithcheck is null and pg_catalog.pg_get_expr(p.polqual, p.polrelid) like '%auth.uid()%= user_id)'
                    when 'd' then p.polwithcheck is null and pg_catalog.pg_get_expr(p.polqual, p.polrelid) like '%auth.uid()%= user_id)'
                    when 'a' then p.polqual is null and pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) like '%auth.uid()%= user_id)'
                    when 'w' then pg_catalog.pg_get_expr(p.polqual, p.polrelid) like '%auth.uid()%= user_id)'
                              and pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) like '%auth.uid()%= user_id)'
                  end) is not true;
  if v_bad <> 0 then
    raise exception 'FAIL b: % policies have the wrong role, type or predicate', v_bad;
  end if;
  raise notice 'PASS b: four policies (%), permissive, to authenticated, (select auth.uid()) = user_id', v_list;
end;
$$;

-- c. anon sees nothing and changes nothing.
do $$
declare
  v_before text;
  v_after  text;
  v_n      bigint;
begin
  select pg_catalog.md5(pg_catalog.string_agg(t::text, ',' order by t.id)) into v_before from public.demo_posts t;
  if v_before is null then raise exception 'FAIL c: setup: public.demo_posts has no rows'; end if;
  perform pg_temp.act_as('anon');

  select count(*) into v_n from public.demo_posts;
  if v_n <> 0 then raise exception 'FAIL c: anon can read % rows', v_n; end if;

  begin
    insert into public.demo_posts (user_id, body) values (current_setting('verify.user_a')::uuid, 'anon');
    raise exception 'FAIL c: anon insert succeeded';
  exception when insufficient_privilege then null;
  end;

  update public.demo_posts set body = 'anon';
  get diagnostics v_n = row_count;
  if v_n <> 0 then raise exception 'FAIL c: anon update changed % rows', v_n; end if;

  delete from public.demo_posts;
  get diagnostics v_n = row_count;
  if v_n <> 0 then raise exception 'FAIL c: anon delete removed % rows', v_n; end if;

  reset role;
  select pg_catalog.md5(pg_catalog.string_agg(t::text, ',' order by t.id)) into v_after from public.demo_posts t;
  if v_after is distinct from v_before then raise exception 'FAIL c: table changed after anon attempts'; end if;
  raise notice 'PASS c: anon reads 0 of 2 rows; insert denied; update and delete affect 0 rows; table unchanged';
end;
$$;

-- d. The owner (user A) can insert, read, update and delete their own row, and not
-- insert for user B.
do $$
declare
  v_a  uuid := current_setting('verify.user_a')::uuid;
  v_b  uuid := current_setting('verify.user_b')::uuid;
  v_id uuid;
  v_n  bigint;
begin
  perform pg_temp.act_as('authenticated', v_a::text);

  insert into public.demo_posts (user_id, body) values (v_a, 'a-new') returning id into v_id;

  select count(*) into v_n from public.demo_posts where id = v_id;
  if v_n <> 1 then raise exception 'FAIL d: owner cannot read own new row'; end if;
  select count(*) into v_n from public.demo_posts where user_id <> v_a;
  if v_n <> 0 then raise exception 'FAIL d: owner can read % rows of other users', v_n; end if;

  update public.demo_posts set body = 'a-edited' where id = v_id;
  get diagnostics v_n = row_count;
  if v_n <> 1 then raise exception 'FAIL d: owner update affected % rows', v_n; end if;

  delete from public.demo_posts where id = v_id;
  get diagnostics v_n = row_count;
  if v_n <> 1 then raise exception 'FAIL d: owner delete affected % rows', v_n; end if;

  begin
    insert into public.demo_posts (user_id, body) values (v_b, 'a-as-b');
    raise exception 'FAIL d: owner inserted a row for another user';
  exception when insufficient_privilege then null;
  end;

  reset role;
  raise notice 'PASS d: owner insert, select, update, delete own row work; insert with another user id denied';
end;
$$;

-- e. Another user (B) cannot see or change A's row, and cannot hand their own row to A.
do $$
declare
  v_a       uuid := current_setting('verify.user_a')::uuid;
  v_b       uuid := current_setting('verify.user_b')::uuid;
  v_a_row   uuid;
  v_b_row   uuid;
  v_before  text;
  v_after   text;
  v_n       bigint;
begin
  select id, pg_catalog.md5(t::text) into v_a_row, v_before from public.demo_posts t where body = 'a-seed';
  select id into v_b_row from public.demo_posts where body = 'b-seed';
  if v_a_row is null or v_b_row is null then
    raise exception 'FAIL e: setup: the seed rows of user A or user B are missing';
  end if;
  perform pg_temp.act_as('authenticated', v_b::text);

  select count(*) into v_n from public.demo_posts where id = v_a_row or user_id = v_a;
  if v_n <> 0 then raise exception 'FAIL e: user B can see user A''s row'; end if;

  update public.demo_posts set body = 'b-was-here' where id = v_a_row;
  get diagnostics v_n = row_count;
  if v_n <> 0 then raise exception 'FAIL e: user B updated % of user A''s rows', v_n; end if;

  delete from public.demo_posts where id = v_a_row;
  get diagnostics v_n = row_count;
  if v_n <> 0 then raise exception 'FAIL e: user B deleted % of user A''s rows', v_n; end if;

  begin
    update public.demo_posts set user_id = v_a where id = v_b_row;
    raise exception 'FAIL e: user B moved their row to user A';
  exception when insufficient_privilege then null;
  end;

  reset role;
  select pg_catalog.md5(t::text) into v_after from public.demo_posts t where id = v_a_row;
  if v_after is distinct from v_before then raise exception 'FAIL e: user A''s row changed'; end if;
  if not exists (select 1 from public.demo_posts where id = v_b_row and user_id = v_b) then
    raise exception 'FAIL e: user B''s row changed owner';
  end if;
  raise notice 'PASS e: user B sees 0 of A''s rows; update and delete affect 0 rows; reassign to A denied; A''s row unchanged';
end;
$$;

-- f. A table with no owner column: RLS on, no policies, deny-all.
create table public.demo_notes (
  id   uuid primary key default gen_random_uuid(),
  body text not null default ''
);
grant select, insert, update, delete on public.demo_notes to anon, authenticated;
insert into public.demo_notes (body) values ('seed');

do $$
declare
  v_role   text;
  v_n      bigint;
  v_before text;
begin
  select pg_catalog.md5(pg_catalog.string_agg(t::text, ',' order by t.id)) into v_before from public.demo_notes t;
  if v_before is null then raise exception 'FAIL f: setup: public.demo_notes has no rows'; end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_notes'::regclass) is not true then
    raise exception 'FAIL f: RLS is not enabled on public.demo_notes';
  end if;
  if pg_temp.policy_list('public.demo_notes') <> '' then
    raise exception 'FAIL f: unexpected policies: %', pg_temp.policy_list('public.demo_notes');
  end if;
  foreach v_role in array array['anon', 'authenticated'] loop
    perform pg_temp.act_as(v_role, case when v_role = 'authenticated' then current_setting('verify.user_a') end);
    select count(*) into v_n from public.demo_notes;
    if v_n <> 0 then raise exception 'FAIL f: % can read % rows', v_role, v_n; end if;
    begin
      insert into public.demo_notes (body) values ('x');
      raise exception 'FAIL f: % insert succeeded', v_role;
    exception when insufficient_privilege then null;
    end;
    update public.demo_notes set body = 'x';
    get diagnostics v_n = row_count;
    if v_n <> 0 then raise exception 'FAIL f: % update changed % rows', v_role, v_n; end if;
    delete from public.demo_notes;
    get diagnostics v_n = row_count;
    if v_n <> 0 then raise exception 'FAIL f: % delete removed % rows', v_role, v_n; end if;
    reset role;
  end loop;
  if (select pg_catalog.md5(pg_catalog.string_agg(t::text, ',' order by t.id)) from public.demo_notes t)
       is distinct from v_before then
    raise exception 'FAIL f: demo_notes changed after anon and authenticated attempts';
  end if;
  raise notice 'PASS f: no owner column -> RLS on, 0 policies; anon and authenticated read 0 of 1 rows, insert denied, update and delete affect 0 rows; table unchanged';
end;
$$;

-- g. Opt-out with maintenance.skip_rls_autogen(): every table created in public for
-- the rest of the transaction is skipped, also inside a savepoint and after rolling
-- back to a savepoint taken after the call. Called inside a savepoint that is rolled
-- back, the call is undone; inside one that is released, it stays. Cleared with
-- set local maintenance.rls_autogen = '' before going on.
do $$
begin
  perform maintenance.skip_rls_autogen();
  perform pg_catalog.set_config('verify.xact',
    pg_catalog.pg_current_xact_id()::text || ':'
      || (extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::bigint::text, true);
end;
$$;
create table public.demo_optout (id uuid primary key, user_id uuid references auth.users (id));
savepoint demo_sp1;
create table public.demo_optout_sp (id uuid primary key, user_id uuid references auth.users (id));

do $$
begin
  if pg_catalog.pg_current_xact_id()::text || ':'
       || (extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::bigint::text
       is distinct from pg_catalog.current_setting('verify.xact') then
    raise exception 'FAIL g: inside a savepoint the transaction id or start time is not that of the top-level transaction';
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_optout_sp'::regclass) is not false
     or pg_temp.policy_list('public.demo_optout_sp') <> '' then
    raise exception 'FAIL g: a table created inside a savepoint after the call got RLS or policies';
  end if;
end;
$$;

rollback to savepoint demo_sp1;
create table public.demo_optout_after_sp (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = '';
savepoint demo_sp2;
do $$ begin perform maintenance.skip_rls_autogen(); end $$;
rollback to savepoint demo_sp2;
create table public.demo_optin_sp_undone (id uuid primary key, user_id uuid references auth.users (id));
savepoint demo_sp3;
do $$ begin perform maintenance.skip_rls_autogen(); end $$;
release savepoint demo_sp3;
create table public.demo_optout_released (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = '';
create table public.demo_optin (id uuid primary key, user_id uuid references auth.users (id));

do $$
declare
  v_t regclass;
begin
  foreach v_t in array array['public.demo_optout', 'public.demo_optout_after_sp', 'public.demo_optout_released']::regclass[] loop
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not false or pg_temp.policy_list(v_t) <> '' then
      raise exception 'FAIL g: % got RLS or policies although maintenance.skip_rls_autogen() was called', v_t;
    end if;
  end loop;
  foreach v_t in array array['public.demo_optin_sp_undone', 'public.demo_optin']::regclass[] loop
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not true
       or pg_temp.policy_list(v_t) <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
      raise exception 'FAIL g: % should have RLS and 4 policies (got %)', v_t, pg_temp.policy_list(v_t);
    end if;
  end loop;
  raise notice 'PASS g: skip_rls_autogen() skips (no RLS, no policies), also inside a savepoint, after rollback to it and after release; a call rolled back with its savepoint is undone; cleared -> RLS and 4 policies';
end;
$$;

-- g1. The token counts only for a role with usage on schema maintenance and execute
-- on maintenance.skip_rls_autogen(). demo_role has neither. It sets by hand the exact
-- token the function wrote in this transaction and creates two tables: both are
-- protected (locked, since it also lacks the policy grants), and its statements
-- print WARNING 'rls_autogen: ignored maintenance.rls_autogen = ...: role demo_role
-- lacks ...'. The role running this file has the grants: the same token built by
-- hand skips its table, like a call of the function.
create role demo_role nologin;
grant demo_role to current_user;
grant usage, create on schema public to demo_role;

do $$
declare
  v_tok  text;
  v_hand text;
  v_t    regclass;
begin
  if pg_catalog.has_schema_privilege('demo_role', 'maintenance', 'USAGE')
     or pg_catalog.has_function_privilege('demo_role', 'maintenance.skip_rls_autogen()', 'EXECUTE') then
    raise exception 'FAIL g1: setup: demo_role already has usage on schema maintenance or execute on maintenance.skip_rls_autogen()';
  end if;
  perform maintenance.skip_rls_autogen();
  v_tok := pg_catalog.current_setting('maintenance.rls_autogen');
  perform pg_catalog.set_config('maintenance.rls_autogen', '', true);
  perform pg_catalog.set_config('role', 'demo_role', true);
  begin
    perform pg_catalog.set_config('maintenance.rls_autogen', v_tok, true);
    create table public.demo_forged_plain (id int);
    create table public.demo_forged_owned (id uuid primary key, user_id uuid);
  exception when others then
    raise exception 'FAIL g1: create table as demo_role with the token set by hand raised an error: %', sqlerrm;
  end;
  perform pg_catalog.set_config('maintenance.rls_autogen', '', true);
  reset role;
  foreach v_t in array array['public.demo_forged_plain', 'public.demo_forged_owned']::regclass[] loop
    if not exists (select 1 from pg_catalog.pg_class where oid = v_t and relowner = 'demo_role'::regrole) then
      raise exception 'FAIL g1: % is not owned by demo_role, so it does not test a table created by demo_role', v_t;
    end if;
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not true
       or pg_temp.policy_list(v_t) <> '' then
      raise exception 'FAIL g1: % was created by demo_role, which lacks the opt-out grants, with this transaction''s token set by hand; it should be locked, RLS on and no policies (got RLS %, policies %)',
        v_t, (select relrowsecurity from pg_catalog.pg_class where oid = v_t), pg_temp.policy_list(v_t);
    end if;
  end loop;

  v_hand := 'skip:' || pg_catalog.pg_current_xact_id()::text || ':'
            || (extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::bigint::text;
  if v_tok is distinct from v_hand then
    raise exception 'FAIL g1: maintenance.skip_rls_autogen() wrote %, expected skip:<transaction id>:<start time in microseconds> = %',
      v_tok, v_hand;
  end if;
  perform pg_catalog.set_config('maintenance.rls_autogen', v_hand, true);
  create table public.demo_forged_granted (id uuid primary key, user_id uuid references auth.users (id));
  perform pg_catalog.set_config('maintenance.rls_autogen', '', true);
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_forged_granted'::regclass) is not false
     or pg_temp.policy_list('public.demo_forged_granted') <> '' then
    raise exception 'FAIL g1: % set the token by hand with the opt-out grants, but its table got RLS or policies', current_user;
  end if;
  raise notice 'PASS g1: demo_role without the opt-out grants set this transaction''s token by hand -> its tables are locked (RLS on, 0 policies); the token is skip:<transaction id>:<start time in microseconds>, and % (with the grants) setting it by hand is skipped', current_user;
end;
$$;

-- g2. Any value other than this transaction's token is ignored: the table gets RLS
-- and its policies, and each statement raises one WARNING. A token with another
-- transaction id stands for a value left by an earlier transaction; a token with
-- this transaction id and another start time, and one without the time, are
-- ignored too, as are 'off', 'FALSE' and '0' with set local, and 'off' with a plain
-- set. The trigger must leave the value as it was.
do $$
begin
  perform pg_catalog.set_config('maintenance.rls_autogen',
    'skip:' || (pg_catalog.pg_current_xact_id()::text::bigint - 1)::text || ':'
      || (extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::bigint::text, true);
end;
$$;
create table public.demo_ignored_stale (id uuid primary key, user_id uuid references auth.users (id));
do $$
begin
  perform pg_catalog.set_config('maintenance.rls_autogen',
    'skip:' || pg_catalog.pg_current_xact_id()::text || ':'
      || ((extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::bigint - 1)::text, true);
end;
$$;
create table public.demo_ignored_wrong_time (id uuid primary key, user_id uuid references auth.users (id));
do $$
begin
  perform pg_catalog.set_config('maintenance.rls_autogen', 'skip:' || pg_catalog.pg_current_xact_id()::text, true);
end;
$$;
create table public.demo_ignored_no_time (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = 'off';
create table public.demo_ignored_off (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = 'FALSE';
create table public.demo_ignored_false (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = '0';
create table public.demo_ignored_zero (id uuid primary key, user_id uuid references auth.users (id));
set maintenance.rls_autogen = 'off';
create table public.demo_ignored_session (id uuid primary key, user_id uuid references auth.users (id));

do $$
declare
  v_t regclass;
begin
  if pg_catalog.current_setting('maintenance.rls_autogen', true) is distinct from 'off' then
    raise exception 'FAIL g2: the trigger changed maintenance.rls_autogen (now %)',
      pg_catalog.current_setting('maintenance.rls_autogen', true);
  end if;
  foreach v_t in array array['public.demo_ignored_stale', 'public.demo_ignored_wrong_time', 'public.demo_ignored_no_time',
                             'public.demo_ignored_off', 'public.demo_ignored_false',
                             'public.demo_ignored_zero', 'public.demo_ignored_session']::regclass[] loop
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not true
       or pg_temp.policy_list(v_t) <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
      raise exception 'FAIL g2: % should have RLS and 4 policies, the value was not this transaction''s token (got %)',
        v_t, pg_temp.policy_list(v_t);
    end if;
  end loop;
  raise notice 'PASS g2: a token with another transaction id, one with this id and another start time, one without the time, off / FALSE / 0 with set local and off with a plain set are ignored -> RLS and 4 policies; value left as it was';
end;
$$;

set local maintenance.rls_autogen = '';

-- g3. The token counts only when current_user holds the opt-out grants, also inside
-- a function that runs with its owner's rights, where current_user is the owner.
-- The role running this file (which, like session_user, has the grants) calls
-- maintenance.skip_rls_autogen(), then a function owned by demo_role, which has
-- neither grant. The table the function creates is owned by demo_role and is
-- protected (locked, since demo_role also lacks the policy grants), and the statement
-- prints WARNING 'rls_autogen: ignored maintenance.rls_autogen = ...: role demo_role
-- lacks ...'. The session_user side needs a second login and is not shown here.
set local role demo_role;
create function public.demo_definer_make(p_name text)
returns void
language plpgsql
security definer
set search_path = pg_catalog, pg_temp
as $$
begin
  execute pg_catalog.format('create table public.%I (id uuid primary key, user_id uuid)', p_name);
end;
$$;
revoke all on function public.demo_definer_make(text) from public;
reset role;

do $$
begin
  if pg_catalog.has_schema_privilege('demo_role', 'maintenance', 'USAGE')
     or pg_catalog.has_function_privilege('demo_role', 'maintenance.skip_rls_autogen()', 'EXECUTE') then
    raise exception 'FAIL g3: setup: demo_role already has usage on schema maintenance or execute on maintenance.skip_rls_autogen()';
  end if;
  perform maintenance.skip_rls_autogen();
  begin
    perform public.demo_definer_make('demo_definer_t');
  exception when others then
    raise exception 'FAIL g3: a function owned by demo_role creating a table after the opt-out call raised an error: %', sqlerrm;
  end;
  perform pg_catalog.set_config('maintenance.rls_autogen', '', true);
  if not exists (select 1 from pg_catalog.pg_class
                  where oid = 'public.demo_definer_t'::regclass and relowner = 'demo_role'::regrole) then
    raise exception 'FAIL g3: public.demo_definer_t is not owned by demo_role, so the function did not run with its owner''s rights';
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_definer_t'::regclass) is not true
     or pg_temp.policy_list('public.demo_definer_t') <> '' then
    raise exception 'FAIL g3: inside a function owned by demo_role (no opt-out grants) the token should be ignored; demo_definer_t should be locked, RLS on and no policies (got RLS %, policies %)',
      (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_definer_t'::regclass),
      pg_temp.policy_list('public.demo_definer_t');
  end if;
  raise notice 'PASS g3: % called maintenance.skip_rls_autogen(), then a function owned by demo_role (no opt-out grants) running with its owner''s rights -> the token is ignored and its table is locked (RLS on, 0 policies)', current_user;
end;
$$;

-- h. Edge cases.
create table public.demo_two_owners (
  id          uuid primary key default gen_random_uuid(),
  reviewer_id uuid references auth.users (id),
  user_id     uuid references auth.users (id)
);
create table public.demo_owner_pref (
  id        uuid primary key default gen_random_uuid(),
  editor_id uuid references auth.users (id),
  owner_id  uuid references auth.users (id)
);
create table public.demo_ambiguous (
  id        uuid primary key default gen_random_uuid(),
  author_id uuid references auth.users (id),
  editor_id uuid references auth.users (id)
);

do $$
begin
  if pg_temp.policy_list('public.demo_two_owners') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_two_owners'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%= user_id)') then
    raise exception 'FAIL h1: user_id was not chosen on demo_two_owners';
  end if;
  raise notice 'PASS h1: two owner candidates (user_id, reviewer_id) -> policies on user_id';

  if pg_temp.policy_list('public.demo_owner_pref') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_owner_pref'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%= owner_id)') then
    raise exception 'FAIL h2: owner_id was not chosen on demo_owner_pref';
  end if;
  raise notice 'PASS h2: two owner candidates (owner_id, editor_id) -> policies on owner_id';

  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_ambiguous'::regclass) is not true
     or pg_temp.policy_list('public.demo_ambiguous') <> '' then
    raise exception 'FAIL h3: ambiguous owner should give RLS on and no policies';
  end if;
  raise notice 'PASS h3: two owner candidates, neither preferred -> RLS on, 0 policies';
end;
$$;

-- Awkward identifiers: spaces, mixed case, a double quote, and SQL in the name.
create table public."demo_Mixed Case" (
  "Row Id"    uuid primary key default gen_random_uuid(),
  "Owner""Col" uuid not null references auth.users (id),
  "Body"      text
);
create table public."demo_x""); drop table public.demo_posts; --" (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id)
);
grant select, insert, update, delete on public."demo_Mixed Case" to authenticated;

do $$
declare
  v_a uuid := current_setting('verify.user_a')::uuid;
  v_b uuid := current_setting('verify.user_b')::uuid;
  v_n bigint;
begin
  if pg_temp.policy_list('public."demo_Mixed Case"') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public."demo_Mixed Case"'::regclass) is not true then
    raise exception 'FAIL h4: "demo_Mixed Case" not secured';
  end if;
  if pg_temp.policy_list('public."demo_x""); drop table public.demo_posts; --"') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or pg_catalog.to_regclass('public.demo_posts') is null then
    raise exception 'FAIL h4: table name with SQL in it was not handled safely';
  end if;

  perform pg_temp.act_as('authenticated', v_a::text);
  insert into public."demo_Mixed Case" ("Owner""Col", "Body") values (v_a, 'mine');
  select count(*) into v_n from public."demo_Mixed Case";
  if v_n <> 1 then raise exception 'FAIL h4: owner sees % rows in "demo_Mixed Case"', v_n; end if;
  begin
    insert into public."demo_Mixed Case" ("Owner""Col", "Body") values (v_b, 'theirs');
    raise exception 'FAIL h4: insert for another user succeeded on "demo_Mixed Case"';
  exception when insufficient_privilege then null;
  end;
  perform pg_temp.act_as('authenticated', v_b::text);
  select count(*) into v_n from public."demo_Mixed Case";
  if v_n <> 0 then raise exception 'FAIL h4: other user sees % rows in "demo_Mixed Case"', v_n; end if;
  reset role;
  raise notice 'PASS h4: quoted mixed-case names and a name containing SQL work; owner policies enforce on "Owner""Col"';
end;
$$;

-- Re-running apply_owner_policies is a no-op.
do $$
declare
  v_before oid[];
  v_after  oid[];
begin
  select pg_catalog.array_agg(oid order by oid) into v_before from pg_catalog.pg_policy where polrelid = 'public.demo_posts'::regclass;
  perform maintenance.apply_owner_policies('public.demo_posts');
  perform maintenance.apply_owner_policies('public.demo_posts');
  select pg_catalog.array_agg(oid order by oid) into v_after from pg_catalog.pg_policy where polrelid = 'public.demo_posts'::regclass;
  if pg_catalog.cardinality(v_before) is distinct from 4 then
    raise exception 'FAIL h5: setup: public.demo_posts has % policies, expected 4', coalesce(pg_catalog.cardinality(v_before), 0);
  end if;
  if v_after is distinct from v_before then
    raise exception 'FAIL h5: re-run changed policies';
  end if;
  raise notice 'PASS h5: re-running apply_owner_policies keeps the same 4 policies';
end;
$$;

-- A policy someone already wrote under one of the fixed names is kept. Also covers the
-- manual call for a table the trigger did not handle.
do $$ begin perform maintenance.skip_rls_autogen(); end $$;
create table public.demo_custom (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id)
);
set local maintenance.rls_autogen = '';
create policy owner_select on public.demo_custom for select to authenticated using (false);

do $$
declare
  v_oid  oid;
  v_qual text;
begin
  select oid, pg_catalog.pg_get_expr(polqual, polrelid) into v_oid, v_qual
    from pg_catalog.pg_policy where polrelid = 'public.demo_custom'::regclass and polname = 'owner_select';
  perform maintenance.apply_owner_policies('public.demo_custom');
  if not exists (select 1 from pg_catalog.pg_policy
                  where polrelid = 'public.demo_custom'::regclass and polname = 'owner_select'
                    and oid = v_oid and pg_catalog.pg_get_expr(polqual, polrelid) = v_qual) then
    raise exception 'FAIL h6: existing owner_select policy was replaced';
  end if;
  if pg_temp.policy_list('public.demo_custom') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_custom'::regclass) is not true then
    raise exception 'FAIL h6: manual call did not secure demo_custom';
  end if;
  raise notice 'PASS h6: existing owner_select (using %) kept; manual call added the other 3 and RLS', v_qual;
end;
$$;

-- CREATE TABLE AS and SELECT INTO.
create table public.demo_ctas as select gen_random_uuid() as id, 'x'::text as body;
select 1 as n into public.demo_select_into;

do $$
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_ctas'::regclass) is not true then
    raise exception 'FAIL h7: CREATE TABLE AS table has no RLS';
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_select_into'::regclass) is not true then
    raise exception 'FAIL h7: SELECT INTO table has no RLS';
  end if;
  raise notice 'PASS h7: CREATE TABLE AS and SELECT INTO tables get RLS';
end;
$$;

-- Partitioned table and a partition.
create table public.demo_parted (
  id      uuid not null default gen_random_uuid(),
  user_id uuid not null references auth.users (id),
  created date not null,
  primary key (id, created)
) partition by range (created);
create table public.demo_parted_2026 partition of public.demo_parted
  for values from ('2026-01-01') to ('2027-01-01');
grant select, insert, update, delete on public.demo_parted, public.demo_parted_2026 to authenticated;

do $$
declare
  v_a uuid := current_setting('verify.user_a')::uuid;
  v_b uuid := current_setting('verify.user_b')::uuid;
  v_n bigint;
begin
  if (select relkind from pg_catalog.pg_class where oid = 'public.demo_parted'::regclass) is distinct from 'p'
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted'::regclass) is not true
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted_2026'::regclass) is not true then
    raise exception 'FAIL h8: partitioned table or partition has no RLS';
  end if;
  if pg_temp.policy_list('public.demo_parted') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or pg_temp.policy_list('public.demo_parted_2026') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL h8: partitioned table or partition is missing policies';
  end if;

  perform pg_temp.act_as('authenticated', v_a::text);
  insert into public.demo_parted (user_id, created) values (v_a, '2026-06-01');
  select count(*) into v_n from public.demo_parted_2026;
  if v_n <> 1 then raise exception 'FAIL h8: owner sees % rows in the partition', v_n; end if;
  perform pg_temp.act_as('authenticated', v_b::text);
  select count(*) into v_n from public.demo_parted;
  if v_n <> 0 then raise exception 'FAIL h8: other user sees % rows through the parent', v_n; end if;
  select count(*) into v_n from public.demo_parted_2026;
  if v_n <> 0 then raise exception 'FAIL h8: other user sees % rows in the partition', v_n; end if;
  reset role;
  raise notice 'PASS h8: partitioned table (relkind p) and its partition both get RLS and 4 policies; enforced both ways';
end;
$$;

-- Tables outside the watched schemas are not touched.
create schema demo_other_schema;
create table demo_other_schema.demo_t (id uuid primary key, user_id uuid references auth.users (id));
create temporary table demo_temp (id uuid primary key);

do $$
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'demo_other_schema.demo_t'::regclass) is not false
     or pg_temp.policy_list('demo_other_schema.demo_t') <> '' then
    raise exception 'FAIL h9: table outside public was changed';
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'pg_temp.demo_temp'::regclass) is not false then
    raise exception 'FAIL h9: temporary table was changed';
  end if;
  raise notice 'PASS h9: tables in other schemas and temporary tables are left alone';
end;
$$;

-- Tables an extension script creates in public get RLS and no policies. Takes the
-- first of these extensions that is available and not installed yet (both create a
-- table in the schema they are installed into), creates it in public and checks
-- every table it put there. An error raised by the trigger during create extension
-- is a FAIL; any other error (a missing dependency, for example) marks that
-- extension unusable and the next one is tried. Rolled back with the rest.
-- Each table is judged by what happened to it, not by who the caller is. A probe
-- table first shows the trigger fires for current_user (check 0 and the checks
-- above already depend on that). Who ran the script is read from the table owner,
-- since create extension makes the role running the script the owner of what it
-- creates.
--   RLS on, no policies           -> tested, passes, whoever owns it.
--   any policy                    -> FAIL.
--   RLS off, owned by current_user -> FAIL: the trigger fires for that role (a
--                                     platform that reassigns ownership of
--                                     extension tables after creating them gives
--                                     this result too).
--   RLS off, owned by another role -> not a test: the script ran as that role and
--                                     the trigger did not fire for it (some managed
--                                     platforms skip event triggers for superuser
--                                     or reserved roles).
-- The next extension is tried when the first tested no table. When none tested a
-- table, prints SKIP h10 with the reason and the final line reports the skip.
do $$
declare
  v_ext    text;
  v_t      regclass;
  v_owner  oid;
  v_rls    boolean;
  v_me     oid := (select oid from pg_catalog.pg_roles where rolname = current_user);
  v_tested text[] := '{}';
  v_other  text[] := '{}';
  v_msg    text;
  v_ctx    text;
begin
  create table public.demo_h10_probe (id int);
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_h10_probe'::regclass) is not true then
    raise exception 'FAIL h10: the trigger did not fire for a probe table created by %', current_user;
  end if;
  drop table public.demo_h10_probe;

  foreach v_ext in array array['pg_partman', 'postgis'] loop
    continue when not exists (select 1 from pg_catalog.pg_available_extensions
                               where name = v_ext and installed_version is null);
    begin
      execute pg_catalog.format('create extension %I schema public', v_ext);
    exception when others then
      get stacked diagnostics v_msg = message_text, v_ctx = pg_exception_context;
      if coalesce(v_msg, '') like 'rls_autogen:%' or coalesce(v_ctx, '') like '%function maintenance.%' then
        raise exception 'FAIL h10: the trigger raised an error during create extension %: %', v_ext, v_msg;
      end if;
      v_other := v_other || pg_catalog.format('%s could not be created (%s), so it was not used', v_ext, v_msg);
      continue;
    end;
    for v_t, v_owner, v_rls in
      select c.oid::regclass, c.relowner, c.relrowsecurity
        from pg_catalog.pg_depend d
        join pg_catalog.pg_class c on c.oid = d.objid
        join pg_catalog.pg_extension e on e.oid = d.refobjid
       where d.classid = 'pg_catalog.pg_class'::regclass
         and d.refclassid = 'pg_catalog.pg_extension'::regclass
         and d.deptype = 'e'
         and e.extname = v_ext
         and c.relnamespace = 'public'::regnamespace
         and c.relkind in ('r', 'p')
       order by c.oid
    loop
      if pg_temp.policy_list(v_t) <> '' then
        raise exception 'FAIL h10: % (created by extension %) got policies: %', v_t, v_ext, pg_temp.policy_list(v_t);
      elsif v_rls then
        v_tested := v_tested || pg_catalog.format('%s (%s, created as %s)', v_t, v_ext, v_owner::regrole);
      elsif v_owner = v_me then
        raise exception 'FAIL h10: % (created by extension %, owned by %, for whom the trigger fires) has no RLS. A platform that reassigns ownership of extension tables after creating them gives this result too.',
          v_t, v_ext, v_owner::regrole;
      else
        v_other := v_other || pg_catalog.format('%s (%s) was created as role %s, for whom the trigger did not fire',
          v_t, v_ext, v_owner::regrole);
      end if;
    end loop;
    exit when pg_catalog.cardinality(v_tested) > 0;
  end loop;
  if pg_catalog.cardinality(v_tested) = 0 then
    perform pg_catalog.set_config('verify.skipped',
      pg_catalog.concat_ws(',', nullif(pg_catalog.current_setting('verify.skipped', true), ''), 'h10'), true);
    if pg_catalog.cardinality(v_other) > 0 then
      raise notice 'SKIP h10: no candidate tested a table: %; extension tables not tested',
        pg_catalog.array_to_string(v_other, '; ');
    else
      raise notice 'SKIP h10: none of pg_partman, postgis is available and not installed yet; extension tables not tested';
    end if;
  else
    raise notice 'PASS h10: tables created by create extension get RLS and 0 policies: %',
      pg_catalog.array_to_string(v_tested, ', ')
      || case when pg_catalog.cardinality(v_other) > 0
              then '; not tested: ' || pg_catalog.array_to_string(v_other, '; ') else '' end;
  end if;
end;
$$;

-- h11 documents a limit, not a feature. ALTER TABLE ... SET SCHEMA public and
-- ALTER TABLE ... ATTACH PARTITION have the command tag ALTER TABLE, which the
-- trigger does not listen to, so the moved-in table and the attached partition
-- keep RLS off. The manual call then secures them. (A partition created with
-- CREATE TABLE ... PARTITION OF is covered; see h8.)
create schema demo_staging;
create table demo_staging.demo_moved (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id)
);
alter table demo_staging.demo_moved set schema public;
do $$ begin perform maintenance.skip_rls_autogen(); end $$;
create table public.demo_parted_2027 (like public.demo_parted including defaults);
set local maintenance.rls_autogen = '';
alter table public.demo_parted attach partition public.demo_parted_2027
  for values from ('2027-01-01') to ('2028-01-01');
grant select, insert, update, delete on public.demo_moved, public.demo_parted_2027 to authenticated;

do $$
declare
  v_a uuid := current_setting('verify.user_a')::uuid;
  v_b uuid := current_setting('verify.user_b')::uuid;
  v_n bigint;
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_moved'::regclass) is not false
     or pg_temp.policy_list('public.demo_moved') <> '' then
    raise exception 'FAIL h11: table moved into public with set schema was changed; update the documented limit';
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted_2027'::regclass) is not false
     or pg_temp.policy_list('public.demo_parted_2027') <> '' then
    raise exception 'FAIL h11: partition attached with attach partition was changed; update the documented limit';
  end if;

  -- A query on the attached partition itself does not apply the parent's policies.
  insert into public.demo_parted (user_id, created) values (v_a, '2027-06-01');
  perform pg_temp.act_as('authenticated', v_b::text);
  select count(*) into v_n from public.demo_parted where created >= '2027-01-01';
  if v_n <> 0 then raise exception 'FAIL h11: other user sees % rows through the parent', v_n; end if;
  select count(*) into v_n from public.demo_parted_2027;
  if v_n <> 1 then raise exception 'FAIL h11: other user sees % rows in the attached partition, expected 1 (RLS off)', v_n; end if;
  reset role;

  perform maintenance.apply_owner_policies('public.demo_moved');
  perform maintenance.apply_owner_policies('public.demo_parted_2027');
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_moved'::regclass) is not true
     or pg_temp.policy_list('public.demo_moved') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted_2027'::regclass) is not true
     or pg_temp.policy_list('public.demo_parted_2027') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL h11: manual call did not secure the moved-in table or the attached partition';
  end if;
  perform pg_temp.act_as('authenticated', v_b::text);
  select count(*) into v_n from public.demo_parted_2027;
  if v_n <> 0 then raise exception 'FAIL h11: other user sees % rows in the attached partition after the manual call', v_n; end if;
  reset role;
  raise notice 'PASS h11: documented limit: set schema public and attach partition leave RLS off (other user read the attached partition directly); manual call adds RLS and 4 policies';
end;
$$;

-- h12. Replica mode. Data-load and restore scripts often set session_replication_role
-- = replica; an event trigger in the default mode does not fire then. rls_autogen is
-- enabled always (check 0), so a table created in replica mode still gets RLS and
-- its policies. Prints SKIP h12 when this role may not set session_replication_role.
do $$
declare
  v_prev text := pg_catalog.current_setting('session_replication_role');
begin
  begin
    perform pg_catalog.set_config('session_replication_role', 'replica', true);
  exception when insufficient_privilege then
    perform pg_catalog.set_config('verify.skipped',
      pg_catalog.concat_ws(',', nullif(pg_catalog.current_setting('verify.skipped', true), ''), 'h12'), true);
    raise notice 'SKIP h12: % may not set session_replication_role (%), so a table created in replica mode was not tested; check 0 still checked that the trigger is enabled always',
      current_user, sqlerrm;
    return;
  end;
  create table public.demo_replica (id uuid primary key, user_id uuid references auth.users (id));
  perform pg_catalog.set_config('session_replication_role', v_prev, true);
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_replica'::regclass) is not true
     or pg_temp.policy_list('public.demo_replica') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL h12: a table created with session_replication_role = replica should have RLS and 4 policies (got RLS %, policies %)',
      (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_replica'::regclass),
      pg_temp.policy_list('public.demo_replica');
  end if;
  raise notice 'PASS h12: a table created with session_replication_role = replica gets RLS and 4 policies';
end;
$$;

-- i. Name fallback, used only when no uuid foreign key to auth.users exists.
create table public.demo_name_user (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  body    text
);
create table public.demo_name_owner (
  id       uuid primary key default gen_random_uuid(),
  owner_id uuid
);
create table public.demo_name_both (
  id       uuid primary key default gen_random_uuid(),
  owner_id uuid,
  user_id  uuid
);
create table public.demo_name_text (
  id      uuid primary key default gen_random_uuid(),
  user_id text
);
create table public.demo_name_bigint (
  id       uuid primary key default gen_random_uuid(),
  user_id  bigint,
  owner_id integer
);
create table public.demo_fk_wins (
  id        uuid primary key default gen_random_uuid(),
  author_id uuid references auth.users (id),
  user_id   uuid
);
grant select, insert, update, delete on public.demo_name_user to anon, authenticated;
insert into public.demo_name_user (user_id, body) values
  (current_setting('verify.user_a')::uuid, 'a-seed'),
  (current_setting('verify.user_b')::uuid, 'b-seed');

do $$
declare
  v_a  uuid := current_setting('verify.user_a')::uuid;
  v_b  uuid := current_setting('verify.user_b')::uuid;
  v_id uuid;
  v_n  bigint;
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_user'::regclass) is not true
     or pg_temp.policy_list('public.demo_name_user') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_name_user'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%auth.uid()%= user_id)') then
    raise exception 'FAIL i1: uuid user_id without a foreign key did not get RLS and 4 policies on user_id';
  end if;

  perform pg_temp.act_as('anon');
  select count(*) into v_n from public.demo_name_user;
  if v_n <> 0 then raise exception 'FAIL i1: anon can read % rows', v_n; end if;
  begin
    insert into public.demo_name_user (user_id, body) values (v_a, 'anon');
    raise exception 'FAIL i1: anon insert succeeded';
  exception when insufficient_privilege then null;
  end;

  perform pg_temp.act_as('authenticated', v_a::text);
  insert into public.demo_name_user (user_id, body) values (v_a, 'a-new') returning id into v_id;
  select count(*) into v_n from public.demo_name_user;
  if v_n <> 2 then raise exception 'FAIL i1: owner sees % rows, expected own 2', v_n; end if;
  begin
    insert into public.demo_name_user (user_id, body) values (v_b, 'a-as-b');
    raise exception 'FAIL i1: owner inserted a row for another user';
  exception when insufficient_privilege then null;
  end;
  update public.demo_name_user set body = 'a-edited' where id = v_id;
  get diagnostics v_n = row_count;
  if v_n <> 1 then raise exception 'FAIL i1: owner update affected % rows', v_n; end if;

  perform pg_temp.act_as('authenticated', v_b::text);
  select count(*) into v_n from public.demo_name_user where user_id = v_a;
  if v_n <> 0 then raise exception 'FAIL i1: user B can see % of user A''s rows', v_n; end if;
  delete from public.demo_name_user where user_id = v_a;
  get diagnostics v_n = row_count;
  if v_n <> 0 then raise exception 'FAIL i1: user B deleted % of user A''s rows', v_n; end if;
  reset role;
  raise notice 'PASS i1: uuid user_id without a foreign key -> RLS and 4 policies on user_id; anon denied, owner only, other user denied';

  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_owner'::regclass) is not true
     or pg_temp.policy_list('public.demo_name_owner') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_name_owner'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%auth.uid()%= owner_id)') then
    raise exception 'FAIL i2: uuid owner_id without a foreign key did not get 4 policies on owner_id';
  end if;
  if pg_temp.policy_list('public.demo_name_both') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_name_both'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%= user_id)') then
    raise exception 'FAIL i2: with both names and no foreign key, user_id was not chosen';
  end if;
  raise notice 'PASS i2: uuid owner_id without a foreign key -> 4 policies on owner_id; user_id preferred when both exist';

  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_text'::regclass) is not true
     or pg_temp.policy_list('public.demo_name_text') <> ''
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_bigint'::regclass) is not true
     or pg_temp.policy_list('public.demo_name_bigint') <> '' then
    raise exception 'FAIL i3: user_id that is not uuid should give RLS on and no policies';
  end if;
  raise notice 'PASS i3: user_id of type text or bigint (owner_id integer) -> RLS on, 0 policies';

  if pg_temp.policy_list('public.demo_fk_wins') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_fk_wins'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%= author_id)') then
    raise exception 'FAIL i4: foreign key column author_id did not win over plain user_id';
  end if;
  raise notice 'PASS i4: foreign key column (author_id) and plain uuid user_id -> policies on author_id';
end;
$$;

-- i5. A user_id with a foreign key to another table is not the owner, even when
-- owner_id is a plain uuid next to it.
create table public.demo_members (id uuid primary key default gen_random_uuid());
create table public.demo_fk_other (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid references public.demo_members (id)
);
create table public.demo_fk_other_both (
  id       uuid primary key default gen_random_uuid(),
  user_id  uuid references public.demo_members (id),
  owner_id uuid
);

do $$
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_fk_other'::regclass) is not true
     or pg_temp.policy_list('public.demo_fk_other') <> ''
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_fk_other_both'::regclass) is not true
     or pg_temp.policy_list('public.demo_fk_other_both') <> '' then
    raise exception 'FAIL i5: user_id with a foreign key to another table should give RLS on and no policies (got % / %)',
      pg_temp.policy_list('public.demo_fk_other'), pg_temp.policy_list('public.demo_fk_other_both');
  end if;
  raise notice 'PASS i5: uuid user_id with a foreign key to public.demo_members -> RLS on, 0 policies (also with a plain owner_id beside it)';
end;
$$;

-- i6. Domain over uuid (two levels deep) with a foreign key to auth.users is the owner.
create domain public.demo_uid as uuid;
create domain public.demo_uid_deep as public.demo_uid;
create table public.demo_domain_fk (
  id        uuid primary key default gen_random_uuid(),
  author_id public.demo_uid_deep references auth.users (id)
);
grant select, insert, update, delete on public.demo_domain_fk to authenticated;

do $$
declare
  v_a uuid := current_setting('verify.user_a')::uuid;
  v_b uuid := current_setting('verify.user_b')::uuid;
  v_n bigint;
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_domain_fk'::regclass) is not true
     or pg_temp.policy_list('public.demo_domain_fk') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_domain_fk'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%auth.uid()%= (author_id)::uuid)') then
    raise exception 'FAIL i6: domain over uuid with a foreign key to auth.users did not get 4 policies on author_id (got %)',
      pg_temp.policy_list('public.demo_domain_fk');
  end if;

  perform pg_temp.act_as('authenticated', v_a::text);
  insert into public.demo_domain_fk (author_id) values (v_a);
  select count(*) into v_n from public.demo_domain_fk;
  if v_n <> 1 then raise exception 'FAIL i6: owner sees % rows, expected 1', v_n; end if;
  begin
    insert into public.demo_domain_fk (author_id) values (v_b);
    raise exception 'FAIL i6: owner inserted a row for another user';
  exception when insufficient_privilege then null;
  end;
  perform pg_temp.act_as('authenticated', v_b::text);
  select count(*) into v_n from public.demo_domain_fk;
  if v_n <> 0 then raise exception 'FAIL i6: other user sees % rows', v_n; end if;
  reset role;
  raise notice 'PASS i6: domain over a domain over uuid, foreign key to auth.users -> RLS and 4 policies on author_id; owner only, other user denied';
end;
$$;

-- i7. Domain over uuid named user_id, no foreign key: name fallback applies.
create table public.demo_domain_name (
  id      uuid primary key default gen_random_uuid(),
  user_id public.demo_uid
);

do $$
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_domain_name'::regclass) is not true
     or pg_temp.policy_list('public.demo_domain_name') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_domain_name'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), '')
                       not like '%auth.uid()%= (user_id)::uuid)') then
    raise exception 'FAIL i7: domain over uuid named user_id without a foreign key did not get 4 policies on user_id (got %)',
      pg_temp.policy_list('public.demo_domain_name');
  end if;
  raise notice 'PASS i7: domain over uuid named user_id without a foreign key -> RLS and 4 policies on user_id';
end;
$$;

-- j. A role other than postgres that creates and owns tables in public, with no
-- usage on schema auth (demo_role, created for check g1). Check j0 runs before it
-- has the two maintenance grants the README documents for it, j1 and j2 after.

-- j0. Without the maintenance grants its create table does not fail and the table
-- is locked: RLS on and no policies, with and without an owner column. Each table
-- prints WARNING 'rls_autogen: ... is locked (RLS on, no policies): owner policies
-- were not added because role demo_role lacks ...'. j2 adds the policies with the
-- manual call once the grants are in place.
do $$
declare
  v_t regclass;
begin
  if pg_catalog.has_schema_privilege('demo_role', 'maintenance', 'USAGE') then
    raise exception 'FAIL j0: setup: demo_role already has usage on schema maintenance, so a role without it cannot be tested';
  end if;
  perform pg_catalog.set_config('role', 'demo_role', true);
  begin
    create table public.demo_role_nogrant_plain (id int);
    create table public.demo_role_nogrant_owned (id uuid primary key, user_id uuid);
  exception when others then
    raise exception 'FAIL j0: create table as demo_role without the maintenance grants raised an error: %', sqlerrm;
  end;
  reset role;
  foreach v_t in array array['public.demo_role_nogrant_plain', 'public.demo_role_nogrant_owned']::regclass[] loop
    if not exists (select 1 from pg_catalog.pg_class where oid = v_t and relowner = 'demo_role'::regrole) then
      raise exception 'FAIL j0: % is not owned by demo_role, so it does not test a table created by demo_role', v_t;
    end if;
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not true
       or pg_temp.policy_list(v_t) <> '' then
      raise exception 'FAIL j0: % (created by demo_role without the maintenance grants) should have RLS on and no policies (got %)',
        v_t, pg_temp.policy_list(v_t);
    end if;
  end loop;
  raise notice 'PASS j0: demo_role without the maintenance grants creates tables without error; with and without an owner column -> RLS on, 0 policies';
end;
$$;

grant usage on schema maintenance to demo_role;
grant execute on function maintenance.apply_owner_policies(regclass) to demo_role;

-- j1. Its create table never fails because auth is out of reach, and never leaves the
-- table open: RLS on and no policies, with or without an owner column.
do $$
declare
  v_t regclass;
begin
  if pg_catalog.has_schema_privilege('demo_role', 'auth', 'USAGE') then
    raise exception 'FAIL j1: setup: demo_role already has usage on schema auth, so a role without it cannot be tested';
  end if;
  perform pg_catalog.set_config('role', 'demo_role', true);
  begin
    create table public.demo_role_plain (id int);
    create table public.demo_role_owned (id uuid primary key, user_id uuid);
  exception when others then
    raise exception 'FAIL j1: create table as demo_role (no usage on schema auth) raised an error: %', sqlerrm;
  end;
  reset role;
  foreach v_t in array array['public.demo_role_plain', 'public.demo_role_owned']::regclass[] loop
    if not exists (select 1 from pg_catalog.pg_class where oid = v_t and relowner = 'demo_role'::regrole) then
      raise exception 'FAIL j1: % is not owned by demo_role, so it does not test a table created by demo_role', v_t;
    end if;
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not true
       or pg_temp.policy_list(v_t) <> '' then
      raise exception 'FAIL j1: % (created by demo_role) should have RLS on and no policies (got %)', v_t, pg_temp.policy_list(v_t);
    end if;
  end loop;
  raise notice 'PASS j1: demo_role without usage on schema auth creates tables without error; with and without an owner column -> RLS on, 0 policies';
end;
$$;

-- j2. The manual call by that owner works with the two grants. Without usage on
-- schema auth it enables RLS and adds no policies; with it, the four policies.
-- With execute on maintenance.skip_rls_autogen(), demo_role's own call skips its
-- table; once that grant is revoked, the same token set by hand is ignored and its
-- next table gets RLS and the four policies.
grant execute on function maintenance.skip_rls_autogen() to demo_role;
set local role demo_role;
do $$ begin perform maintenance.skip_rls_autogen(); end $$;
create table public.demo_role_manual (id uuid primary key, user_id uuid);
set local maintenance.rls_autogen = '';
reset role;

do $$
declare
  v_t regclass := 'public.demo_role_manual';
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not false then
    raise exception 'FAIL j2: setup: % has RLS although demo_role, with execute on maintenance.skip_rls_autogen(), called it', v_t;
  end if;
  perform pg_catalog.set_config('role', 'demo_role', true);
  perform maintenance.apply_owner_policies(v_t);
  reset role;
  if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) is not true or pg_temp.policy_list(v_t) <> '' then
    raise exception 'FAIL j2: manual call by demo_role without usage on schema auth should give RLS on and no policies (got %)',
      pg_temp.policy_list(v_t);
  end if;

  -- Usage on schema auth through membership in authenticated, which has it on Supabase.
  begin
    grant authenticated to demo_role;
  exception when insufficient_privilege then null;
  end;
  if not pg_catalog.has_schema_privilege('demo_role', 'auth', 'USAGE') then
    perform pg_catalog.set_config('verify.skipped',
      pg_catalog.concat_ws(',', nullif(pg_catalog.current_setting('verify.skipped', true), ''), 'j2'), true);
    raise notice 'SKIP j2: manual call by demo_role with the two grants -> RLS on, 0 policies; % cannot give demo_role usage on schema auth (grant authenticated to demo_role), so the call with policies was not tested (also not on the tables j0 locked), nor the ignored token set by hand without execute on skip_rls_autogen()', current_user;
    return;
  end if;
  perform pg_catalog.set_config('role', 'demo_role', true);
  perform maintenance.apply_owner_policies(v_t);
  reset role;
  if pg_temp.policy_list(v_t) <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL j2: manual call by demo_role with usage on schema auth did not add 4 policies (got %)', pg_temp.policy_list(v_t);
  end if;

  -- The fix the j0 warning gives: with the grants, the manual call on the locked tables.
  perform pg_catalog.set_config('role', 'demo_role', true);
  perform maintenance.apply_owner_policies('public.demo_role_nogrant_owned');
  perform maintenance.apply_owner_policies('public.demo_role_nogrant_plain');
  reset role;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_role_nogrant_owned'::regclass) is not true
     or pg_temp.policy_list('public.demo_role_nogrant_owned') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL j2: manual call by demo_role on demo_role_nogrant_owned (locked in j0) did not add 4 policies (got %)',
      pg_temp.policy_list('public.demo_role_nogrant_owned');
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_role_nogrant_plain'::regclass) is not true
     or pg_temp.policy_list('public.demo_role_nogrant_plain') <> '' then
    raise exception 'FAIL j2: demo_role_nogrant_plain (no owner column) should keep RLS on and no policies (got %)',
      pg_temp.policy_list('public.demo_role_nogrant_plain');
  end if;

  -- Without execute on skip_rls_autogen() (usage on schema maintenance kept), the
  -- token demo_role builds by hand is ignored.
  revoke execute on function maintenance.skip_rls_autogen() from demo_role;
  perform pg_catalog.set_config('role', 'demo_role', true);
  perform pg_catalog.set_config('maintenance.rls_autogen',
    'skip:' || pg_catalog.pg_current_xact_id()::text || ':'
      || (extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::bigint::text, true);
  create table public.demo_role_forged (id uuid primary key, user_id uuid);
  perform pg_catalog.set_config('maintenance.rls_autogen', '', true);
  reset role;
  if not exists (select 1 from pg_catalog.pg_class where oid = 'public.demo_role_forged'::regclass and relowner = 'demo_role'::regrole)
     or (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_role_forged'::regclass) is not true
     or pg_temp.policy_list('public.demo_role_forged') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL j2: demo_role without execute on maintenance.skip_rls_autogen() set the token by hand; demo_role_forged should have RLS and 4 policies (got %)',
      pg_temp.policy_list('public.demo_role_forged');
  end if;
  raise notice 'PASS j2: demo_role with execute on skip_rls_autogen() skips its table; manual call by demo_role (owner, not postgres) with the two grants -> RLS on, 0 policies without usage on schema auth; 4 policies with it, also on the table j0 locked; without execute on skip_rls_autogen() its token set by hand is ignored -> RLS and 4 policies';
end;
$$;

do $$
declare
  v_skipped text[] := pg_catalog.string_to_array(
                        nullif(pg_catalog.current_setting('verify.skipped', true), ''), ',');
begin
  if coalesce(pg_catalog.cardinality(v_skipped), 0) > 0 then
    raise notice 'ALL CHECKS PASSED (% skipped: %)',
      pg_catalog.cardinality(v_skipped), pg_catalog.array_to_string(v_skipped, ', ');
  else
    raise notice 'ALL CHECKS PASSED';
  end if;
end;
$$;

rollback;
