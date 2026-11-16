-- rls_autogen self-check.
--
-- Run as postgres after applying migrations/20261114000000_rls_autogen.sql:
--   psql "$DATABASE_URL" -f test/verify.sql
-- or paste the whole file into the SQL editor.
-- Run it as a role the event trigger fires for. Some managed platforms skip event
-- triggers for superuser or reserved roles; check 0 stops with FAIL 0 and says so
-- when the trigger did not fire for the role running this file.
--
-- Everything runs in one transaction that ends in ROLLBACK, so nothing is left behind.
-- It creates tables and domains named public.demo_* and two throwaway rows in auth.users with random ids.
-- Any trigger you have on auth.users runs for those two rows (and is rolled back with them).
--
-- Each check raises NOTICE 'PASS: ...' or stops with ERROR 'FAIL: ...'. Check h10
-- (extension tables) raises NOTICE 'SKIP h10: ...' instead when neither pg_partman
-- nor postgis is available and not installed yet, or when each one it creates ran
-- its script as another role for whom the trigger did not fire (not a test of
-- the trigger).
-- The last line of a good run is NOTICE 'ALL CHECKS PASSED'. If a check was
-- skipped it reads NOTICE 'ALL CHECKS PASSED (1 skipped: h10)', which is not a
-- full pass: the skipped check was not tested.
-- Checks g, g2, h6 and h11 switch the trigger off on purpose, so each table they skip
-- prints WARNING 'rls_autogen: RLS was NOT enabled on ...'. That is expected.

begin;

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

-- 0. Setup: the trigger is installed, fires for the role running this file, and
-- the role simulation works. Every later check needs the trigger to fire for
-- current_user, so a probe table shows that first and names the cause if not.
do $$
declare
  v_uid uuid;
  v_rls boolean;
begin
  if not exists (select 1 from pg_catalog.pg_event_trigger
                  where evtname = 'rls_autogen' and evtenabled <> 'D') then
    raise exception 'FAIL 0: event trigger rls_autogen is missing or disabled';
  end if;
  begin
    create table public.demo_probe_0 (id int);
  exception when insufficient_privilege then
    raise exception 'FAIL 0: the trigger could not secure a table created by %: %', current_user, sqlerrm;
  end;
  select relrowsecurity into v_rls from pg_catalog.pg_class where oid = 'public.demo_probe_0'::regclass;
  drop table public.demo_probe_0;
  if not v_rls then
    raise exception 'FAIL 0: the trigger did not fire for a table created by role % (superuser: %, maintenance.rls_autogen: %). Some managed platforms skip event triggers for superuser or reserved roles; run this file as a role the trigger fires for, such as the role that creates your tables.',
      current_user,
      (select rolsuper from pg_catalog.pg_roles where rolname = current_user),
      coalesce(pg_catalog.current_setting('maintenance.rls_autogen', true), '(not set)');
  end if;
  perform pg_temp.act_as('authenticated', pg_catalog.current_setting('verify.user_a'));
  select auth.uid() into v_uid;
  if v_uid is distinct from pg_catalog.current_setting('verify.user_a')::uuid
     or current_user <> 'authenticated' then
    raise exception 'FAIL 0: role simulation broken (current_user %, auth.uid() %)', current_user, v_uid;
  end if;
  reset role;
  raise notice 'PASS 0: event trigger installed and fires for %; auth.uid() returns the simulated user', current_user;
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
     and not (p.polpermissive
              and p.polroles = array['authenticated'::regrole::oid]
              and case p.polcmd
                    when 'r' then p.polwithcheck is null and pg_catalog.pg_get_expr(p.polqual, p.polrelid) like '%auth.uid()%= user_id)'
                    when 'd' then p.polwithcheck is null and pg_catalog.pg_get_expr(p.polqual, p.polrelid) like '%auth.uid()%= user_id)'
                    when 'a' then p.polqual is null and pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) like '%auth.uid()%= user_id)'
                    when 'w' then pg_catalog.pg_get_expr(p.polqual, p.polrelid) like '%auth.uid()%= user_id)'
                              and pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid) like '%auth.uid()%= user_id)'
                  end);
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

-- d. The owner (user A) can insert, read, update and delete their own row, and not insert for user B.
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
  v_role text;
  v_n    bigint;
begin
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_notes'::regclass) then
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
    reset role;
  end loop;
  raise notice 'PASS f: no owner column -> RLS on, 0 policies; anon and authenticated read 0 of 1 rows, insert denied';
end;
$$;

-- g. Opt-out with a transaction-local setting, then back on.
set local maintenance.rls_autogen = 'off';
create table public.demo_optout (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = 'FALSE';
create table public.demo_optout_false (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = '0';
create table public.demo_optout_zero (id uuid primary key, user_id uuid references auth.users (id));
set local maintenance.rls_autogen = 'on';
create table public.demo_optin (id uuid primary key, user_id uuid references auth.users (id));

do $$
declare
  v_t regclass;
begin
  foreach v_t in array array['public.demo_optout', 'public.demo_optout_false', 'public.demo_optout_zero']::regclass[] loop
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) then
      raise exception 'FAIL g: % has RLS although the trigger was switched off', v_t;
    end if;
    if pg_temp.policy_list(v_t) <> '' then
      raise exception 'FAIL g: % has policies although the trigger was switched off', v_t;
    end if;
  end loop;
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_optin'::regclass)
     or pg_temp.policy_list('public.demo_optin') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL g: trigger did not resume after setting it back on';
  end if;
  raise notice 'PASS g: off / FALSE / 0 skip the table (no RLS, no policies); back on -> RLS and 4 policies';
end;
$$;

-- g2. A plain set (not set local) also skips: it keeps the trigger off for every
-- later table on the connection. Each skipped table (here and in g) raises a
-- WARNING; SQL cannot assert a WARNING, so it shows in the output only. The
-- trigger must leave the value as it was. Restored with reset before going on.
set maintenance.rls_autogen = 'off';
create table public.demo_optout_session (id uuid primary key, user_id uuid references auth.users (id));
create table public.demo_optout_session_2 (id uuid primary key, user_id uuid references auth.users (id));

do $$
declare
  v_t regclass;
begin
  if pg_catalog.current_setting('maintenance.rls_autogen', true) is distinct from 'off' then
    raise exception 'FAIL g2: the trigger changed maintenance.rls_autogen (now %)',
      pg_catalog.current_setting('maintenance.rls_autogen', true);
  end if;
  foreach v_t in array array['public.demo_optout_session', 'public.demo_optout_session_2']::regclass[] loop
    if (select relrowsecurity from pg_catalog.pg_class where oid = v_t) or pg_temp.policy_list(v_t) <> '' then
      raise exception 'FAIL g2: % got RLS or policies although a plain set switched the trigger off', v_t;
    end if;
  end loop;
end;
$$;

reset maintenance.rls_autogen;
create table public.demo_optin_after_reset (id uuid primary key, user_id uuid references auth.users (id));

do $$
begin
  if pg_catalog.lower(pg_catalog.btrim(coalesce(pg_catalog.current_setting('maintenance.rls_autogen', true), '')))
       in ('off', 'false', '0') then
    raise exception 'FAIL g2: maintenance.rls_autogen is still off after reset (set for the role, database or connection?)';
  end if;
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_optin_after_reset'::regclass)
     or pg_temp.policy_list('public.demo_optin_after_reset') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update' then
    raise exception 'FAIL g2: trigger did not resume after reset maintenance.rls_autogen';
  end if;
  raise notice 'PASS g2: a plain set also skips every later table (no RLS, no policies) and the trigger leaves the value as it was; after reset -> RLS and 4 policies';
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
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
                       not like '%= user_id)') then
    raise exception 'FAIL h1: user_id was not chosen on demo_two_owners';
  end if;
  raise notice 'PASS h1: two owner candidates (user_id, reviewer_id) -> policies on user_id';

  if pg_temp.policy_list('public.demo_owner_pref') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_owner_pref'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
                       not like '%= owner_id)') then
    raise exception 'FAIL h2: owner_id was not chosen on demo_owner_pref';
  end if;
  raise notice 'PASS h2: two owner candidates (owner_id, editor_id) -> policies on owner_id';

  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_ambiguous'::regclass)
     or pg_temp.policy_list('public.demo_ambiguous') <> '' then
    raise exception 'FAIL h3: ambiguous owner should give RLS on and no policies';
  end if;
  raise notice 'PASS h3: two owner candidates, neither preferred -> RLS on, 0 policies';
end;
$$;

-- Awkward identifiers: spaces, mixed case, a double quote, and SQL in the name.
create table public."Demo Table" (
  "Row Id"    uuid primary key default gen_random_uuid(),
  "Owner""Col" uuid not null references auth.users (id),
  "Body"      text
);
create table public."demo_x""); drop table public.demo_posts; --" (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id)
);
grant select, insert, update, delete on public."Demo Table" to authenticated;

do $$
declare
  v_a uuid := current_setting('verify.user_a')::uuid;
  v_b uuid := current_setting('verify.user_b')::uuid;
  v_n bigint;
begin
  if pg_temp.policy_list('public."Demo Table"') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or not (select relrowsecurity from pg_catalog.pg_class where oid = 'public."Demo Table"'::regclass) then
    raise exception 'FAIL h4: "Demo Table" not secured';
  end if;
  if pg_temp.policy_list('public."demo_x""); drop table public.demo_posts; --"') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or pg_catalog.to_regclass('public.demo_posts') is null then
    raise exception 'FAIL h4: table name with SQL in it was not handled safely';
  end if;

  perform pg_temp.act_as('authenticated', v_a::text);
  insert into public."Demo Table" ("Owner""Col", "Body") values (v_a, 'mine');
  select count(*) into v_n from public."Demo Table";
  if v_n <> 1 then raise exception 'FAIL h4: owner sees % rows in "Demo Table"', v_n; end if;
  begin
    insert into public."Demo Table" ("Owner""Col", "Body") values (v_b, 'theirs');
    raise exception 'FAIL h4: insert for another user succeeded on "Demo Table"';
  exception when insufficient_privilege then null;
  end;
  perform pg_temp.act_as('authenticated', v_b::text);
  select count(*) into v_n from public."Demo Table";
  if v_n <> 0 then raise exception 'FAIL h4: other user sees % rows in "Demo Table"', v_n; end if;
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
  if v_after is distinct from v_before then
    raise exception 'FAIL h5: re-run changed policies';
  end if;
  raise notice 'PASS h5: re-running apply_owner_policies keeps the same 4 policies';
end;
$$;

-- A policy someone already wrote under one of the fixed names is kept. Also covers the
-- manual call for a table the trigger did not handle.
set local maintenance.rls_autogen = 'off';
create table public.demo_custom (
  id      uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id)
);
set local maintenance.rls_autogen = 'on';
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
     or not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_custom'::regclass) then
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
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_ctas'::regclass) then
    raise exception 'FAIL h7: CREATE TABLE AS table has no RLS';
  end if;
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_select_into'::regclass) then
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
  if (select relkind from pg_catalog.pg_class where oid = 'public.demo_parted'::regclass) <> 'p'
     or not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted'::regclass)
     or not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted_2026'::regclass) then
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
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'demo_other_schema.demo_t'::regclass)
     or pg_temp.policy_list('demo_other_schema.demo_t') <> '' then
    raise exception 'FAIL h9: table outside public was changed';
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'pg_temp.demo_temp'::regclass) then
    raise exception 'FAIL h9: temporary table was changed';
  end if;
  raise notice 'PASS h9: tables in other schemas and temporary tables are left alone';
end;
$$;

-- Tables an extension script creates in public get RLS and no policies. Takes the
-- first of these extensions that is available and not installed yet (both create a
-- table in the schema they are installed into), creates it in public and checks
-- every table it put there. Any error from create extension is a FAIL. Rolled back
-- with the rest.
-- Each table is judged by what happened to it, not by who the caller is. A probe
-- table first shows the trigger fires for current_user (check 0 and the checks
-- above already depend on that). Who ran the script is read from the table owner,
-- since create extension makes the role running the script the owner of what it
-- creates.
--   RLS on, no policies           -> tested, passes, whoever owns it.
--   any policy                    -> FAIL.
--   RLS off, owned by current_user -> FAIL: the trigger fires for that role.
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
begin
  create table public.demo_h10_probe (id int);
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_h10_probe'::regclass) then
    raise exception 'FAIL h10: the trigger did not fire for a probe table created by %', current_user;
  end if;
  drop table public.demo_h10_probe;

  foreach v_ext in array array['pg_partman', 'postgis'] loop
    continue when not exists (select 1 from pg_catalog.pg_available_extensions
                               where name = v_ext and installed_version is null);
    begin
      execute pg_catalog.format('create extension %I schema public', v_ext);
    exception when others then
      raise exception 'FAIL h10: create extension % raised an error: %', v_ext, sqlerrm;
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
        raise exception 'FAIL h10: % (created by extension % as %, for whom the trigger fires) has no RLS',
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
      raise notice 'SKIP h10: not a test of the trigger: %; no other candidate tested a table; extension tables not tested',
        pg_catalog.array_to_string(v_other, '; ');
    else
      raise notice 'SKIP h10: none of pg_partman, postgis is available and not installed yet; extension tables not tested';
    end if;
  else
    raise notice 'PASS h10: tables created by create extension get RLS and 0 policies: %',
      pg_catalog.array_to_string(v_tested, ', ')
      || case when pg_catalog.cardinality(v_other) > 0
              then '; not a test of the trigger: ' || pg_catalog.array_to_string(v_other, '; ') else '' end;
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
set local maintenance.rls_autogen = 'off';
create table public.demo_parted_2027 (like public.demo_parted including defaults);
set local maintenance.rls_autogen = 'on';
alter table public.demo_parted attach partition public.demo_parted_2027
  for values from ('2027-01-01') to ('2028-01-01');
grant select, insert, update, delete on public.demo_moved, public.demo_parted_2027 to authenticated;

do $$
declare
  v_a uuid := current_setting('verify.user_a')::uuid;
  v_b uuid := current_setting('verify.user_b')::uuid;
  v_n bigint;
begin
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_moved'::regclass)
     or pg_temp.policy_list('public.demo_moved') <> '' then
    raise exception 'FAIL h11: table moved into public with set schema was changed; update the documented limit';
  end if;
  if (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted_2027'::regclass)
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
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_moved'::regclass)
     or pg_temp.policy_list('public.demo_moved') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_parted_2027'::regclass)
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
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_user'::regclass)
     or pg_temp.policy_list('public.demo_name_user') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_name_user'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
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

  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_owner'::regclass)
     or pg_temp.policy_list('public.demo_name_owner') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_name_owner'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
                       not like '%auth.uid()%= owner_id)') then
    raise exception 'FAIL i2: uuid owner_id without a foreign key did not get 4 policies on owner_id';
  end if;
  if pg_temp.policy_list('public.demo_name_both') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_name_both'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
                       not like '%= user_id)') then
    raise exception 'FAIL i2: with both names and no foreign key, user_id was not chosen';
  end if;
  raise notice 'PASS i2: uuid owner_id without a foreign key -> 4 policies on owner_id; user_id preferred when both exist';

  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_text'::regclass)
     or pg_temp.policy_list('public.demo_name_text') <> ''
     or not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_name_bigint'::regclass)
     or pg_temp.policy_list('public.demo_name_bigint') <> '' then
    raise exception 'FAIL i3: user_id that is not uuid should give RLS on and no policies';
  end if;
  raise notice 'PASS i3: user_id of type text or bigint (owner_id integer) -> RLS on, 0 policies';

  if pg_temp.policy_list('public.demo_fk_wins') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_fk_wins'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
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
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_fk_other'::regclass)
     or pg_temp.policy_list('public.demo_fk_other') <> ''
     or not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_fk_other_both'::regclass)
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
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_domain_fk'::regclass)
     or pg_temp.policy_list('public.demo_domain_fk') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_domain_fk'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
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
  if not (select relrowsecurity from pg_catalog.pg_class where oid = 'public.demo_domain_name'::regclass)
     or pg_temp.policy_list('public.demo_domain_name') <> 'a:owner_insert,d:owner_delete,r:owner_select,w:owner_update'
     or exists (select 1 from pg_catalog.pg_policy p
                 where p.polrelid = 'public.demo_domain_name'::regclass
                   and coalesce(pg_catalog.pg_get_expr(p.polqual, p.polrelid), pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid))
                       not like '%auth.uid()%= (user_id)::uuid)') then
    raise exception 'FAIL i7: domain over uuid named user_id without a foreign key did not get 4 policies on user_id (got %)',
      pg_temp.policy_list('public.demo_domain_name');
  end if;
  raise notice 'PASS i7: domain over uuid named user_id without a foreign key -> RLS and 4 policies on user_id';
end;
$$;

do $$
declare
  v_skipped text[] := pg_catalog.string_to_array(
                        nullif(pg_catalog.current_setting('verify.skipped', true), ''), ',');
begin
  if pg_catalog.cardinality(v_skipped) > 0 then
    raise notice 'ALL CHECKS PASSED (% skipped: %)',
      pg_catalog.cardinality(v_skipped), pg_catalog.array_to_string(v_skipped, ', ');
  else
    raise notice 'ALL CHECKS PASSED';
  end if;
end;
$$;

rollback;
