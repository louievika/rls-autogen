-- rls_autogen: row level security on by default for new tables in public.
-- README.md has the details for everything below.
--
-- What it does
--   An event trigger named rls_autogen runs after CREATE TABLE, CREATE TABLE AS
--   and SELECT INTO. Every new table, partitioned table or partition in public
--   gets row level security enabled (not forced).
--   If the table has an owner column, it also gets four policies for the
--   authenticated role: owner_select, owner_insert, owner_update and
--   owner_delete, each limited to (select auth.uid()) = <owner column>. The
--   owner can read, add, change and delete their own rows.
--   The owner column is a uuid column with a single-column foreign key to
--   auth.users(id); with several, user_id is used, else owner_id, else none.
--   Only when there is no such column, the name rule applies: it takes the uuid
--   column user_id or, only if there is no uuid user_id, owner_id, and uses it
--   only if that column has no foreign key at all. So a user_id with any foreign
--   key means no policies, even if a plain owner_id exists. A domain over uuid
--   counts as uuid. With no owner column, or without auth.users, the table gets
--   RLS and no policies, so it is deny-all for anon and authenticated. A notice
--   says which case applied. When the table has an owner column but auth.uid()
--   or the role authenticated is missing, the caller has no usage on schema
--   auth, or authenticated has no usage on schema auth or no execute on
--   auth.uid(), it gets RLS and no policies, and a WARNING names the table and
--   the reason.
--   A table created by an extension script gets RLS and no policies, and a
--   WARNING, when the trigger fires for the role that runs the script.
--   A creating role without usage on schema maintenance and execute on
--   maintenance.apply_owner_policies(regclass) gets RLS and no policies, and a
--   WARNING with the two grants, the roles that can give them and the manual
--   call that adds the policies.
--   Existing policies with these names are kept. Grants are not changed.
--   For a table the trigger did not see, run as its owner:
--     select maintenance.apply_owner_policies('public.demo_posts');
--
-- Install
--   Expects the roles anon, authenticated and postgres; the revoke or grant for
--   a missing one is skipped with a notice. Creates the schema maintenance, or
--   reuses an existing one, and revokes all access to it from public, anon and
--   authenticated. Safe to run
--   again; run it in one transaction (psql -1) so that the event trigger is not
--   missing between its drop and its create. Over an installed 1.0.0 it ends in
--   the same state as a fresh install: it revokes the execute on
--   maintenance.rls_autogen() that 1.0.0 granted to postgres. Add this file next
--   to the 1.0.0 file; do not edit that one.
--
-- Opt out for the tables created in one transaction
--   begin; select maintenance.skip_rls_autogen(); create table ...; commit;
--   The function sets maintenance.rls_autogen to the token
--   'skip:<transaction id>:<transaction start time in microseconds since 1970>'
--   for the current transaction only. The trigger skips a table only when the
--   value is exactly that token for the transaction it runs in and both
--   current_user and session_user have usage on schema maintenance and execute
--   on maintenance.skip_rls_autogen(); it raises a WARNING naming the table.
--   Inside a function that runs with its owner's rights current_user is the
--   owner, so the login role (session_user) must hold the grants too. Any
--   other value ('off', a token of an earlier transaction, a plain set, a role,
--   database, server or connection value, or the token when either role lacks
--   those grants) is ignored: tables are protected and each statement that
--   creates a table in a watched schema raises one WARNING saying the value was
--   ignored and, where that is the reason, which role lacks which grant.
--   Transaction ids count up, so a value stored ahead of time could name a
--   later transaction id, but it would also have to contain the microsecond
--   start time of a transaction that has not started yet.
--
-- Replica mode
--   The event trigger is enabled with enable always, so it also fires when
--   session_replication_role = replica, as data-load and restore scripts often
--   set it. Disable it by hand for a restore (see README.md).
--
-- Known limits (see README.md)
--   - The opt-out covers every table created in public for the rest of its
--     transaction, extension tables included.
--   - Not covered: views, materialized views, foreign tables, tables created
--     inside CREATE SCHEMA, tables moved in with SET SCHEMA, partitions added
--     with ATTACH PARTITION, foreign keys added later, and tables that existed
--     before this file. Use the manual call where RLS can be enabled.
--   - The manual call on a partitioned table does not change its partitions.
--   - A user_id or owner_id whose foreign key to another table is added later
--     keeps the name fallback policies.
--   - Restoring a dump with the trigger enabled adds policies, causes duplicate
--     policy errors and locks tables. Disable the trigger for the restore;
--     session_replication_role = replica does not stop it.
--   - Table owners, roles with BYPASSRLS and service_role bypass RLS.
--   - On hosted platforms such as Supabase, the trigger may not fire for
--     superuser or reserved roles. Tables it does not see, including extension
--     tables, keep RLS off; list them with the RLS-off query in README.md.
--
-- Accepted risks (risk: why accepted; where README.md covers it)
--   - owner_update lets an owner change any column of their own row, but not give
--     it to another user: that is what an owner policy is; "What it does" shows
--     the drops for a read-only table.
--   - Views, materialized views and foreign tables are not covered: RLS cannot be
--     enabled on any of them; views need security_invoker; "Not covered".
--   - ALTER TABLE is not hooked (set schema into a watched schema, attach
--     partition, a foreign key added later): hooking it would add policies again
--     to tables whose policies someone has already tuned; the manual call is
--     documented; "Not covered".
--   - The name rule trusts a uuid user_id or owner_id with no foreign key: without
--     it a table created before its foreign key would get no policies; "Name
--     fallback".
--   - The grants on skip_rls_autogen() control the opt-out, but a table's owner can
--     still run alter table ... disable row level security on its own table: no
--     trigger can prevent that; "By design".
--   - Platforms that do not fire event triggers for superuser or reserved roles:
--     outside a migration's control; the RLS-off query finds such tables; "Roles
--     the trigger does not fire for".
--   - Restoring a dump with the trigger enabled collides with the dump's own
--     policies: disable, restore, enable always; the trigger fires in replica mode
--     too, so a restore that sets session_replication_role = replica still needs
--     the disable; re-running this file re-creates the trigger enabled, so it is
--     not re-applied during a restore window; "Dump and restore".
--   - The opt-out needs the grants on both current_user and session_user: a
--     session that logs in as one role and switches with set role needs them on
--     both roles; without them the table is simply protected (fail closed); "Opt
--     out".
--   - Inside a function that runs with its owner's rights, both checks see the
--     owner and the login role: when both hold the grants, the token set by that
--     session also counts for tables the function creates for a caller without
--     them. Who may call such a function is its owner's choice; "Opt out".
--   - Self-check h10 judges by table owner, which misreads a platform that
--     reassigns extension-table ownership: its FAIL message says so; "Verify".
--   - A creating role without the maintenance grants gets RLS and no owner
--     policies: fail closed by design; the WARNING gives the fix; "Tables the
--     trigger did not see".

create schema if not exists maintenance;
revoke all on schema maintenance from public;

-- Enable RLS on one table and add the owner policies when an owner column is found.
-- Runs as the caller, who must own the table.
create or replace function maintenance.apply_owner_policies(p_table pg_catalog.regclass)
returns pg_catalog.void
language plpgsql
security invoker
set search_path = pg_catalog, pg_temp
as $$
declare
  v_kind  pg_catalog."char";
  v_auth  pg_catalog.oid;
  v_users pg_catalog.oid;
  v_uid   pg_catalog.oid;
  v_uuid  pg_catalog.name[];
  v_cols  pg_catalog.name[];
  v_owner pg_catalog.name;
  v_refs  pg_catalog.text;
  v_pred  pg_catalog.text;
  v_why   pg_catalog.text[] := '{}';
begin
  select c.relkind into v_kind from pg_catalog.pg_class c where c.oid = p_table;
  if v_kind is null or v_kind not in ('r', 'p') then
    raise exception 'rls_autogen: % is not a table or partitioned table', p_table
      using errcode = 'wrong_object_type';
  end if;

  execute pg_catalog.format('alter table %s enable row level security', p_table);

  -- Catalog reads only: to_regclass('auth.users') raises an error for a caller
  -- without usage on schema auth.
  select n.oid into v_auth from pg_catalog.pg_namespace n where n.nspname = 'auth';
  select c.oid into v_users from pg_catalog.pg_class c where c.relnamespace = v_auth and c.relname = 'users';
  if v_users is null then
    raise notice 'rls_autogen: auth.users does not exist, so % cannot have an owner column; RLS is on, no policies created. Add policies yourself.', p_table;
    return;
  end if;

  -- Columns of type uuid, directly or through a domain over uuid (any depth).
  with recursive t(attname, typid) as (
    select a.attname, a.atttypid
      from pg_catalog.pg_attribute a
     where a.attrelid = p_table
       and a.attnum > 0
       and not a.attisdropped
    union all
    select t.attname, y.typbasetype
      from t
      join pg_catalog.pg_type y on y.oid = t.typid
     where y.typtype = 'd'
  )
  select pg_catalog.array_agg(t.attname) into v_uuid
    from t
   where t.typid = 'pg_catalog.uuid'::pg_catalog.regtype;

  select pg_catalog.array_agg(distinct a.attname order by a.attname) into v_cols
    from pg_catalog.pg_constraint k
    join pg_catalog.pg_attribute a on a.attrelid = k.conrelid and a.attnum = k.conkey[1]
    join pg_catalog.pg_attribute r on r.attrelid = k.confrelid and r.attnum = k.confkey[1]
   where k.conrelid = p_table
     and k.contype = 'f'
     and k.confrelid = v_users
     and pg_catalog.cardinality(k.conkey) = 1
     and r.attname = 'id'
     and a.attname = any (v_uuid)
     and not a.attisdropped;

  if v_cols is null then
    -- Name fallback, used only when no foreign key candidate exists:
    -- a uuid column named exactly user_id, else exactly owner_id, and only
    -- when that column has no foreign key at all.
    v_owner := case when 'user_id' = any (v_uuid) then 'user_id'
                    when 'owner_id' = any (v_uuid) then 'owner_id' end;
    if v_owner is null then
      raise notice 'rls_autogen: % has no owner column (uuid foreign key to auth.users.id, or uuid column user_id or owner_id without a foreign key); RLS is on, no policies created', p_table;
      return;
    end if;
    select pg_catalog.string_agg(distinct k.confrelid::pg_catalog.regclass::pg_catalog.text, ', ') into v_refs
      from pg_catalog.pg_constraint k
      join pg_catalog.pg_attribute a on a.attrelid = k.conrelid and a.attnum = any (k.conkey)
     where k.conrelid = p_table
       and k.contype = 'f'
       and a.attname = v_owner;
    if v_refs is not null then
      raise notice 'rls_autogen: % column % references % (not as a single-column key to auth.users.id), so it is not the owner column; RLS is on, no policies created. Add policies yourself.', p_table, v_owner, v_refs;
      return;
    end if;
    raise notice 'rls_autogen: % has no single-column foreign key to auth.users(id); using uuid column % (no foreign key) as owner by its name', p_table, v_owner;
  elsif pg_catalog.cardinality(v_cols) = 1 then
    v_owner := v_cols[1];
  elsif 'user_id' = any (v_cols) then
    v_owner := 'user_id';
  elsif 'owner_id' = any (v_cols) then
    v_owner := 'owner_id';
  else
    raise notice 'rls_autogen: % has several owner candidates (%); RLS is on, no policies created',
      p_table, pg_catalog.array_to_string(v_cols, ', ');
    return;
  end if;

  -- The policies need these. Without them the table stays locked: RLS on, no policies.
  -- The creating role needs usage on schema auth to create them; authenticated, for
  -- which the policies call auth.uid(), needs usage on auth and execute on auth.uid().
  if not pg_catalog.has_schema_privilege(v_auth, 'USAGE') then
    v_why := v_why || pg_catalog.format('role %I has no usage on schema auth', current_user);
  end if;
  select p.oid into v_uid
    from pg_catalog.pg_proc p
   where p.pronamespace = v_auth and p.proname = 'uid' and p.pronargs = 0
     and p.prorettype = 'pg_catalog.uuid'::pg_catalog.regtype;
  if v_uid is null then
    v_why := v_why || 'function auth.uid() returning uuid does not exist'::pg_catalog.text;
  end if;
  if not exists (select 1 from pg_catalog.pg_roles r where r.rolname = 'authenticated') then
    v_why := v_why || 'role authenticated does not exist'::pg_catalog.text;
  else
    if not pg_catalog.has_schema_privilege('authenticated', v_auth, 'USAGE') then
      v_why := v_why || 'role authenticated has no usage on schema auth'::pg_catalog.text;
    end if;
    if v_uid is not null and not pg_catalog.has_function_privilege('authenticated', v_uid, 'EXECUTE') then
      v_why := v_why || 'role authenticated has no execute on auth.uid()'::pg_catalog.text;
    end if;
  end if;
  if pg_catalog.cardinality(v_why) > 0 then
    raise warning 'rls_autogen: % has owner column %, but %; RLS is on, no policies created. Add policies yourself.',
      p_table, v_owner, pg_catalog.array_to_string(v_why, ', and ');
    return;
  end if;

  v_pred := pg_catalog.format('(select auth.uid()) = %I', v_owner);

  if not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = p_table and p.polname = 'owner_select') then
    execute pg_catalog.format('create policy owner_select on %s for select to authenticated using (%s)', p_table, v_pred);
  end if;
  if not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = p_table and p.polname = 'owner_insert') then
    execute pg_catalog.format('create policy owner_insert on %s for insert to authenticated with check (%s)', p_table, v_pred);
  end if;
  if not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = p_table and p.polname = 'owner_update') then
    execute pg_catalog.format('create policy owner_update on %s for update to authenticated using (%s) with check (%s)', p_table, v_pred, v_pred);
  end if;
  if not exists (select 1 from pg_catalog.pg_policy p where p.polrelid = p_table and p.polname = 'owner_delete') then
    execute pg_catalog.format('create policy owner_delete on %s for delete to authenticated using (%s)', p_table, v_pred);
  end if;
end;
$$;

-- Opt out for the rest of the current transaction. The token is the top-level
-- transaction id and the transaction's start time as whole microseconds since
-- 1970; both stay the same inside a savepoint, and the time is the same whatever
-- the time zone or locale. pg_current_xact_id() is used, not the deprecated
-- txid_current(); its 64-bit value includes the epoch, so it is not reused after
-- wraparound. The trigger builds the same token to compare.
create or replace function maintenance.skip_rls_autogen()
returns pg_catalog.void
language plpgsql
security invoker
set search_path = pg_catalog, pg_temp
as $$
begin
  perform pg_catalog.set_config('maintenance.rls_autogen',
    'skip:' || pg_catalog.pg_current_xact_id()::pg_catalog.text || ':'
      || (extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::pg_catalog.int8::pg_catalog.text,
    true);
end;
$$;

-- Event trigger function: applies the above to each new table in the watched schemas.
create or replace function maintenance.rls_autogen()
returns pg_catalog.event_trigger
language plpgsql
security invoker
set search_path = pg_catalog, pg_temp
as $$
declare
  -- Watched schemas. Add names here to cover more schemas.
  c_schemas constant pg_catalog.text[] := array['public'];
  v_value  pg_catalog.text := coalesce(pg_catalog.current_setting('maintenance.rls_autogen', true), '');
  v_usage  pg_catalog.bool := pg_catalog.has_schema_privilege('maintenance', 'USAGE');
  v_skip   pg_catalog.bool := false;
  v_ignore pg_catalog.text;
  v_oid    pg_catalog.oid;
  v_in_ext pg_catalog.bool;
  v_ext    pg_catalog.name;
  v_apply_fn pg_catalog.oid;
  v_skip_fn  pg_catalog.oid;
  v_lack   pg_catalog.text[] := '{}';
  v_nskip  pg_catalog.text[] := '{}';
  v_role   pg_catalog.name;
  v_rlack  pg_catalog.text[];
  v_nspown pg_catalog.text;
  v_fnown  pg_catalog.text;
begin
  -- The event trigger fires without any grant, but apply_owner_policies runs as
  -- the creating role. Check that role's grants first, so that a role without
  -- them still gets a locked table instead of an error. Catalog lookup only:
  -- a regprocedure cast raises an error without usage on schema maintenance.
  if not v_usage then
    v_lack := v_lack || 'usage on schema maintenance'::pg_catalog.text;
  end if;
  select p.oid, pg_catalog.quote_ident(r.rolname) into v_apply_fn, v_fnown
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    left join pg_catalog.pg_roles r on r.oid = p.proowner
   where n.nspname = 'maintenance' and p.proname = 'apply_owner_policies'
     and p.pronargs = 1 and p.proargtypes[0] = 'pg_catalog.regclass'::pg_catalog.regtype;
  -- The roles that can give the two grants, for the WARNING below: the owner of the
  -- schema and the owner of the function (the role that installed this file). They
  -- differ when the schema existed before the install.
  select pg_catalog.quote_ident(r.rolname) into v_nspown
    from pg_catalog.pg_namespace n
    join pg_catalog.pg_roles r on r.oid = n.nspowner
   where n.nspname = 'maintenance';
  if v_apply_fn is null or not pg_catalog.has_function_privilege(v_apply_fn, 'EXECUTE') then
    v_lack := v_lack || 'execute on maintenance.apply_owner_policies(regclass)'::pg_catalog.text;
  end if;

  if v_value <> '' then
    -- Only the token of this (top-level) transaction skips: its id and its start
    -- time, as skip_rls_autogen() writes it. A value stored ahead of time would
    -- have to contain the microsecond start time of a transaction that has not
    -- started yet.
    if v_value = 'skip:' || pg_catalog.pg_current_xact_id()::pg_catalog.text || ':'
                 || (extract(epoch from pg_catalog.transaction_timestamp()) * 1000000)::pg_catalog.int8::pg_catalog.text then
      -- The token counts only when both current_user and session_user may call
      -- skip_rls_autogen(): any role can set the value by hand, and inside a
      -- function that runs with its owner's rights current_user is the owner, not
      -- the caller. Same catalog lookup as above.
      select p.oid into v_skip_fn
        from pg_catalog.pg_proc p
        join pg_catalog.pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'maintenance' and p.proname = 'skip_rls_autogen' and p.pronargs = 0;
      foreach v_role in array case when session_user = current_user then array[current_user]
                                   else array[current_user, session_user] end loop
        v_rlack := '{}';
        if not pg_catalog.has_schema_privilege(v_role, 'maintenance', 'USAGE') then
          v_rlack := v_rlack || 'usage on schema maintenance'::pg_catalog.text;
        end if;
        if v_skip_fn is null or not pg_catalog.has_function_privilege(v_role, v_skip_fn, 'EXECUTE') then
          v_rlack := v_rlack || 'execute on maintenance.skip_rls_autogen()'::pg_catalog.text;
        end if;
        if pg_catalog.cardinality(v_rlack) > 0 then
          v_nskip := v_nskip || pg_catalog.format('%s %I lacks %s',
            case when v_role = current_user then 'role' else 'session user' end,
            v_role, pg_catalog.array_to_string(v_rlack, ' and '));
        end if;
      end loop;
      if pg_catalog.cardinality(v_nskip) = 0 then
        v_skip := true;
      else
        v_ignore := pg_catalog.format(
          'rls_autogen: ignored maintenance.rls_autogen = %L: %s, so it cannot opt out (the opt-out needs both the current user and the session user to have the grants); tables are protected as usual.',
          v_value, pg_catalog.array_to_string(v_nskip, '; '));
      end if;
    else
      v_ignore := pg_catalog.format(
        'rls_autogen: ignored maintenance.rls_autogen = %L; tables are protected as usual. The supported opt-out is select maintenance.skip_rls_autogen(); inside the same transaction.',
        v_value);
    end if;
  end if;

  for v_oid, v_in_ext in
    select c.oid, pg_catalog.bool_or(d.in_extension)
      from pg_catalog.pg_event_trigger_ddl_commands() d
      join pg_catalog.pg_class c on c.oid = d.objid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
     where d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
       and d.object_type = 'table'
       and c.relkind in ('r', 'p')
       and n.nspname = any (c_schemas)
     group by c.oid
     order by c.oid
  loop
    -- WARNING, not NOTICE, so both show at default client settings.
    if v_skip then
      raise warning 'rls_autogen: RLS is not enabled on %: the opt-out is set for this transaction.',
        v_oid::pg_catalog.regclass;
      continue;
    end if;
    if v_ignore is not null then
      raise warning using message = v_ignore;
      v_ignore := null;
    end if;
    begin
      if v_in_ext then
        -- Created by an extension script: lock it, but never guess an owner column.
        execute pg_catalog.format('alter table %s enable row level security', v_oid::pg_catalog.regclass);
        select e.extname into v_ext
          from pg_catalog.pg_depend dep
          join pg_catalog.pg_extension e on e.oid = dep.refobjid
         where dep.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
           and dep.objid = v_oid
           and dep.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass
           and dep.deptype = 'e'
         limit 1;
        -- WARNING, not NOTICE: Postgres hides messages below WARNING while an
        -- extension script runs.
        raise warning 'rls_autogen: % was created by extension %; RLS is on, no policies created (owner columns are not guessed on extension tables). It is locked for anon and authenticated; add a policy yourself if API roles need it.',
          v_oid::pg_catalog.regclass, coalesce(v_ext, '(unknown)');
      elsif pg_catalog.cardinality(v_lack) > 0 then
        -- The creating role owns the table, so it can lock it without the helper.
        execute pg_catalog.format('alter table %s enable row level security', v_oid::pg_catalog.regclass);
        raise warning using message = pg_catalog.format(
          'rls_autogen: %s is locked (RLS on, no policies): owner policies were not added because role %I lacks %s. '
          'To add them: as role %s (owner of schema maintenance) or a superuser, grant usage on schema maintenance to %I; '
          'as role %s (owner of maintenance.apply_owner_policies) or a superuser, '
          'grant execute on function maintenance.apply_owner_policies(regclass) to %I; '
          'then, as %I: select maintenance.apply_owner_policies(%L);',
          v_oid::pg_catalog.regclass, current_user, pg_catalog.array_to_string(v_lack, ' and '),
          coalesce(v_nspown, '(unknown)'), current_user, coalesce(v_fnown, '(unknown)'), current_user,
          current_user, v_oid::pg_catalog.regclass::pg_catalog.text);
      else
        perform maintenance.apply_owner_policies(v_oid::pg_catalog.regclass);
      end if;
    exception when insufficient_privilege then
      raise exception 'rls_autogen: could not secure %: %', v_oid::pg_catalog.regclass, sqlerrm
        using errcode = 'insufficient_privilege',
              hint = 'Possible cause: this role does not own the table.';
    end;
  end loop;
end;
$$;

revoke all on function maintenance.apply_owner_policies(regclass) from public;
revoke all on function maintenance.skip_rls_autogen() from public;
revoke all on function maintenance.rls_autogen() from public;

-- Revokes for anon and authenticated, and grants to postgres, for the roles that exist.
-- The trigger runs as the role that creates the table, and calls apply_owner_policies
-- as that role. On Supabase that is postgres. The event trigger itself needs no grant;
-- another role without these grants gets RLS, no policies and a WARNING. The opt-out
-- counts only when both current_user and session_user have usage on maintenance and
-- execute on skip_rls_autogen().
do $$
declare
  v_role pg_catalog.name;
begin
  foreach v_role in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_catalog.pg_roles where rolname = v_role) then
      execute pg_catalog.format('revoke all on schema maintenance from %I', v_role);
      execute pg_catalog.format('revoke all on function maintenance.apply_owner_policies(regclass) from %I', v_role);
      execute pg_catalog.format('revoke all on function maintenance.skip_rls_autogen() from %I', v_role);
      execute pg_catalog.format('revoke all on function maintenance.rls_autogen() from %I', v_role);
    else
      raise notice 'rls_autogen: role % does not exist; its revoke was skipped', v_role;
    end if;
  end loop;
  if exists (select 1 from pg_catalog.pg_roles where rolname = 'postgres') then
    grant usage on schema maintenance to postgres;
    grant execute on function maintenance.apply_owner_policies(regclass) to postgres;
    grant execute on function maintenance.skip_rls_autogen() to postgres;
    -- 1.0.0 granted execute on the event trigger function to postgres; it needs
    -- none. Revoke that grant so a re-run over 1.0.0 ends like a fresh install.
    -- Not when postgres owns the function: that would remove the owner's own
    -- execute, which a fresh install keeps.
    if not exists (select 1 from pg_catalog.pg_proc p
                     join pg_catalog.pg_roles r on r.oid = p.proowner
                    where p.oid = 'maintenance.rls_autogen()'::pg_catalog.regprocedure
                      and r.rolname = 'postgres') then
      revoke execute on function maintenance.rls_autogen() from postgres;
    end if;
  else
    raise notice 'rls_autogen: role postgres does not exist; its grant was skipped';
  end if;
end;
$$;

drop event trigger if exists rls_autogen;
create event trigger rls_autogen on ddl_command_end
  when tag in ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
  execute function maintenance.rls_autogen();
-- Fire in every session_replication_role mode, also replica, which data-load and
-- restore scripts often set; in the default mode a table created then would be
-- left without RLS and without a message.
alter event trigger rls_autogen enable always;
