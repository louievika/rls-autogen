-- rls_autogen: row level security on by default for new tables in public.
--
-- What it does
--   An event trigger runs after CREATE TABLE, CREATE TABLE AS and SELECT INTO.
--   Every new table, partitioned table or partition in public gets row level
--   security enabled (not forced). If the table has an owner column, meaning a
--   uuid column with a single-column foreign key to auth.users(id), it also gets
--   four policies for the authenticated role: owner_select, owner_insert,
--   owner_update and owner_delete, each limited to (select auth.uid()) = <column>.
--   With more than one such column, user_id is used, then owner_id; otherwise no
--   policies are created. Only when no such foreign key column exists, a uuid
--   column named exactly user_id, else exactly owner_id, is taken as the owner by
--   its name alone, and only if that column has no foreign key at all. If it has a
--   foreign key to another table, it is not the owner: no policies are created and
--   a notice says so. Foreign key columns always win over the name fallback. A
--   uuid column may also be a domain over uuid. If auth.users does not exist, no
--   policies are created and a notice says so. A table
--   without policies is deny-all for anon and authenticated. Existing policies with these names are kept as they are.
--   Grants are not changed. Re-running this file is safe.
--   A table created by an extension script (CREATE EXTENSION or ALTER EXTENSION
--   UPDATE) also gets RLS enabled, but never owner policies: no owner column is
--   guessed on an extension's table. A WARNING names the table and its extension
--   (a NOTICE would be hidden, since Postgres shows only WARNING and above while
--   an extension script runs).
--   It is locked for anon and authenticated until you add a policy yourself.
--   This needs the event trigger to fire for the role that runs the script; see
--   Known limits.
--
-- Opt out for the tables created in one transaction
--   set local maintenance.rls_autogen = 'off';
--   Only set local inside a transaction is supported. Set at any other level (a
--   plain set, alter role ... set, alter database ... set, connection options),
--   the switch keeps the trigger off for every later table on that connection,
--   role or database. A set left on a pooled connection carries over to the next
--   client that gets it. Each skipped table raises a WARNING that names it and
--   says RLS was NOT enabled; when the value is also set beyond this session's
--   own set commands, the WARNING says so and how to clear it. To check the
--   current value:
--     select pg_catalog.current_setting('maintenance.rls_autogen', true);
--
-- Known limits
--   - A foreign key added later with ALTER TABLE does not fire the trigger. Run
--     select maintenance.apply_owner_policies('public.your_table');
--   - A user_id or owner_id column whose foreign key to another table is added
--     after CREATE TABLE (as a schema restore does) already got the four name
--     fallback policies, and neither the new foreign key nor the call above
--     removes them; drop them yourself.
--   - Tables that existed before this migration are not changed. Same call.
--   - ALTER TABLE ... SET SCHEMA public does not fire the trigger, so a table moved
--     into public keeps RLS off. Run the same call on it, or enable RLS and add
--     policies on it yourself.
--   - ALTER TABLE ... ATTACH PARTITION does not fire the trigger, so an attached
--     partition keeps RLS off, and a query on the partition itself does not apply
--     the parent's policies. Run the same call on the partition, or enable RLS and
--     add policies on it yourself. A partition created with CREATE TABLE ...
--     PARTITION OF is covered.
--   - Extension tables. When the event trigger fires for the role that runs the
--     extension's script, its tables in public get RLS on, no policies and a
--     WARNING. PostgreSQL documents no exception by role, so this holds for a
--     superuser too; it documents event triggers as off only in single-user mode
--     or with event_triggers = off (PostgreSQL 17 and later). A function or query
--     that reads such a table as an API role (for example a coordinate transform
--     reading its reference table) gets no rows until you add a read policy for
--     that role. Some managed platforms skip event triggers for superuser or
--     reserved roles. There, a table created by such a role, including by an
--     extension script the platform runs as such a role, is NOT touched and no
--     message is shown. After installing an extension, check its tables and
--     secure them yourself. To list the tables in public with RLS off:
--       select c.oid::regclass from pg_catalog.pg_class c
--        where c.relnamespace = 'public'::regnamespace
--          and c.relkind in ('r', 'p') and not c.relrowsecurity;
--   - Table owners, roles with BYPASSRLS and service_role bypass RLS by design.
--   - On hosted Supabase, event triggers do not fire for superuser or reserved
--     roles (supabase_admin, service_role, anon, authenticated and others).

create schema if not exists maintenance;
revoke all on schema maintenance from public, anon, authenticated;

-- Enable RLS on one table and add the owner policies when an owner column is found.
-- Runs as the caller, who must own the table.
create or replace function maintenance.apply_owner_policies(p_table regclass)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_users regclass := pg_catalog.to_regclass('auth.users');
  v_kind  "char";
  v_uuid  name[];
  v_cols  name[];
  v_owner name;
  v_refs  text;
  v_pred  text;
begin
  select c.relkind into v_kind from pg_catalog.pg_class c where c.oid = p_table;
  if v_kind is null or v_kind not in ('r', 'p') then
    raise exception 'rls_autogen: % is not a table or partitioned table', p_table
      using errcode = 'wrong_object_type';
  end if;

  execute pg_catalog.format('alter table %s enable row level security', p_table);

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
    select pg_catalog.string_agg(distinct k.confrelid::pg_catalog.regclass::text, ', ') into v_refs
      from pg_catalog.pg_constraint k
      join pg_catalog.pg_attribute a on a.attrelid = k.conrelid and a.attnum = any (k.conkey)
     where k.conrelid = p_table
       and k.contype = 'f'
       and a.attname = v_owner;
    if v_refs is not null then
      raise notice 'rls_autogen: % column % references % (not as a single-column key to auth.users.id), so it is not the owner column; RLS is on, no policies created. Add policies yourself.', p_table, v_owner, v_refs;
      return;
    end if;
    raise notice 'rls_autogen: % has no foreign key to auth.users; using uuid column % (no foreign key) as owner by its name', p_table, v_owner;
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

-- Event trigger function: applies the above to each new table in the watched schemas.
create or replace function maintenance.rls_autogen()
returns event_trigger
language plpgsql
security invoker
set search_path = ''
as $$
declare
  -- Watched schemas. Add names here to cover more schemas.
  c_schemas constant text[] := array['public'];
  v_value  text := coalesce(pg_catalog.current_setting('maintenance.rls_autogen', true), '');
  v_off    boolean := pg_catalog.lower(pg_catalog.btrim(v_value)) in ('off', 'false', '0');
  v_reset  text;
  v_skip   text;
  v_oid    oid;
  v_in_ext boolean;
  v_ext    name;
begin
  if v_off then
    -- Read the value RESET would return, which comes from the role, the database,
    -- the connection options or the server configuration. The subtransaction is
    -- rolled back, so the current value is left exactly as it was. A plain SET and
    -- SET LOCAL cannot be told apart from SQL, so both get the first message.
    begin
      execute 'reset maintenance.rls_autogen';
      v_reset := coalesce(pg_catalog.current_setting('maintenance.rls_autogen', true), '');
      raise exception 'rls_autogen: probe';
    exception when raise_exception then
      null;
    end;
    if pg_catalog.lower(pg_catalog.btrim(v_reset)) in ('off', 'false', '0') then
      v_skip := pg_catalog.format(
        'It is set beyond this transaction (for the role, the database, the connection options or the server configuration), '
        'so every later table on this connection is skipped too. reset maintenance.rls_autogen does not clear it; '
        'run alter role %I reset maintenance.rls_autogen or alter database %I reset maintenance.rls_autogen '
        '(or remove it from the connection options or server configuration), then reconnect.',
        session_user, pg_catalog.current_database());
    else
      v_skip := 'Only set local inside a transaction is supported; a plain set keeps it off for every later table '
                'on this connection until reset maintenance.rls_autogen.';
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
    if v_off then
      -- WARNING, not NOTICE, so it shows at default client settings.
      raise warning 'rls_autogen: RLS was NOT enabled on % because maintenance.rls_autogen is off (%). %',
        v_oid::pg_catalog.regclass, pg_catalog.quote_literal(v_value), v_skip;
      continue;
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
      else
        perform maintenance.apply_owner_policies(v_oid::pg_catalog.regclass);
      end if;
    exception when insufficient_privilege then
      raise exception 'rls_autogen: could not secure %: %', v_oid::pg_catalog.regclass, sqlerrm
        using errcode = 'insufficient_privilege',
              hint = 'Grant usage on schema maintenance and execute on maintenance.apply_owner_policies(regclass) '
                     'to this role, or run set local maintenance.rls_autogen = ''off'' first.';
    end;
  end loop;
end;
$$;

revoke all on function maintenance.apply_owner_policies(regclass) from public, anon, authenticated;
revoke all on function maintenance.rls_autogen() from public, anon, authenticated;

-- The trigger runs as the role that creates the table. On Supabase that is postgres.
grant usage on schema maintenance to postgres;
grant execute on function maintenance.apply_owner_policies(regclass) to postgres;
grant execute on function maintenance.rls_autogen() to postgres;

drop event trigger if exists rls_autogen;
create event trigger rls_autogen on ddl_command_end
  when tag in ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
  execute function maintenance.rls_autogen();
