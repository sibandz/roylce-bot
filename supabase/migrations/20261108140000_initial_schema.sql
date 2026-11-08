create table if not exists public.users (
  id uuid primary key,
  username text not null check (username ~ '^[A-Za-z0-9_.-]{3,32}$'),
  username_key text generated always as (lower(username)) stored unique,
  password_salt text not null,
  password_hash text not null,
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at bigint not null,
  demo_state jsonb
);

create table if not exists public.signup_codes (
  code_hash text primary key,
  label text not null,
  expires_at bigint not null,
  used_at bigint,
  created_at bigint not null
);

create table if not exists public.sessions (
  token_hash text primary key,
  user_id uuid not null references public.users(id) on delete cascade,
  expires_at bigint not null
);

create index if not exists sessions_user_id on public.sessions(user_id);

alter table public.users enable row level security;
alter table public.signup_codes enable row level security;
alter table public.sessions enable row level security;

revoke all on public.users, public.signup_codes, public.sessions from public, anon, authenticated;
grant select, insert, update, delete on public.users, public.signup_codes, public.sessions to service_role;

create or replace function public.redeem_signup(
  p_user_id uuid,
  p_username text,
  p_password_salt text,
  p_password_hash text,
  p_code_hash text,
  p_now bigint
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  invite_expires_at bigint;
  invite_used_at bigint;
begin
  select expires_at, used_at
    into invite_expires_at, invite_used_at
    from public.signup_codes
    where code_hash = p_code_hash
    for update;

  if not found or invite_used_at is not null or invite_expires_at <= p_now then
    raise exception using errcode = 'P0001', message = 'INVITE_INVALID';
  end if;

  begin
    insert into public.users (id, username, password_salt, password_hash, role, created_at)
    values (p_user_id, p_username, p_password_salt, p_password_hash, 'user', p_now);
  exception when unique_violation then
    raise exception using errcode = 'P0001', message = 'USERNAME_TAKEN';
  end;

  update public.signup_codes
    set used_at = p_now
    where code_hash = p_code_hash;
end;
$$;

revoke all on function public.redeem_signup(uuid, text, text, text, text, bigint) from public, anon, authenticated;
grant execute on function public.redeem_signup(uuid, text, text, text, text, bigint) to service_role;
