-- Additive migration; deploy once to the existing gate database after review.
begin;
create table if not exists jarod_pin_security.otp_challenges (
  scope text not null, challenge text not null, digest text not null,
  issued_at timestamptz not null default clock_timestamp(),
  expires_at timestamptz not null, failures integer not null default 0,
  consumed boolean not null default false, primary key(scope,challenge)
);
alter table jarod_pin_security.otp_challenges enable row level security;
revoke all on jarod_pin_security.otp_challenges from public, anon, authenticated;
create or replace function public.jarod_otp(p_secret text,p_scope text,p_ip text,p_action text,p_challenge text,p_digest text)
returns jsonb language plpgsql security definer set search_path='' as $$
declare t timestamptz; r jarod_pin_security.otp_challenges%rowtype; gate jsonb;
begin
  gate := jarod_pin_security.check_gate(p_secret,p_scope,p_ip,'status',false);
  if not (gate->>'allowed')::boolean then return jsonb_build_object('ok',false,'retry',gate->'retry'); end if;
  if p_challenge is null or p_challenge !~ '^[a-f0-9]{64}$' or p_digest is null or p_digest !~ '^[a-f0-9]{64}$' then raise exception 'Invalid request'; end if;
  if p_action='issue' then
    perform pg_advisory_xact_lock(hashtextextended('jarod-otp:'||p_scope,0));
    t:=clock_timestamp();
    delete from jarod_pin_security.otp_challenges where scope=p_scope and issued_at<t-interval '1 day';
    if exists(select 1 from jarod_pin_security.otp_challenges where scope=p_scope and issued_at>t-interval '60 seconds')
      or (select count(*) from jarod_pin_security.otp_challenges where scope=p_scope and issued_at>t-interval '15 minutes')>=3 then
      return jsonb_build_object('ok',false,'retry',60);
    end if;
    insert into jarod_pin_security.otp_challenges(scope,challenge,digest,issued_at,expires_at)
      values(p_scope,p_challenge,p_digest,t,t+interval '5 minutes');
    return jsonb_build_object('ok',true);
  elsif p_action='verify' then
    select * into r from jarod_pin_security.otp_challenges where scope=p_scope and challenge=p_challenge for update;
    t:=clock_timestamp();
    if not found or r.consumed or r.expires_at<=t or r.failures>=5 then return jsonb_build_object('ok',false); end if;
    if r.digest<>p_digest then
      update jarod_pin_security.otp_challenges set failures=failures+1 where scope=p_scope and challenge=p_challenge;
      return jsonb_build_object('ok',false);
    end if;
    update jarod_pin_security.otp_challenges set consumed=true where scope=p_scope and challenge=p_challenge;
    return jsonb_build_object('ok',true);
  else raise exception 'Invalid action';
  end if;
end; $$;
revoke all on function public.jarod_otp(text,text,text,text,text,text) from public;
grant execute on function public.jarod_otp(text,text,text,text,text,text) to anon, authenticated, service_role;
commit;
