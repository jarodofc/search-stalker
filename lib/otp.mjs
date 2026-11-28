import {createHmac,randomInt,randomBytes} from 'node:crypto';
export const otpCookie='__Host-zotp-challenge';
export const sessionCookie='__Host-zotp-session';
export const challengeAge=300,sessionAge=8*3600;
export const mac=(key,input)=>createHmac('sha256',key).update(input).digest('hex');
export function newChallenge(){return randomBytes(32).toString('hex');}
export function newCode(){return String(randomInt(0,1000000)).padStart(6,'0');}
export function hashes(key,scope,challenge,code){return {challenge:mac(key,'challenge:'+scope+':'+challenge),digest:mac(key,'otp:'+scope+':'+challenge+':'+code)};}
export function cookie(name,value,age){return name+'='+value+'; Path=/; Max-Age='+age+'; Secure; HttpOnly; SameSite=Strict';}
export function readCookie(req,name){return (req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1)||'';}
export async function otpRpc(e,ip,action,challenge,code,fetcher=fetch){
 const h=hashes(e.secret,e.scope,challenge,code);
 const r=await fetcher(e.url+'/rest/v1/rpc/jarod_otp',{method:'POST',headers:{apikey:e.key,...(e.key.startsWith('eyJ')?{Authorization:'Bearer '+e.key}:{}),'Content-Type':'application/json'},body:JSON.stringify({p_secret:e.secret,p_scope:e.scope,p_ip:mac(e.secret,'ip:'+ip),p_action:action,p_challenge:h.challenge,p_digest:h.digest}),cache:'no-store',signal:AbortSignal.timeout(5000),redirect:'error'});
 if(!r.ok)throw Error('OTP database unavailable');
 const x=await r.json();if(typeof x?.ok!=='boolean')throw Error('Invalid OTP response');return x;
}
export async function sendCode(e,code,fetcher=fetch){
 if(!/^\d{6}$/.test(code)||!/^\d+:[A-Za-z0-9_-]+$/.test(e.token||'')||!/^\d+$/.test(e.chat||''))throw Error('OTP configuration');
 const names={zforense:'zFORENSE',zcrlv:'zCRLV',zfinance:'zFINANCE'};
 if(!names[e.scope])throw Error('Unknown scope');
 const r=await fetcher('https://api.telegram.org/bot'+e.token+'/sendMessage',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chat_id:e.chat,text:names[e.scope]+' | Código de acesso\n\n'+code+'\n\nVálido por 5 minutos e de uso único. Se não solicitou, ignore. Não compartilhe o código.',protect_content:true}),redirect:'error',signal:AbortSignal.timeout(8000)});
 if(!r.ok||!(await r.json()).ok)throw Error('OTP delivery unavailable');
}
