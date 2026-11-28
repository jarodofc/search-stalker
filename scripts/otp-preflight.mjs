import {newChallenge,newCode,otpRpc} from '../lib/otp.mjs';
async function main(){
 if(process.env.VERCEL_ENV!=='production'){console.log('OTP production check skipped outside production');return;}
 const e={secret:process.env.Z_GATE_SECRET,key:process.env.Z_GATE_API_KEY,url:process.env.Z_GATE_URL,scope:process.env.Z_GATE_SCOPE,token:process.env.Z_OTP_BOT_TOKEN,chat:process.env.Z_OTP_CHAT_ID};
 if(process.env.Z_OTP_ENABLED!=='true'||!e.secret||!e.key||!/^https:\/\/[a-z0-9-]+\.supabase\.co\/?$/.test(e.url||'')||!['zforense','zcrlv','zfinance'].includes(e.scope)||!/^\d+:[A-Za-z0-9_-]+$/.test(e.token||'')||!/^\d+$/.test(e.chat||''))throw Error('OTP configuration incomplete');
 e.url=e.url.replace(/\/$/,'');
 async function telegram(method,body){const r=await fetch('https://api.telegram.org/bot'+e.token+'/'+method,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(10000)});if(!r.ok)throw Error('Telegram API unavailable');const data=await r.json();if(!data.ok)throw Error('Telegram API rejected request');return data.result;}
 const bot=await telegram('getMe',{});if(bot.username?.toLowerCase()!=='mywebsrobot')throw Error('Wrong Telegram bot');
 const chat=await telegram('getChat',{chat_id:e.chat});if(chat.type!=='private'||String(chat.id)!==e.chat)throw Error('Wrong Telegram recipient');
 const c=newChallenge(),code=newCode(),ip='otp-production-preflight';
 const issue=await otpRpc(e,ip,'issue',c,code);if(!issue.ok)throw Error('OTP issuance blocked');
 const wrong=code==='000000'?'000001':'000000';
 if((await otpRpc(e,ip,'verify',c,wrong)).ok)throw Error('Invalid OTP accepted');
 if(!(await otpRpc(e,ip,'verify',c,code)).ok)throw Error('Correct OTP rejected');
 if((await otpRpc(e,ip,'verify',c,code)).ok)throw Error('Replayed OTP accepted');
 await telegram('sendMessage',{chat_id:e.chat,text:'JAROD.SYSTEM | '+e.scope.toUpperCase()+'\n\nTeste de entrega concluído. O banco validou a emissão, a rejeição de código incorreto e o uso único. Este aviso não é um código de acesso.',protect_content:true});
 console.log('OTP preflight: bot, private chat, database issuance, wrong-code rejection, one-time verification, replay rejection and Telegram delivery verified.');
}
main().catch(()=>{console.error('OTP preflight failed. Production deployment stopped.');process.exitCode=1;});
