'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const {isPrivateIp, validatePublicUrl, setCommonHeaders, readLimitedBuffer}=require('../api/_utils');
test('endereços reservados não são públicos',()=>{
 for(const ip of ['127.0.0.1','10.1.2.3','169.254.169.254','192.168.1.1','172.16.0.1','::1','fd00::1','::ffff:127.0.0.1'])assert.equal(isPrivateIp(ip),true,ip);
 assert.equal(isPrivateIp('8.8.8.8'),false);
});
test('validação rejeita URLs perigosas',async()=>{
 await assert.rejects(()=>validatePublicUrl('http://127.0.0.1/'),/bloqueado/);
 await assert.rejects(()=>validatePublicUrl('file:///etc/passwd'),/protocolos/);
 await assert.rejects(()=>validatePublicUrl('https://user:pass@example.com'),/Credenciais/);
});
test('CORS somente permite origem exata',()=>{
 const old=process.env.ALLOWED_ORIGIN;process.env.ALLOWED_ORIGIN='https://app.example.com';
 try{
  const h={},res={setHeader(k,v){h[k.toLowerCase()]=v;}};
  setCommonHeaders({headers:{origin:'https://app.example.com.evil.test'}},res);
  assert.equal(h['access-control-allow-origin'],undefined);
  setCommonHeaders({headers:{origin:'https://app.example.com'}},res);
  assert.equal(h['access-control-allow-origin'],'https://app.example.com');
 } finally {if(old===undefined)delete process.env.ALLOWED_ORIGIN;else process.env.ALLOWED_ORIGIN=old;}
});
test('limita resposta no streaming',async()=>{
 await assert.rejects(()=>readLimitedBuffer(new Response(new Uint8Array(12)),10),/Limite/);
 assert.equal((await readLimitedBuffer(new Response('hello'),10)).toString(),'hello');
});
