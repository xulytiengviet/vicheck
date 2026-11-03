'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {cleanUrl, publicIPv4, publicIPv6, parsePage, makeFindings} = require('../server.js');
test('accept ordinary HTTPS hostname',()=>{
  assert.equal(cleanUrl('https://example.com/a?b=1').hostname,'example.com');
  assert.equal(cleanUrl('example.com').protocol,'https:');
});
test('reject local and dangerous URLs',()=>{
 for(const url of ['http://localhost/','http://127.0.0.1/','http://10.0.0.1/','http://[::1]/','file:///etc/passwd','https://admin:password@example.com','http://test.local','https://example.com:8080/']) {
   assert.throws(()=>cleanUrl(url),url);
 }
});
test('reject private/reserved IPs',()=>{
 for(const address of ['127.0.0.1','10.0.0.1','172.16.1.2','192.168.1.1','169.254.2.2','100.100.2.1','203.0.113.10']) assert.equal(publicIPv4(address),false,address);
 assert.equal(publicIPv4('8.8.8.8'),true);
 for(const address of ['::1','fe80::1','fc00::1','::ffff:127.0.0.1']) assert.equal(publicIPv6(address),false);
 assert.equal(publicIPv6('2606:4700:4700::1111'),true);
});
test('detect website categories and security findings',()=>{
 const sample={url:'https://example.com',status:200,truncated:false,headers:{'content-type':'text/html','x-content-type-options':'nosniff'},
 body:'<html><title>Demo</title><form><input type="email" name="email"></form><script src="https://www.googletagmanager.com/gtag/js?id=1"></script></html>'};
 const p=parsePage(sample); assert.equal(p.forms,1);assert.equal(p.personal,1);assert.equal(p.privacy.length,0);
 const f=makeFindings(p);assert.ok(f.some(x=>x.tone==='red'));assert.ok(f.some(x=>x.tone==='blue'));assert.ok(f.some(x=>x.tone==='green'));
});
