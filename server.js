'use strict';
/**
 * ViCheck: passive, public-page audit only.
 * No credential use, no port scanning, no exploits, no storage of scan results.
 * Node >= 20. No runtime dependencies.
 */
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns').promises;
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 3000);
const MAX_BYTES = 850000;
const MAX_REDIRECTS = 3;
const MAX_ACTIVE = 4;
const buckets = new Map();
let active = 0;

const LAW = Object.freeze({
  privacy: { name: 'Luật Bảo vệ dữ liệu cá nhân 91/2025/QH15; NĐ 356/2025/NĐ-CP (cần đối chiếu phạm vi áp dụng)', url: 'https://vanban.chinhphu.vn/?classid=1&docid=214590&pageid=27160&typegroup=' },
  commerce: { name: 'Luật Thương mại điện tử 122/2025/QH15 (cần đối chiếu loại hình và nghĩa vụ)', url: 'https://vanban.chinhphu.vn/?classid=1&docid=216503&pageid=27160&typegroupid=3' },
  ai: { name: 'Bộ checklist minh bạch AI của dự án (cần xác minh theo trường hợp)', url: 'https://github.com/xulytiengviet/vicheck/blob/main/references/07-ai-transparency.md' }
});
function bad(message, code = 400) { const e = new Error(message); e.status = code; throw e; }
function publicIPv4(address) {
  const a = address.split('.').map(Number);
  if (a.length !== 4 || a.some(v => !Number.isInteger(v) || v < 0 || v > 255)) return false;
  const [x,y,z] = a;
  if ([0,10,127].includes(x) || x >= 224 || x === 255) return false;
  if (x === 169 && y === 254 || x === 172 && y >= 16 && y <= 31 ||
      x === 192 && (y === 168 || y === 0 && (z === 0 || z === 2) || y === 88 && z === 99) ||
      x === 100 && y >= 64 && y <= 127 || x === 198 && (y === 18 || y === 19 || y === 51 && z === 100) ||
      x === 203 && y === 0 && z === 113 || x === 192 && y === 0 && z === 2) return false;
  return true;
}
function publicIPv6(address) {
  const a = address.toLowerCase();
  if (a.includes('.') || a.startsWith('::ffff:')) return false; // no mapped IPv4
  if (!/^[23][0-9a-f]{0,3}:/.test(a)) return false; // global-unicast range only
  return !/^2001:(?:db8|0:|10:|20:)/.test(a);
}
function cleanUrl(input) {
  if (typeof input !== 'string' || input.length > 2048) bad('URL không hợp lệ hoặc quá dài.');
  let value = input.trim();
  if (!/^https?:\/\//i.test(value)) value = 'https://' + value;
  let u;
  try { u = new URL(value); } catch { bad('Không phân tích được URL.'); }
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) bad('Chỉ chấp nhận URL HTTP(S) công khai, không chứa tài khoản/mật khẩu.');
  if (u.port && !['80','443'].includes(u.port)) bad('Không quét cổng tùy chỉnh.');
  const host = u.hostname.toLowerCase().replace(/\.$/,'');
  if (!host || net.isIP(host) || /^\d+(?:\.\d+)*$/.test(host) ||
      !host.includes('.') || /(^|\.)((localhost)|(local)|(internal)|(test)|(invalid)|(example)|(onion))$/.test(host) ||
      /[^\x00-\x7f]/.test(host)) bad('Chỉ chấp nhận tên miền công khai, không chấp nhận IP hoặc địa chỉ mạng nội bộ.');
  u.hash = '';
  return u;
}
async function resolvePublic(u) {
  let addresses;
  try { addresses = await dns.lookup(u.hostname, { all:true, verbatim:true }); }
  catch { bad('Tên miền không phân giải được DNS.', 422); }
  if (!addresses.length || addresses.some(x => x.family === 4 ? !publicIPv4(x.address) : !publicIPv6(x.address)))
    bad('DNS trả về địa chỉ không công khai hoặc chưa được hỗ trợ.', 403);
  return addresses[0];
}
function oneRequest(u, address) {
  return new Promise((resolve, reject) => {
    const driver = u.protocol === 'https:' ? https : http;
    let finished = false;
    const done = (err, out) => { if (finished) return; finished = true; err ? reject(err) : resolve(out); };
    const req = driver.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method:'GET', timeout:10000, agent:false,
      lookup: (hostname, opts, cb) => cb(null, address.address, address.family),
      headers: { 'Accept':'text/html,application/xhtml+xml;q=0.9', 'User-Agent':'ViCheck-PassiveAudit/1.0 (+https://github.com/xulytiengviet/vicheck)' }
    }, res => {
      const chunks=[]; let bytes=0; let truncated=false;
      res.on('data', chunk => {
        const remain = MAX_BYTES - bytes;
        if (remain > 0) chunks.push(chunk.subarray(0, remain));
        bytes += chunk.length;
        if (bytes > MAX_BYTES) { truncated=true; res.destroy(); done(null, {status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8'),truncated}); }
      });
      res.on('end', () => done(null,{status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('utf8'),truncated}));
      res.on('error', err => { if (!finished) done(err); });
    });
    req.on('timeout', ()=>req.destroy(new Error('Website phản hồi quá chậm (10 giây).')));
    req.on('error', err=>done(err));
    req.end();
  });
}
async function download(input) {
  let u = cleanUrl(input);
  const base = u.hostname.replace(/^www\./,'');
  for (let i=0;i<=MAX_REDIRECTS;i++) {
    const address=await resolvePublic(u);
    let r;
    try { r=await oneRequest(u,address); } catch(e) { bad('Không truy cập được website: '+e.message, 502); }
    if ([301,302,303,307,308].includes(r.status) && r.headers.location) {
      if (i===MAX_REDIRECTS) bad('Website chuyển hướng quá nhiều lần.',422);
      const target = cleanUrl(new URL(r.headers.location,u).href);
      if (target.hostname.replace(/^www\./,'') !== base) bad('Website chuyển hướng sang tên miền khác: không tự động theo.',422);
      u=target;continue;
    }
    if (r.status < 200 || r.status >= 400) bad('Website trả về HTTP '+r.status+'. Chưa thể kết luận kiểm tra.',422);
    if (!/html/i.test(String(r.headers['content-type']||''))) bad('URL không trả về HTML; chưa thể kiểm tra bằng phương pháp này.',422);
    return {url:u.href,...r};
  }
  bad('Không thể tải website.',502);
}
function decode(x) {
  return String(x||'').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,'<').replace(/&gt;/gi,'>');
}
function strip(x) { return decode(x.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim()); }
function attribute(tag,key) {
  const m=tag.match(new RegExp('\\b'+key+'\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))','i'));
  return m ? decode(m[1]||m[2]||m[3]||'') : '';
}
function parsePage(r) {
  const html=r.body;
  const title=strip((html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)||[])[1]||'').slice(0,140);
  const forms=(html.match(/<form\b/gi)||[]).length;
  const inputs=[...html.matchAll(/<input\b[^>]*>/gi)].map(m=>m[0]);
  const personal=inputs.filter(t=>/^(email|tel|password|date)$/.test(attribute(t,'type')) || /(?:email|phone|mobile|sdt|ho.ten|full.?name)/i.test(attribute(t,'name'))).length;
  const password=inputs.some(t=>attribute(t,'type').toLowerCase()==='password');
  const scripts=[...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)')/gi)].map(m=>m[1]||m[2]);
  const trackingPattern=/(google-analytics|googletagmanager|facebook\.net\/.*fbevents|connect\.facebook\.net|analytics\.tiktok|hotjar|clarity\.ms|mixpanel|segment\.com|gtag\(|fbq\()/i;
  const trackers=[...new Set(scripts.filter(s=>trackingPattern.test(s)).map(s=>s.slice(0,120)))];
  if (trackingPattern.test(html.replace(/<script\b[^>]*\bsrc[^>]*>/gi,'')) && !trackers.length) trackers.push('Dấu hiệu mã theo dõi nội tuyến (cần xác minh)');
  const anchors=[...html.matchAll(/<a\b[^>]*>([\s\S]*?)<\/a>/gi)].slice(0,1000).map(m=>{
    const href=attribute(m[0].split('>')[0], 'href');
    let resolved='';
    try { const u=new URL(href,r.url); if(['https:','http:'].includes(u.protocol)) resolved=u.href; } catch {}
    return {text:strip(m[1]).slice(0,120), href:resolved};
  });
  const classify = (re) => anchors.filter(a=>re.test(a.text+' '+a.href)).slice(0,4);
  const privacy=classify(/(privacy|chinh.?sach.?bao.?mat|bao.?ve.?du.?lieu|quyen.?rieng.?tu|personal.?data)/i);
  const terms=classify(/(terms|dieu.?khoan|dieu.?kien|chinh.?sach.?ban|refund|return|doi.?tra)/i);
  const contacts=classify(/(contact|lien.?he|gioi.?thieu|about)/i);
  const text=strip(html).slice(0,110000);
  const commerce=/(\/checkout\b|\/cart\b|gio.?hang|them.?vao.?gio|mua.?ngay|thanh.?toan|checkout|add to cart)/i.test(html);
  const accounts=password || /(\/login\b|\/signin\b|\/register\b|dang.?nhap|dang.?ky.?tai.?khoan)/i.test(html);
  const ai=/(chatbot|tro.?ly.?ai|ai.?assistant|chat.?with.?ai|openai|anthropic|dialogflow)/i.test(html);
  const aiDisclosure=/(noi.?dung.?do.?ai|tao.?boi.?ai|bot.?tu.?dong|ai.generated|chatbot.?ai)/i.test(text);
  const cookieNotice=/(cookie.{0,35}(dong.?y|consent|chap.?nhan|tuy.?chon)|accept all cookies|quan.?ly.?cookie)/i.test(text);
  const h=r.headers;
  const setCookies=Array.isArray(h['set-cookie']) ? h['set-cookie'] : h['set-cookie'] ? [h['set-cookie']] : [];
  const securityHeaders={
    hsts:!!h['strict-transport-security'],csp:!!h['content-security-policy'],
    nosniff:/nosniff/i.test(String(h['x-content-type-options']||'')),
    frame:!!h['x-frame-options'] || /frame-ancestors/i.test(String(h['content-security-policy']||'')),
    referrer:!!h['referrer-policy'],
    cookieCount:setCookies.length, cookieWithoutSecure:setCookies.filter(x=>!/;\s*secure(?:;|$)/i.test(x)).length,
    cookieWithoutHttpOnly:setCookies.filter(x=>!/;\s*httponly(?:;|$)/i.test(x)).length
  };
  const level=commerce?2:accounts?3:(forms>0||personal>0||trackers.length||ai)?1:0;
  return {url:r.url,status:r.status,title,forms,personal,password,scripts:scripts.length,trackers,privacy,terms,contacts,commerce,accounts,ai,aiDisclosure,cookieNotice,headers:securityHeaders,level,truncated:r.truncated};
}
function makeFindings(p) {
  const findings=[];
  function add(tone,category,title,detail,fix,evidence,law){
    findings.push({id:'VC-'+String(findings.length+1).padStart(3,'0'),tone,category,title,detail,fix,evidence: evidence||'',law:law||null});
  }
  if (p.url.startsWith('https:')) add('green','Bảo mật','Website phản hồi qua HTTPS','Kết nối HTTPS được thiết lập thành công ở thời điểm quét.','Duy trì cấu hình TLS và gia hạn chứng thư.','URL: '+p.url);
  else add('blue','Bảo mật','Website đang sử dụng HTTP','Trang được truy cập không mã hóa; dữ liệu trao đổi có thể bị can thiệp trên đường truyền.','Triển khai HTTPS, điều hướng HTTP → HTTPS và kiểm tra chứng thư.','URL: '+p.url);
  const h=p.headers;
  const checks=[
    ['hsts','Strict-Transport-Security','Bật HSTS sau khi đã kiểm tra tất cả tên miền phụ.'],
    ['csp','Content-Security-Policy','Xây dựng CSP theo tài nguyên thực tế, ưu tiên report-only trước.'],
    ['nosniff','X-Content-Type-Options: nosniff','Thêm header X-Content-Type-Options: nosniff.'],
    ['frame','Chống nhúng trang (frame)','Thiết lập CSP frame-ancestors hoặc X-Frame-Options.'],
    ['referrer','Referrer-Policy','Thiết lập Referrer-Policy phù hợp, ví dụ strict-origin-when-cross-origin.']
  ];
  for(const [key,label,fix] of checks){
    if(key==='hsts' && !p.url.startsWith('https:')) continue;
    if(h[key]) add('green','Bảo mật',label+' được nhận diện','Header tương ứng xuất hiện trong phản hồi HTTP.','Kiểm tra giá trị và phạm vi chính sách trên hệ thống thật.','Response header: '+label);
    else add('blue','Bảo mật','Chưa thấy '+label,'Thiếu tín hiệu phòng vệ ở phản hồi trang chủ. Đây là khuyến nghị cấu hình, không tự chứng minh có lỗ hổng khai thác được.',fix,'Không tìm thấy header: '+label);
  }
  if(h.cookieCount){
    if(h.cookieWithoutSecure) add('blue','Bảo mật','Có cookie thiếu thuộc tính Secure',h.cookieWithoutSecure+'/'+h.cookieCount+' cookie trong phản hồi đầu tiên thiếu Secure.','Rà soát loại cookie; thêm Secure cho cookie truyền qua HTTPS.','Set-Cookie: thuộc tính, không hiển thị giá trị');
    if(h.cookieWithoutHttpOnly) add('blue','Bảo mật','Có cookie thiếu thuộc tính HttpOnly','Cookie truy cập được từ JavaScript có thể làm tăng tác động của XSS; cookie phục vụ client có thể cần ngoại lệ.','Rà soát cookie phiên/xác thực và đặt HttpOnly khi phù hợp.','Set-Cookie: thuộc tính, không hiển thị giá trị');
  }
  if(p.personal || p.forms){
    if(p.privacy.length) add('green','Dữ liệu cá nhân','Có liên kết chính sách quyền riêng tư','Phát hiện liên kết chính sách từ trang chủ; chưa xác nhận nội dung, cách xin đồng ý hoặc việc thực thi.','Đọc và đối chiếu toàn văn chính sách, quy trình thu thập và xử lý dữ liệu.',p.privacy[0].href,LAW.privacy);
    else add('red','Pháp lý','Có biểu mẫu nhưng chưa thấy chính sách quyền riêng tư','Website có dấu hiệu thu thập dữ liệu; không tìm thấy liên kết chính sách ở trang chủ. Có nguy cơ cần rà soát pháp lý, chưa đủ bằng chứng để kết luận vi phạm.','Bổ sung thông báo xử lý dữ liệu, mục đích, quyền của chủ thể và cơ chế đồng ý nếu áp dụng.','Form: '+p.forms+' · Input thông tin cá nhân: '+p.personal,LAW.privacy);
  } else if(p.privacy.length){
    add('green','Dữ liệu cá nhân','Có đường dẫn chính sách quyền riêng tư','Đã thấy liên kết công khai trên trang chủ.','Xem lại nội dung và tính phù hợp với hoạt động thực tế.',p.privacy[0].href,LAW.privacy);
  }
  if(p.trackers.length){
    if(!p.privacy.length) add('yellow','Dữ liệu cá nhân','Có tín hiệu theo dõi nhưng chưa thấy chính sách','Có dấu hiệu mã phân tích/tracking; việc có xử lý dữ liệu cá nhân hay yêu cầu đồng ý cần kiểm chứng.','Rà soát dữ liệu SDK thu thập; bổ sung thông báo và cơ chế lựa chọn nếu áp dụng.',p.trackers.join(' · '),LAW.privacy);
    if(!p.cookieNotice) add('yellow','Dữ liệu cá nhân','Chưa nhận diện cơ chế thông báo cookie/tracking','Không tìm thấy dấu hiệu banner quản lý cookie trong HTML tĩnh. Có thể giao diện được dựng động sau khi tải.','Kiểm tra thực tế bằng trình duyệt và đối chiếu yêu cầu xử lý dữ liệu theo trường hợp.',p.trackers.join(' · '),LAW.privacy);
    else add('green','Dữ liệu cá nhân','Có dấu hiệu giao diện cookie','Nhận diện nội dung quản lý cookie; chưa chứng minh cơ chế đồng ý hoạt động đúng.','Kiểm tra hành vi trước/sau đồng ý và khả năng rút lại.','Nội dung HTML trang chủ',LAW.privacy);
  }
  if(p.commerce){
    if(p.terms.length) add('green','Thương mại điện tử','Có đường dẫn điều khoản bán hàng','Tìm thấy liên kết điều khoản/chính sách bán hàng; cần kiểm tra nội dung.','Đối chiếu nghĩa vụ công khai thông tin, xử lý khiếu nại và quy trình giao dịch.',p.terms[0].href,LAW.commerce);
    else add('yellow','Thương mại điện tử','Có tín hiệu giao dịch nhưng chưa thấy điều khoản','Phát hiện từ khóa/đường dẫn mua hàng; có thể là nội dung minh họa.','Xác định site có bán hàng thực tế hay không, công khai điều khoản nếu thuộc diện áp dụng.','Tín hiệu checkout/cart trong HTML',LAW.commerce);
    if(!p.contacts.length) add('yellow','Thương mại điện tử','Chưa thấy liên kết liên hệ từ trang chủ','Có dấu hiệu thương mại nhưng chưa nhận diện đường dẫn liên hệ.','Bổ sung thông tin đơn vị bán hàng và kênh hỗ trợ phù hợp.','Không tìm thấy liên kết contact/liên hệ',LAW.commerce);
  }
  if(p.ai && !p.aiDisclosure) add('yellow','Minh bạch AI','Có dấu hiệu AI nhưng chưa thấy thông tin minh bạch','Từ khóa AI/chatbot có thể chỉ là nội dung giới thiệu; chưa xác minh hoạt động hệ thống.','Kiểm tra việc thông báo tương tác với AI và cách công bố nội dung do AI tạo khi có nghĩa vụ.','Từ khóa chatbot/AI trong HTML',LAW.ai);
  if(p.ai && p.aiDisclosure) add('green','Minh bạch AI','Có dấu hiệu công bố AI','Tìm thấy văn bản thông báo có liên quan AI.','Đối chiếu với chức năng AI đang vận hành.','Nội dung HTML trang chủ',LAW.ai);
  if(p.truncated) add('gray','Giới hạn kiểm tra','Trang quá lớn nên chỉ đọc phần đầu HTML','Kết quả có thể bỏ sót chính sách/liên kết nằm ở cuối trang.','Dùng công cụ phân tích mã nguồn để kiểm tra toàn diện.','Giới hạn '+MAX_BYTES+' byte');
  add('gray','Giới hạn kiểm tra','Chưa đánh giá được backend, dữ liệu và lỗ hổng khai thác','Audit thụ động trang công khai không kiểm tra API nội bộ, phiên đăng nhập, logic nghiệp vụ, mã JS tải động, chứng thư chi tiết hay nghĩa vụ pháp lý thực tế.','Kết hợp kiểm thử được ủy quyền, rà soát mã nguồn và tư vấn pháp lý.','Phạm vi: một HTML công khai cùng response headers');
  return findings;
}
function auditClass(p) {
  return p.commerce ? 'Website có dấu hiệu thương mại điện tử' : p.accounts ? 'Website có tài khoản' : p.forms || p.personal || p.trackers.length || p.ai ? 'Website có tương tác / thu thập nhẹ' : 'Website tĩnh hoặc chưa nhận diện tương tác';
}
function respond(res,status,payload,origin){
  if (origin && (/^https:\/\/xulytiengviet\.github\.io$/.test(origin) || /^http:\/\/localhost(?::\d+)?$/.test(origin) || /^http:\/\/127\.0\.0\.1(?::\d+)?$/.test(origin))) res.setHeader('Access-Control-Allow-Origin',origin);
  res.setHeader('Vary','Origin');
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
  res.end(JSON.stringify(payload));
}
function readBody(req) {
  return new Promise((resolve,reject)=>{
    let body='';req.setEncoding('utf8');
    req.on('data', s=>{body+=s;if(body.length>4096){reject(new Error('Yêu cầu quá dài.'));req.destroy();}});
    req.on('end',()=>resolve(body)); req.on('error',reject);
  });
}
const server=http.createServer(async(req,res)=>{
  const origin=String(req.headers.origin||'');
  const route=(req.url||'/').split('?')[0];
  if(req.method==='OPTIONS' && route==='/api/audit') {
    if (/^https:\/\/xulytiengviet\.github\.io$/.test(origin) || /^http:\/\/(localhost|127\.0\.0\.1)(?::\d+)?$/.test(origin)) {
      res.writeHead(204,{'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Methods':'POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type','Vary':'Origin'});res.end();return;
    } return respond(res,403,{error:'Origin không được phép.'},origin);
  }
  if(req.method==='GET' && route==='/health') return respond(res,200,{ok:true,service:'vicheck',version:'1.0.0'},origin);
  if(req.method==='POST' && route==='/api/audit') {
    const ip=String(req.socket.remoteAddress||'anonymous'); const now=Date.now();
    for(const [k,v] of buckets) if(now-v.since>60000) buckets.delete(k);
    const bucket=buckets.get(ip)||{since:now,count:0}; bucket.count++;buckets.set(ip,bucket);
    if(bucket.count>8) return respond(res,429,{error:'Vượt giới hạn 8 lần quét/phút. Hãy thử lại sau.'},origin);
    if(active>=MAX_ACTIVE) return respond(res,503,{error:'Máy chủ đang bận. Vui lòng thử lại.'},origin);
    active++;
    try {
      const raw=await readBody(req);
      let input;try{input=JSON.parse(raw);}catch{bad('JSON không hợp lệ.');}
      const source=await download(input.url);
      const observed=parsePage(source);
      const result={version:'1.0.0',checkedAt:new Date().toISOString(),classification:auditClass(observed),observed,findings:makeFindings(observed),
        disclaimer:'Rà soát tự động từ dữ liệu công khai; không phải chứng nhận an toàn, kết luận vi phạm pháp luật hoặc ý kiến tư vấn pháp lý.'};
      return respond(res,200,result,origin);
    } catch(e){return respond(res,e.status||502,{error:e.message||'Quét không thành công.'},origin);}
    finally { active--; }
  }
  if(req.method==='GET' && (route==='/'||route==='/index.html')) {
    const file=path.join(__dirname,'index.html');
    try {res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff'});
      fs.createReadStream(file).pipe(res);}catch{res.writeHead(500);res.end('index unavailable');}
    return;
  }
  if(req.method==='GET' && route==='/favicon.svg') {
    res.writeHead(200,{'Content-Type':'image/svg+xml','Cache-Control':'public, max-age=86400'});
    res.end('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="15" fill="#081222"/><path d="M32 9 50 16v14c0 12-7 20-18 25C21 50 14 42 14 30V16Z" stroke="#53e6bd" stroke-width="5" fill="none"/><path d="m23 31 6 6 13-15" fill="none" stroke="#53e6bd" stroke-width="5"/></svg>');return;
  }
  res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});res.end('Not found');
});
if(require.main===module) server.listen(PORT,'0.0.0.0',()=>console.log('ViCheck listening on '+PORT));
module.exports={cleanUrl,publicIPv4,publicIPv6,parsePage,makeFindings,server};
