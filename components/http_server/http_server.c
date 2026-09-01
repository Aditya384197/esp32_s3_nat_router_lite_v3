#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <errno.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_https_server.h"
#include "esp_http_server.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "router_config.h"
#include "wifi_config.h"
#include "http_server.h"

extern esp_netif_t *wifiAP;
extern esp_netif_t *wifiSTA;
extern void router_reconnect_uplink(void);
extern esp_err_t router_apply_ap_config(void);
extern const uint8_t server_cert_pem_start[] asm("_binary_server_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_server_cert_pem_end");
extern const uint8_t server_key_pem_start[] asm("_binary_server_key_pem_start");
extern const uint8_t server_key_pem_end[] asm("_binary_server_key_pem_end");

static const char *TAG = "http_server";
static volatile bool dns_started = false;
static portMUX_TYPE ap_apply_mux = portMUX_INITIALIZER_UNLOCKED;
static bool ap_apply_pending = false;
static bool ap_apply_dirty = false;

#define AUTH_SESSION_MAX 4
#define AUTH_TOKEN_BYTES 32
#define AUTH_CSRF_BYTES 16
#define AUTH_IDLE_US (15LL * 60LL * 1000000LL)
#define AUTH_ABSOLUTE_US (8LL * 60LL * 60LL * 1000000LL)
/* 600,000 PBKDF2-SHA256 iterations is OWASP's number for a modern
 * server CPU (~100-300ms there). On a 240MHz MCU - even with hardware
 * SHA acceleration - that realistically costs multiple seconds, which
 * would turn every single login into a multi-second freeze. Instead
 * of guessing a fixed count for this chip, measure its real hashing
 * speed once and pick a count that targets a fixed, tolerable
 * wall-clock cost. This is standard practice for password hashing on
 * constrained hardware (the cost factor is calibrated to the device,
 * not copied from server-class guidance). The resulting iteration
 * count is stored alongside the hash it created (admin_iters) -
 * verification always replays that exact stored count, never a fresh
 * recalibration, or a correct password would stop matching its own
 * hash after a firmware/hardware change shifted the calibration. */
#define AUTH_PBKDF2_TARGET_MS 350U
#define AUTH_PBKDF2_MIN_ITERS 50000U
#define AUTH_PBKDF2_MAX_ITERS 300000U
#define AUTH_PBKDF2_CALIB_ITERS 15000U
#define AUTH_FAIL_SLOTS 16
#define AUTH_BLOCK_AFTER 6U
#define AUTH_BLOCK_US (60LL * 1000000LL)
/* Base blocked-state duration escalates from here (doubling per failure
 * past AUTH_BLOCK_AFTER) up to this cap - without a cap, the original
 * version reset to a flat 60s on every failure past the threshold, so a
 * sustained attacker could settle into ~1 guess/60s forever. Escalating
 * further, matched to our other build's cap, makes sustained attempts
 * cost progressively more instead of plateauing. */
#define AUTH_BLOCK_MAX_US (300LL * 1000000LL)
#define AUTH_MAX_BODY 384

typedef struct { bool used; uint8_t token[AUTH_TOKEN_BYTES]; uint8_t csrf[AUTH_CSRF_BYTES]; uint32_t ip; int64_t created_us; int64_t last_use_us; char user[33]; } auth_session_t;
typedef struct { bool used; uint32_t ip; uint16_t fails; int64_t next_allowed_us; int64_t blocked_until_us; } auth_rl_t;
static auth_session_t sessions[AUTH_SESSION_MAX];
static auth_rl_t rate_slots[AUTH_FAIL_SLOTS];
static portMUX_TYPE auth_mux = portMUX_INITIALIZER_UNLOCKED;
static bool bootstrap_in_progress = false;
static SemaphoreHandle_t auth_hash_sem = NULL;

static const char INDEX_HTML[] =
"<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\"><meta name=\"referrer\" content=\"no-referrer\"><title>ESP32-S3 NAT Router</title><style>*{box-sizing:border-box}html,body{margin:0;height:100%;font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#080d15;color:#edf3fb}body{overflow:hidden}.start{height:100svh;display:grid;grid-template-rows:50% 50%;padding:10px;gap:10px}.panel{min-height:0;border:1px solid #263449;border-radius:15px;padding:15px;background:#101925;overflow:auto}.status{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.stat{padding:9px;border:1px solid #263348;border-radius:9px;background:#0b121d}.k{font-size:10px;color:#7f8da5}.v{font-size:14px;font-weight:700;margin-top:3px;word-break:break-word}h1{font-size:17px;margin:0 0 9px}h2{font-size:12px;text-transform:uppercase;color:#8c9ab0;letter-spacing:1px;margin:0 0 9px}label{display:block;font-size:11px;color:#9aa8bd;margin:8px 0 4px}input{width:100%;padding:10px;border:1px solid #2b3a51;background:#0a111c;color:#edf3fb;border-radius:9px}button{width:100%;margin-top:8px;padding:10px;border:0;border-radius:9px;background:#8fe7ff;color:#061019;font-weight:700}button.alt{background:#182437;color:#edf3fb;border:1px solid #2b3a51}.row{display:flex;gap:8px}.row>*{flex:1}.msg{min-height:17px;font-size:11px;color:#91a2bb;margin-top:6px}.ok{color:#65e6a1}.err{color:#ff8ca0}.netlist{max-height:190px;overflow:auto}.net{padding:7px;border-bottom:1px solid #243149;font-size:12px}.net button{width:auto;padding:4px 8px;margin:0 0 0 6px;font-size:10px}.secure{height:100svh;padding:10px;overflow:auto;display:none}.box{max-width:720px;margin:auto}.foot{font-size:10px;color:#60708a;text-align:center;margin-top:8px}.tag{font-size:10px;padding:3px 7px;border-radius:99px;background:#172237;color:#a8bad2}</style></head><body><div id=\"start\" class=\"start\"><section class=\"panel\"><h1>ESP32-S3 NAT Router</h1><div class=\"status\"><div class=\"stat\"><div class=\"k\">UPLINK</div><div class=\"v\" id=\"u\">-</div></div><div class=\"stat\"><div class=\"k\">IP</div><div class=\"v\" id=\"ip\">-</div></div><div class=\"stat\"><div class=\"k\">RSSI</div><div class=\"v\" id=\"rssi\">-</div></div><div class=\"stat\"><div class=\"k\">UPTIME</div><div class=\"v\" id=\"uptime\">-</div></div><div class=\"stat\"><div class=\"k\">DOWNLOADED</div><div class=\"v\" id=\"rx\">-</div></div><div class=\"stat\"><div class=\"k\">UPLOADED</div><div class=\"v\" id=\"tx\">-</div></div><div class=\"stat\"><div class=\"k\">CLIENTS</div><div class=\"v\" id=\"clients\">-</div></div><div class=\"stat\"><div class=\"k\">AP</div><div class=\"v\" id=\"ap\">-</div></div><div class=\"stat\"><div class=\"k\">FREE HEAP</div><div class=\"v\" id=\"heap\">-</div></div></div></section><section class=\"panel\"><div style=\"height:100%;display:flex;flex-direction:column;justify-content:center;max-width:430px;margin:auto\"><h2 id=\"authTitle\">Admin sign in</h2><div id=\"authHint\" class=\"msg\">Secure management access</div><label>Username</label><input id=\"user\" maxlength=\"32\" autocomplete=\"username\"><label>Password</label><input id=\"pw\" type=\"password\" maxlength=\"63\" autocomplete=\"current-password\"><button id=\"loginBtn\" onclick=\"login()\">Sign in</button><div id=\"loginMsg\" class=\"msg\"></div><div class=\"foot\">HTTPS management only. NAT forwarding does not pass through authentication.</div></div></section></div><div id=\"secure\" class=\"secure\"><div class=\"box\"><section class=\"panel\"><h2 style=\"margin:0 0 9px\">Live Status</h2><div class=\"status\"><div class=\"stat\"><div class=\"k\">UPLINK</div><div class=\"v\" id=\"s_u\">-</div></div><div class=\"stat\"><div class=\"k\">IP</div><div class=\"v\" id=\"s_ip\">-</div></div><div class=\"stat\"><div class=\"k\">RSSI</div><div class=\"v\" id=\"s_rssi\">-</div></div><div class=\"stat\"><div class=\"k\">UPTIME</div><div class=\"v\" id=\"s_uptime\">-</div></div><div class=\"stat\"><div class=\"k\">DOWNLOADED</div><div class=\"v\" id=\"s_rx\">-</div></div><div class=\"stat\"><div class=\"k\">UPLOADED</div><div class=\"v\" id=\"s_tx\">-</div></div><div class=\"stat\"><div class=\"k\">CLIENTS</div><div class=\"v\" id=\"s_clients\">-</div></div><div class=\"stat\"><div class=\"k\">AP</div><div class=\"v\" id=\"s_ap\">-</div></div><div class=\"stat\"><div class=\"k\">FREE HEAP</div><div class=\"v\" id=\"s_heap\">-</div></div></div></section><section class=\"panel\"><div style=\"display:flex;justify-content:space-between;align-items:center\"><h1>Router controls</h1><span class=\"tag\" id=\"who\"></span></div><div class=\"row\"><button class=\"alt\" onclick=\"refreshStatus()\">Refresh status</button><button class=\"alt\" onclick=\"logout()\">Log out</button></div><h2 style=\"margin-top:14px\">Internet Uplink</h2><button class=\"alt\" onclick=\"scan()\">Scan Wi-Fi</button><div id=\"nets\" class=\"netlist\"></div><label>SSID</label><input id=\"ssid\" maxlength=\"32\" autocomplete=\"off\"><label>Password</label><input id=\"pass\" type=\"password\" maxlength=\"63\" autocomplete=\"off\"><button onclick=\"connectWifi()\">Connect / Save Uplink</button><div id=\"wm\" class=\"msg\"></div><h2 style=\"margin-top:16px\">Access Point</h2><label>AP SSID</label><input id=\"apssid\" maxlength=\"32\" autocomplete=\"off\"><label>AP password</label><input id=\"appass\" type=\"password\" maxlength=\"63\" autocomplete=\"off\"><button onclick=\"saveAP()\">Save AP</button><div id=\"am\" class=\"msg\"></div><h2 style=\"margin-top:16px\">Admin credentials</h2><label>Username</label><input id=\"newuser\" maxlength=\"32\" autocomplete=\"username\"><label>New password</label><input id=\"newpass\" type=\"password\" maxlength=\"63\" autocomplete=\"new-password\"><button onclick=\"changeAdmin()\">Change credentials</button><div id=\"cm\" class=\"msg\"></div></section></div></div><script>const $=id=>document.getElementById(id);let csrf='';let authed=false;let configured=false;let apInit=false;async function api(u,o){o=o||{};o.credentials='same-origin';o.headers=o.headers||{};if(csrf)o.headers['X-CSRF-Token']=csrf;const r=await fetch(u,o);let x={};try{x=await r.json()}catch(e){}if(r.status===401){authed=false;showLogin();throw Error('Authentication required')}if(r.status===429)throw Error('Temporarily rate limited');if(!r.ok)throw Error(x.message||'Request failed');return x}function showLogin(){$('secure').style.display='none';$('start').style.display='grid'}function showSecure(x){authed=true;csrf=x.csrf||'';apInit=false;$('start').style.display='none';$('secure').style.display='block';$('who').textContent=x.user||'';refreshStatus()}async function refreshAuth(){try{const x=await api('/api/auth');configured=!!x.configured;if(x.authenticated){showSecure(x)}else{showLogin();$('authTitle').textContent=configured?'Admin sign in':'Create admin account';$('authHint').textContent=configured?'HTTPS management access':'First boot: create the administrator account';$('loginBtn').textContent=configured?'Sign in':'Create admin account';$('pw').autocomplete=configured?'current-password':'new-password'}}catch(e){}}function setText(id,val){const el=$(id);if(el)el.textContent=val}async function refreshStatus(){try{const x=await api('/api/status');for(const p of ['','s_']){setText(p+'u',x.uplink);setText(p+'ip',x.ip);setText(p+'rssi',x.rssi+' dBm');setText(p+'uptime',x.uptime);setText(p+'rx',x.rx);setText(p+'tx',x.tx);setText(p+'clients',x.clients);setText(p+'ap',x.ap_ssid);setText(p+'heap',x.heap_free_kb+' KB (min '+x.heap_min_kb+')')}if(authed&&!apInit){$('apssid').value=x.ap_ssid;apInit=true}}catch(e){}}async function login(){const u=$('user').value.trim(),p=$('pw').value;if(!u||!p||p.length<12){$('loginMsg').textContent='Enter a username and a password of at least 12 characters';return}$('loginBtn').disabled=true;try{const x=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({user:u,pass:p})});$('loginMsg').textContent='';$('pw').value='';showSecure(x)}catch(e){$('loginMsg').textContent='Unable to sign in'}finally{$('loginBtn').disabled=false}}async function logout(){try{await api('/api/logout',{method:'POST'})}catch(e){}csrf='';authed=false;apInit=false;showLogin();refreshAuth()}async function scan(){try{const x=await api('/api/scan',{method:'POST'});$('nets').innerHTML=x.networks.map(n=>n.hidden?'<div class=\"net\">Hidden network ('+n.rssi+' dBm) — enter SSID manually</div>':'<div class=\"net\"><span>'+esc(n.ssid)+'</span> <span>'+n.rssi+' dBm</span><button class=\"pick\" data-s=\"'+encodeURIComponent(n.ssid)+'\">Use</button></div>').join('')||'<div class=\"msg\">No networks found</div>';document.querySelectorAll('.pick').forEach(b=>b.onclick=()=>pick(decodeURIComponent(b.dataset.s)))}catch(e){$('nets').textContent=e.message}}function pick(s){$('ssid').value=s;$('pass').focus()}async function connectWifi(){try{const x=await api('/api/connect',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({ssid:$('ssid').value.trim(),pass:$('pass').value})});$('wm').textContent=x.message;setTimeout(refreshStatus,1000)}catch(e){$('wm').textContent=e.message}}async function saveAP(){try{const x=await api('/api/ap',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({ssid:$('apssid').value.trim(),pass:$('appass').value})});$('am').textContent=x.message}catch(e){$('am').textContent=e.message}}async function changeAdmin(){const u=$('newuser').value.trim(),p=$('newpass').value;if(!u||p.length<12){$('cm').textContent='Username required; password must be at least 12 characters';return}try{const x=await api('/api/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({user:u,pass:p})});$('cm').textContent=x.message;csrf=x.csrf||'';$('newpass').value='';configured=true}catch(e){$('cm').textContent=e.message}}function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;')}refreshAuth();setInterval(refreshStatus,3000);</script></body></html>";

static bool ct_bytes(const uint8_t *a,const uint8_t *b,size_t n){uint8_t d=0;for(size_t i=0;i<n;i++)d|=(uint8_t)(a[i]^b[i]);return d==0;}
static void hex_encode(const uint8_t *in,size_t n,char *out){static const char h[]="0123456789abcdef";for(size_t i=0;i<n;i++){out[i*2]=h[in[i]>>4];out[i*2+1]=h[in[i]&15];}out[n*2]=0;}
static int hex_nibble(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static bool hex_decode(const char *in,uint8_t *out,size_t n){for(size_t i=0;i<n;i++){int hi=hex_nibble(in[i*2]),lo=hex_nibble(in[i*2+1]);if(hi<0||lo<0)return false;out[i]=(uint8_t)((hi<<4)|lo);}return true;}
static bool pbkdf2_sha256(const char *pw,const uint8_t *salt,size_t slen,uint8_t out[32],uint32_t iters)
{
    if(!pw||!salt||!out||iters==0)return false;
    const mbedtls_md_info_t *md=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if(!md)return false;
    const size_t hlen=32;
    uint8_t u[32],t[32];
    uint8_t block[20];
    if(slen+4>sizeof(block))return false;
    memcpy(block,salt,slen);
    block[slen]=0;block[slen+1]=0;block[slen+2]=0;block[slen+3]=1;
    int rc=mbedtls_md_hmac(md,(const unsigned char*)pw,strlen(pw),block,slen+4,u);
    if(rc!=0){memset(u,0,sizeof(u));memset(t,0,sizeof(t));return false;}
    memcpy(t,u,hlen);
    for(uint32_t i=1;i<iters;i++){
        rc=mbedtls_md_hmac(md,(const unsigned char*)pw,strlen(pw),u,hlen,u);
        if(rc!=0){memset(u,0,sizeof(u));memset(t,0,sizeof(t));return false;}
        for(size_t j=0;j<hlen;j++)t[j]^=u[j];
    }
    memcpy(out,t,hlen);
    memset(u,0,sizeof(u));memset(t,0,sizeof(t));memset(block,0,sizeof(block));
    return true;
}
static uint32_t calibrate_pbkdf2_iterations(void){uint8_t dummy_salt[16]={0};uint8_t out[32];int64_t t0=esp_timer_get_time();bool ok=pbkdf2_sha256("calibration",dummy_salt,sizeof(dummy_salt),out,AUTH_PBKDF2_CALIB_ITERS);int64_t elapsed=esp_timer_get_time()-t0;memset(out,0,sizeof(out));if(!ok||elapsed<=0)return AUTH_PBKDF2_MIN_ITERS;double iters_per_us=(double)AUTH_PBKDF2_CALIB_ITERS/(double)elapsed;double target=iters_per_us*(double)AUTH_PBKDF2_TARGET_MS*1000.0;uint32_t iters=(uint32_t)target;if(iters<AUTH_PBKDF2_MIN_ITERS)iters=AUTH_PBKDF2_MIN_ITERS;if(iters>AUTH_PBKDF2_MAX_ITERS)iters=AUTH_PBKDF2_MAX_ITERS;return iters;}
static bool auth_hash_acquire(void){return auth_hash_sem&&xSemaphoreTake(auth_hash_sem,pdMS_TO_TICKS(10000))==pdTRUE;}
static void auth_hash_release(void){if(auth_hash_sem)(void)xSemaphoreGive(auth_hash_sem);}
static uint32_t peer_ip(httpd_req_t *req){int fd=httpd_req_to_sockfd(req);struct sockaddr_in sa={0};socklen_t sl=sizeof(sa);if(fd>=0&&getpeername(fd,(struct sockaddr*)&sa,&sl)==0)return sa.sin_addr.s_addr;return 0;}
static bool cookie_get(httpd_req_t *req,const char *name,char *out,size_t cap){char h[192];if(httpd_req_get_hdr_value_str(req,"Cookie",h,sizeof(h))!=ESP_OK)return false;size_t nl=strlen(name);char *p=h;while(p){while(*p==' ')p++;if(strncmp(p,name,nl)==0&&p[nl]=='='){p+=nl+1;char *e=strchr(p,';');size_t n=e?(size_t)(e-p):strlen(p);if(n>=cap)return false;memcpy(out,p,n);out[n]=0;return true;}p=strchr(p,';');if(p)p++;}return false;}
static bool session_auth(httpd_req_t *req,uint8_t csrf[AUTH_CSRF_BYTES],char *user,size_t user_cap){char c[65];uint8_t tok[AUTH_TOKEN_BYTES];uint32_t ip=peer_ip(req);if(!cookie_get(req,"__Host-session",c,sizeof(c))||strlen(c)!=64||!hex_decode(c,tok,sizeof(tok)))return false;int64_t now=esp_timer_get_time();bool ok=false;portENTER_CRITICAL(&auth_mux);for(int i=0;i<AUTH_SESSION_MAX;i++){if(sessions[i].used&&sessions[i].ip==ip&&ct_bytes(tok,sessions[i].token,sizeof(tok))){if(now-sessions[i].last_use_us<=AUTH_IDLE_US&&now-sessions[i].created_us<=AUTH_ABSOLUTE_US){sessions[i].last_use_us=now;memcpy(csrf,sessions[i].csrf,sizeof(sessions[i].csrf));strlcpy(user,sessions[i].user,user_cap);ok=true;}else{memset(&sessions[i],0,sizeof(sessions[i]));}}}portEXIT_CRITICAL(&auth_mux);memset(tok,0,sizeof(tok));return ok;}
static bool csrf_ok(httpd_req_t *req,const uint8_t expected[AUTH_CSRF_BYTES]){char h[40];uint8_t got[AUTH_CSRF_BYTES];if(httpd_req_get_hdr_value_str(req,"X-CSRF-Token",h,sizeof(h))!=ESP_OK||strlen(h)!=32||!hex_decode(h,got,sizeof(got)))return false;bool ok=ct_bytes(got,expected,sizeof(got));memset(got,0,sizeof(got));return ok;}
static bool origin_ok(httpd_req_t *req){char h[160];if(httpd_req_get_hdr_value_str(req,"Origin",h,sizeof(h))!=ESP_OK)return true;return strcmp(h,"https://192.168.4.1")==0||strcmp(h,"https://router.local")==0;}
static bool rate_allowed(uint32_t ip){int64_t now=esp_timer_get_time();bool ok=true;portENTER_CRITICAL(&auth_mux);for(int i=0;i<AUTH_FAIL_SLOTS;i++){if(rate_slots[i].used&&rate_slots[i].ip==ip){ok=!(now<rate_slots[i].blocked_until_us||now<rate_slots[i].next_allowed_us);break;}}portEXIT_CRITICAL(&auth_mux);return ok;}
static void rate_failure(uint32_t ip){int64_t now=esp_timer_get_time();portENTER_CRITICAL(&auth_mux);int slot=-1;for(int i=0;i<AUTH_FAIL_SLOTS;i++)if(rate_slots[i].used&&rate_slots[i].ip==ip){slot=i;break;}if(slot<0){for(int i=0;i<AUTH_FAIL_SLOTS;i++)if(!rate_slots[i].used){slot=i;break;}if(slot<0)slot=0;memset(&rate_slots[slot],0,sizeof(rate_slots[slot]));rate_slots[slot].used=true;rate_slots[slot].ip=ip;}if(rate_slots[slot].fails<UINT16_MAX)rate_slots[slot].fails++;uint32_t e=rate_slots[slot].fails>5?5:rate_slots[slot].fails;rate_slots[slot].next_allowed_us=now+((int64_t)250000<<e);if(rate_slots[slot].fails>=AUTH_BLOCK_AFTER){uint32_t over=rate_slots[slot].fails-AUTH_BLOCK_AFTER;uint32_t shift=over>6?6:over;int64_t escalated=AUTH_BLOCK_US<<shift;if(escalated>AUTH_BLOCK_MAX_US||escalated<0)escalated=AUTH_BLOCK_MAX_US;rate_slots[slot].blocked_until_us=now+escalated;}portEXIT_CRITICAL(&auth_mux);}
static void rate_success(uint32_t ip){portENTER_CRITICAL(&auth_mux);for(int i=0;i<AUTH_FAIL_SLOTS;i++)if(rate_slots[i].used&&rate_slots[i].ip==ip){memset(&rate_slots[i],0,sizeof(rate_slots[i]));break;}portEXIT_CRITICAL(&auth_mux);}

static bool read_form(httpd_req_t *req,const char *f1,char *o1,size_t n1,const char *f2,char *o2,size_t n2){ int len=req->content_len; if(len<=0||len>AUTH_MAX_BODY)return false; char body[AUTH_MAX_BODY+1];int got=0;int64_t deadline=esp_timer_get_time()+5000000;while(got<len){if(esp_timer_get_time()>deadline)return false;int n=httpd_req_recv(req,body+got,len-got);if(n==HTTPD_SOCK_ERR_TIMEOUT)continue;if(n<=0)return false;got+=n;}body[len]=0;bool a=false,b=false;char *save=NULL;for(char *p=strtok_r(body,"&",&save);p;p=strtok_r(NULL,"&",&save)){char *eq=strchr(p,'=');if(!eq)continue;*eq=0;char *dst=NULL;size_t cap=0;bool *have=NULL;if(strcmp(p,f1)==0){dst=o1;cap=n1;have=&a;}else if(strcmp(p,f2)==0){dst=o2;cap=n2;have=&b;}else continue;size_t w=0;const char *v=eq+1;for(size_t i=0;v[i];i++){if(w+1>=cap)return false;if(v[i]=='+')dst[w++]=' ';else if(v[i]=='%'&&v[i+1]&&v[i+2]){int hi=hex_nibble(v[i+1]),lo=hex_nibble(v[i+2]);if(hi<0||lo<0)return false;dst[w++]=(char)((hi<<4)|lo);i+=2;}else dst[w++]=v[i];}dst[w]=0;*have=true;}return a&&b;}

static size_t json_escape_local(const char *in,char *out,size_t cap){size_t w=0;for(size_t i=0;in&&in[i]&&w+1<cap;i++){unsigned char c=(unsigned char)in[i];if(c=='"'||c=='\\'){if(w+2>=cap)break;out[w++]='\\';out[w++]=(char)c;}else if(c<0x20){if(w+6>=cap)break;snprintf(out+w,cap-w,"\\u%04x",c);w+=6;}else out[w++]=(char)c;}out[w]=0;return w;}
static void security_headers(httpd_req_t *req){httpd_resp_set_hdr(req,"Cache-Control","no-store");httpd_resp_set_hdr(req,"X-Content-Type-Options","nosniff");httpd_resp_set_hdr(req,"X-Frame-Options","DENY");httpd_resp_set_hdr(req,"Referrer-Policy","no-referrer");httpd_resp_set_hdr(req,"Permissions-Policy","camera=(),microphone=(),geolocation=()");httpd_resp_set_hdr(req,"Cross-Origin-Resource-Policy","same-origin");httpd_resp_set_hdr(req,"Cross-Origin-Opener-Policy","same-origin");httpd_resp_set_hdr(req,"Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");httpd_resp_set_hdr(req,"Strict-Transport-Security","max-age=31536000; includeSubDomains");}
static void json_error(httpd_req_t *req,const char *status,const char *msg){char b[192];snprintf(b,sizeof(b),"{\"ok\":false,\"message\":\"%s\"}",msg);security_headers(req);httpd_resp_set_type(req,"application/json");httpd_resp_set_status(req,status);httpd_resp_sendstr(req,b);}

static esp_err_t index_handler(httpd_req_t *req){security_headers(req);httpd_resp_set_type(req,"text/html; charset=utf-8");return httpd_resp_send(req,INDEX_HTML,HTTPD_RESP_USE_STRLEN);}
static esp_err_t status_handler(httpd_req_t *req){char uptime[32];format_uptime(get_uptime_seconds(),uptime,sizeof(uptime));char ipbuf[16]="-";wifi_ap_record_t ap={0};int rssi=0;if(esp_wifi_sta_get_ap_info(&ap)==ESP_OK)rssi=ap.rssi;if(ap_connect)ip4addr_ntoa_r((const ip4_addr_t*)&my_ip,ipbuf,sizeof(ipbuf));wifi_config_lock();char apbuf[200];json_escape_local(ap_ssid,apbuf,sizeof(apbuf));wifi_config_unlock();uint32_t heap_free=(uint32_t)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)/1024);uint32_t heap_min=(uint32_t)(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL)/1024);uint32_t psram_free=(uint32_t)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM)/1024);char out[640];snprintf(out,sizeof(out),"{\"uplink\":\"%s\",\"ip\":\"%s\",\"rssi\":%d,\"uptime\":\"%s\",\"rx\":\"%.2f MB\",\"tx\":\"%.2f MB\",\"clients\":%u,\"ap_ssid\":\"%s\",\"heap_free_kb\":%lu,\"heap_min_kb\":%lu,\"psram_free_kb\":%lu}",ap_connect?"Connected":"Disconnected",ipbuf,rssi,uptime,(double)get_sta_bytes_received()/1048576.0,(double)get_sta_bytes_sent()/1048576.0,connect_count,apbuf,(unsigned long)heap_free,(unsigned long)heap_min,(unsigned long)psram_free);security_headers(req);httpd_resp_set_type(req,"application/json");return httpd_resp_sendstr(req,out);}
static esp_err_t auth_state_handler(httpd_req_t *req){char user[33]="",ue[129]="",ch[33]="";uint8_t csrf[AUTH_CSRF_BYTES];bool ok=session_auth(req,csrf,user,sizeof(user));if(ok){hex_encode(csrf,sizeof(csrf),ch);json_escape_local(user,ue,sizeof(ue));}wifi_config_lock();bool configured=admin_pass&&admin_pass[0];wifi_config_unlock();char out[240];snprintf(out,sizeof(out),"{\"authenticated\":%s,\"configured\":%s,\"user\":\"%s\",\"csrf\":\"%s\"}",ok?"true":"false",configured?"true":"false",ue,ch);security_headers(req);httpd_resp_set_type(req,"application/json");return httpd_resp_sendstr(req,out);}
static int session_slot(void){int free_slot=-1;for(int i=0;i<AUTH_SESSION_MAX;i++)if(!sessions[i].used){free_slot=i;break;}if(free_slot>=0)return free_slot;int oldest=0;for(int i=1;i<AUTH_SESSION_MAX;i++)if(sessions[i].last_use_us<sessions[oldest].last_use_us)oldest=i;return oldest;}
static esp_err_t issue_session(httpd_req_t *req,const char *user){uint8_t tok[AUTH_TOKEN_BYTES],csrf[AUTH_CSRF_BYTES];esp_fill_random(tok,sizeof(tok));esp_fill_random(csrf,sizeof(csrf));char th[65],ch[33],ue[129];uint32_t ip=peer_ip(req);hex_encode(tok,sizeof(tok),th);hex_encode(csrf,sizeof(csrf),ch);json_escape_local(user,ue,sizeof(ue));int64_t now=esp_timer_get_time();portENTER_CRITICAL(&auth_mux);int i=session_slot();memset(&sessions[i],0,sizeof(sessions[i]));sessions[i].used=true;sessions[i].ip=ip;sessions[i].created_us=now;sessions[i].last_use_us=now;memcpy(sessions[i].token,tok,sizeof(tok));memcpy(sessions[i].csrf,csrf,sizeof(csrf));strlcpy(sessions[i].user,user,sizeof(sessions[i].user));portEXIT_CRITICAL(&auth_mux);char cookie[150];snprintf(cookie,sizeof(cookie),"__Host-session=%s; HttpOnly; Secure; SameSite=Strict; Max-Age=900; Path=/",th);httpd_resp_set_hdr(req,"Set-Cookie",cookie);char out[240];snprintf(out,sizeof(out),"{\"ok\":true,\"user\":\"%s\",\"csrf\":\"%s\"}",ue,ch);security_headers(req);httpd_resp_set_type(req,"application/json");memset(tok,0,sizeof(tok));memset(csrf,0,sizeof(csrf));return httpd_resp_sendstr(req,out);}
static bool verify_admin(const char *user,const char *pw){wifi_config_lock();char u[33],salthex[33],stored[65];uint32_t iters;strlcpy(u,admin_user?admin_user:"",sizeof(u));strlcpy(salthex,admin_salt?admin_salt:"",sizeof(salthex));strlcpy(stored,admin_pass?admin_pass:"",sizeof(stored));iters=admin_iters;wifi_config_unlock();if(!stored[0])return false;bool user_ok=(strlen(u)==strlen(user))&&ct_bytes((const uint8_t*)u,(const uint8_t*)user,strlen(u));if(strlen(salthex)==32&&strlen(stored)==64&&iters>0){uint8_t salt[16],expect[32],have[32];bool decoded=false,hash_ok=false;if(auth_hash_acquire()){decoded=hex_decode(salthex,salt,sizeof(salt))&&hex_decode(stored,have,sizeof(have));if(decoded&&pbkdf2_sha256(pw,salt,sizeof(salt),expect,iters))hash_ok=ct_bytes(expect,have,sizeof(have));auth_hash_release();}memset(salt,0,sizeof(salt));memset(expect,0,sizeof(expect));memset(have,0,sizeof(have));return user_ok&&hash_ok;}size_t n=strlen(pw),m=strlen(stored);return user_ok&&n==m&&ct_bytes((const uint8_t*)pw,(const uint8_t*)stored,n);}
static bool bootstrap_claim(void)
{
    bool claimed=false;
    portENTER_CRITICAL(&auth_mux);
    if(!bootstrap_in_progress){bootstrap_in_progress=true;claimed=true;}
    portEXIT_CRITICAL(&auth_mux);
    return claimed;
}

static void bootstrap_release(void)
{
    portENTER_CRITICAL(&auth_mux);
    bootstrap_in_progress=false;
    portEXIT_CRITICAL(&auth_mux);
}

static esp_err_t login_handler(httpd_req_t *req)
{
    uint32_t ip=peer_ip(req);
    if(!origin_ok(req)){json_error(req,"403 Forbidden","Request rejected");return ESP_OK;}
    if(!rate_allowed(ip)){json_error(req,"429 Too Many Requests","Try again later");return ESP_OK;}
    char u[33],p[64];
    if(!read_form(req,"user",u,sizeof(u),"pass",p,sizeof(p))){json_error(req,"400 Bad Request","Invalid request");return ESP_OK;}
    if(!u[0]||strlen(p)<12||strlen(p)>63){rate_failure(ip);json_error(req,"401 Unauthorized","Authentication failed");return ESP_OK;}

    if(!wifi_config_admin_configured()){
        if(!bootstrap_claim()){rate_failure(ip);json_error(req,"429 Too Many Requests","Try again later");return ESP_OK;}
        esp_err_t se=ESP_OK;
        uint8_t salt[16],hash[32];char sh[33],hh[65];esp_fill_random(salt,sizeof(salt));
        uint32_t iters=calibrate_pbkdf2_iterations();
        if(!auth_hash_acquire()) se=ESP_FAIL;
        else { if(!pbkdf2_sha256(p,salt,sizeof(salt),hash,iters))se=ESP_FAIL; auth_hash_release(); }
        if(se==ESP_OK){hex_encode(salt,sizeof(salt),sh);hex_encode(hash,sizeof(hash),hh);se=wifi_config_save_admin_hash(u,sh,hh,iters);}
        memset(salt,0,sizeof(salt));memset(hash,0,sizeof(hash));bootstrap_release();
        if(se!=ESP_OK){rate_failure(ip);json_error(req,"500 Internal Server Error","Credential setup failed");return ESP_OK;}
        rate_success(ip);
        return issue_session(req,u);
    }

    bool ok=verify_admin(u,p);
    if(!ok){rate_failure(ip);json_error(req,"401 Unauthorized","Authentication failed");return ESP_OK;}
    if(!wifi_config_admin_hashed()){
        uint8_t salt[16],hash[32];char sh[33],hh[65];esp_fill_random(salt,sizeof(salt));
        uint32_t iters=calibrate_pbkdf2_iterations();
        if(auth_hash_acquire()){if(pbkdf2_sha256(p,salt,sizeof(salt),hash,iters)){hex_encode(salt,sizeof(salt),sh);hex_encode(hash,sizeof(hash),hh);(void)wifi_config_save_admin_hash(u,sh,hh,iters);}auth_hash_release();}
        memset(salt,0,sizeof(salt));memset(hash,0,sizeof(hash));
    }
    rate_success(ip);
    return issue_session(req,u);
}
static bool require_session(httpd_req_t *req,bool need_csrf){uint8_t c[16];char user[33];if(!session_auth(req,c,user,sizeof(user))){json_error(req,"401 Unauthorized","Authentication required");return false;}if(need_csrf&&!csrf_ok(req,c)){json_error(req,"403 Forbidden","Request rejected");return false;}return true;}
static esp_err_t logout_handler(httpd_req_t *req)
{
    if(!origin_ok(req)){json_error(req,"403 Forbidden","Request rejected");return ESP_OK;}
    uint8_t csrf_value[AUTH_CSRF_BYTES];
    char user[33];
    if(!session_auth(req,csrf_value,user,sizeof(user))){json_error(req,"401 Unauthorized","Authentication required");return ESP_OK;}
    if(!csrf_ok(req,csrf_value)){json_error(req,"403 Forbidden","Request rejected");return ESP_OK;}
    char v[]="__Host-session=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/";
    httpd_resp_set_hdr(req,"Set-Cookie",v);
    portENTER_CRITICAL(&auth_mux);
    for(int i=0;i<AUTH_SESSION_MAX;i++)if(sessions[i].used&&strcmp(sessions[i].user,user)==0)memset(&sessions[i],0,sizeof(sessions[i]));
    portEXIT_CRITICAL(&auth_mux);
    memset(csrf_value,0,sizeof(csrf_value));
    security_headers(req);httpd_resp_set_type(req,"application/json");
    return httpd_resp_sendstr(req,"{\"ok\":true}");
}
static esp_err_t setup_handler(httpd_req_t *req)
{
    if(!origin_ok(req))return ESP_OK;
    if(!require_session(req,true))return ESP_OK;
    char u[33],p[64];
    if(!read_form(req,"user",u,sizeof(u),"pass",p,sizeof(p))||!u[0]||strlen(p)<12||strlen(p)>63){json_error(req,"400 Bad Request","Invalid credentials");return ESP_OK;}
    uint8_t salt[16],hash[32];char sh[33],hh[65];esp_fill_random(salt,sizeof(salt));
    uint32_t iters=calibrate_pbkdf2_iterations();
    if(!pbkdf2_sha256(p,salt,sizeof(salt),hash,iters)){memset(salt,0,sizeof(salt));memset(hash,0,sizeof(hash));json_error(req,"500 Internal Server Error","Credential setup failed");return ESP_OK;}
    hex_encode(salt,sizeof(salt),sh);hex_encode(hash,sizeof(hash),hh);memset(salt,0,sizeof(salt));memset(hash,0,sizeof(hash));
    if(wifi_config_save_admin_hash(u,sh,hh,iters)!=ESP_OK){json_error(req,"500 Internal Server Error","Credential setup failed");return ESP_OK;}
    portENTER_CRITICAL(&auth_mux);memset(sessions,0,sizeof(sessions));portEXIT_CRITICAL(&auth_mux);
    return issue_session(req,u);
}
static esp_err_t connect_handler(httpd_req_t *req){if(!origin_ok(req))return ESP_OK;if(!require_session(req,true))return ESP_OK;if(wifi_scan_is_active()){json_error(req,"409 Conflict","Wi-Fi scan is running");return ESP_OK;}char s[33],p[64];if(!read_form(req,"ssid",s,sizeof(s),"pass",p,sizeof(p))||wifi_config_save_sta(s,p)!=ESP_OK){json_error(req,"400 Bad Request","Invalid Wi-Fi settings");return ESP_OK;}router_reconnect_uplink();security_headers(req);httpd_resp_set_type(req,"application/json");return httpd_resp_sendstr(req,"{\"ok\":true,\"message\":\"Uplink saved; connecting...\"}");}
static void apply_ap_task(void *arg){(void)arg;for(;;){vTaskDelay(pdMS_TO_TICKS(1000));esp_err_t e=router_apply_ap_config();if(e!=ESP_OK)ESP_LOGE(TAG,"AP apply failed: %s",esp_err_to_name(e));portENTER_CRITICAL(&ap_apply_mux);if(ap_apply_dirty){ap_apply_dirty=false;portEXIT_CRITICAL(&ap_apply_mux);continue;}ap_apply_pending=false;portEXIT_CRITICAL(&ap_apply_mux);break;}vTaskDelete(NULL);}
static esp_err_t ap_handler(httpd_req_t *req){if(!origin_ok(req))return ESP_OK;if(!require_session(req,true))return ESP_OK;char s[33],p[64];if(!read_form(req,"ssid",s,sizeof(s),"pass",p,sizeof(p))||wifi_config_save_ap(s,p)!=ESP_OK){json_error(req,"400 Bad Request","Invalid AP settings");return ESP_OK;}bool make=false;portENTER_CRITICAL(&ap_apply_mux);if(ap_apply_pending)ap_apply_dirty=true;else{ap_apply_pending=true;make=true;}portEXIT_CRITICAL(&ap_apply_mux);if(make&&xTaskCreate(apply_ap_task,"apply_ap",3072,NULL,4,NULL)!=pdPASS){portENTER_CRITICAL(&ap_apply_mux);ap_apply_pending=false;ap_apply_dirty=false;portEXIT_CRITICAL(&ap_apply_mux);json_error(req,"500 Internal Server Error","AP settings saved but could not be applied");return ESP_OK;}security_headers(req);httpd_resp_set_type(req,"application/json");return httpd_resp_sendstr(req,"{\"ok\":true,\"message\":\"AP settings saved; reconnect with the new AP credentials\"}");}
static esp_err_t scan_handler(httpd_req_t *req){if(!origin_ok(req))return ESP_OK;if(!require_session(req,true))return ESP_OK;if(!wifi_scan_try_begin()){json_error(req,"409 Conflict","Scan already running");return ESP_OK;}wifi_scan_config_t cfg={0};cfg.show_hidden=true;cfg.scan_type=WIFI_SCAN_TYPE_ACTIVE;cfg.scan_time.active.min=100;cfg.scan_time.active.max=250;esp_err_t e=esp_wifi_scan_start(&cfg,true);if(e!=ESP_OK){wifi_scan_end();json_error(req,"500 Internal Server Error","Wi-Fi scan failed");return ESP_OK;}uint16_t count=0;esp_wifi_scan_get_ap_num(&count);if(count>32)count=32;wifi_ap_record_t *list=count?calloc(count,sizeof(*list)):NULL;if(count&&!list){wifi_scan_end();json_error(req,"500 Internal Server Error","Out of memory");return ESP_OK;}if(count)esp_wifi_scan_get_ap_records(&count,list);char *out=malloc(4096);if(!out){free(list);wifi_scan_end();json_error(req,"500 Internal Server Error","Out of memory");return ESP_OK;}size_t pos=(size_t)snprintf(out,4096,"{\"networks\":[");bool first=true;for(uint16_t i=0;i<count&&pos<3900;i++){if(list[i].ssid[0]==0){int n=snprintf(out+pos,4096-pos,"%s{\"ssid\":\"\",\"rssi\":%d,\"hidden\":true}",first?"":",",list[i].rssi);if(n<0||(size_t)n>=4096-pos)break;pos+=n;first=false;continue;}char esc[200];json_escape_local((const char*)list[i].ssid,esc,sizeof(esc));int n=snprintf(out+pos,4096-pos,"%s{\"ssid\":\"%s\",\"rssi\":%d,\"hidden\":false}",first?"":",",esc,list[i].rssi);if(n<0||(size_t)n>=4096-pos)break;pos+=n;first=false;}snprintf(out+pos,4096-pos,"]}");free(list);wifi_scan_end();security_headers(req);httpd_resp_set_type(req,"application/json");e=httpd_resp_send(req,out,HTTPD_RESP_USE_STRLEN);free(out);return e;}
static esp_err_t redirect_http(httpd_req_t *req){httpd_resp_set_status(req,"308 Permanent Redirect");httpd_resp_set_hdr(req,"Location","https://192.168.4.1/");httpd_resp_set_type(req,"text/plain");return httpd_resp_sendstr(req,"Use HTTPS");}
static TaskHandle_t dns_task_handle = NULL;

static void captive_dns_task(void *arg)
{
    (void)arg;

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        dns_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = htons(53);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        close(fd);
        dns_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint8_t query[512];
    uint8_t response[512];

    while (dns_task_handle != NULL) {
        struct sockaddr_in peer = {0};
        socklen_t peer_len = sizeof(peer);

        int n = recvfrom(fd, query, sizeof(query), 0,
                         (struct sockaddr *)&peer, &peer_len);

        if (n < 12) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                continue;
            }
            continue;
        }

        uint16_t flags = ((uint16_t)query[2] << 8) | query[3];
        uint16_t qdcount = ((uint16_t)query[4] << 8) | query[5];

        /* Ignore already-formed DNS responses and empty queries. */
        if ((flags & 0x8000U) != 0 || qdcount == 0) {
            continue;
        }

        size_t qend = 12;
        bool valid = true;

        for (uint16_t q = 0; q < qdcount; ++q) {
            while (qend < (size_t)n) {
                uint8_t label_len = query[qend++];

                if (label_len == 0) {
                    break;
                }

                /* Compression pointers are not valid inside this request parser. */
                if ((label_len & 0xC0U) != 0 ||
                    label_len > 63 ||
                    qend + label_len > (size_t)n) {
                    valid = false;
                    break;
                }

                qend += label_len;
            }

            if (!valid || qend + 4 > (size_t)n) {
                valid = false;
                break;
            }

            qend += 4; /* QTYPE + QCLASS */
        }

        /* qend + 16 must fit in response[]: 16 is the exact size of the
         * answer record appended below (2 pointer + 2 type + 2 class +
         * 4 ttl + 2 rdlength + 4 rdata). The original bound here only
         * rejected qend > sizeof(response), which still allowed qend
         * up to 512 - then the 16-byte answer record written straight
         * after it landed partly outside the 512-byte response[]
         * buffer. A crafted query with a ~497-512 byte question section
         * would overflow the stack buffer by up to 16 bytes. */
        if (!valid || qend + 16 > sizeof(response)) {
            continue;
        }

        memcpy(response, query, qend);

        /* Standard successful DNS response with one answer. */
        response[2] = 0x81;
        response[3] = 0x80;
        response[6] = 0x00;
        response[7] = 0x01;
        response[8] = 0x00;
        response[9] = 0x00;
        response[10] = 0x00;
        response[11] = 0x00;

        size_t pos = qend;

        /* Pointer back to the first question name. */
        response[pos++] = 0xC0;
        response[pos++] = 0x0C;

        /* TYPE=A, CLASS=IN, TTL=30 seconds, RDLENGTH=4. */
        response[pos++] = 0x00;
        response[pos++] = 0x01;
        response[pos++] = 0x00;
        response[pos++] = 0x01;
        response[pos++] = 0x00;
        response[pos++] = 0x00;
        response[pos++] = 0x00;
        response[pos++] = 0x1E;
        response[pos++] = 0x00;
        response[pos++] = 0x04;

        memcpy(&response[pos], &my_ap_ip, sizeof(my_ap_ip));
        pos += sizeof(my_ap_ip);

        (void)sendto(fd, response, pos, 0,
                     (struct sockaddr *)&peer, peer_len);
    }

    close(fd);
    dns_task_handle = NULL;
    vTaskDelete(NULL);
}

void captive_portal_start(void)
{
    if (dns_task_handle != NULL) {
        return;
    }

    if (xTaskCreatePinnedToCore(captive_dns_task,
                                "captive_dns",
                                3072,
                                NULL,
                                tskIDLE_PRIORITY + 1,
                                &dns_task_handle,
                                1) != pdPASS) {
        dns_task_handle = NULL;
        ESP_LOGE(TAG, "Failed to start captive DNS task");
    }
}

void captive_portal_stop(void)
{
    dns_task_handle = NULL;
}

static httpd_handle_t start_http_redirect(void){httpd_config_t c=HTTPD_DEFAULT_CONFIG();c.server_port=80;c.max_uri_handlers=1;c.max_open_sockets=2;struct ifreq ifr={0};strncpy(ifr.ifr_name,"WIFI_AP_DEF",sizeof(ifr.ifr_name)-1);c.if_name=&ifr;c.task_priority=tskIDLE_PRIORITY+1;c.core_id=1;c.stack_size=4096;httpd_handle_t h=NULL;if(httpd_start(&h,&c)!=ESP_OK)return NULL;httpd_uri_t u={.uri="/*",.method=HTTP_GET,.handler=redirect_http};c.uri_match_fn=httpd_uri_match_wildcard;if(httpd_register_uri_handler(h,&u)!=ESP_OK){httpd_stop(h);return NULL;}return h;}

httpd_handle_t start_webserver(uint16_t port)
{
    (void)port;
    if (!auth_hash_sem) auth_hash_sem = xSemaphoreCreateMutex();
    if (!auth_hash_sem) return NULL;

    httpd_ssl_config_t c = HTTPD_SSL_CONFIG_DEFAULT();
    c.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
    c.port_secure = 443;
    c.servercert = server_cert_pem_start;
    c.servercert_len = server_cert_pem_end - server_cert_pem_start;
    c.prvtkey_pem = server_key_pem_start;
    c.prvtkey_len = server_key_pem_end - server_key_pem_start;
    c.session_tickets = false;
    c.httpd.task_priority = tskIDLE_PRIORITY + 3;
    c.httpd.core_id = 1;
    c.httpd.stack_size = 8192;
    c.httpd.max_open_sockets = 4;
    c.httpd.max_uri_handlers = 10;
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, "WIFI_AP_DEF", sizeof(ifr.ifr_name) - 1);
    c.httpd.if_name = &ifr;
    c.httpd.lru_purge_enable = true;
    c.httpd.recv_wait_timeout = 5;
    c.httpd.send_wait_timeout = 5;

    httpd_handle_t h = NULL;
    if (httpd_ssl_start(&h, &c) != ESP_OK) return NULL;

    const httpd_uri_t uris[] = {
        {.uri="/", .method=HTTP_GET, .handler=index_handler},
        {.uri="/api/status", .method=HTTP_GET, .handler=status_handler},
        {.uri="/api/auth", .method=HTTP_GET, .handler=auth_state_handler},
        {.uri="/api/login", .method=HTTP_POST, .handler=login_handler},
        {.uri="/api/logout", .method=HTTP_POST, .handler=logout_handler},
        {.uri="/api/scan", .method=HTTP_POST, .handler=scan_handler},
        {.uri="/api/connect", .method=HTTP_POST, .handler=connect_handler},
        {.uri="/api/ap", .method=HTTP_POST, .handler=ap_handler},
        {.uri="/api/setup", .method=HTTP_POST, .handler=setup_handler},
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); ++i) {
        if (httpd_register_uri_handler(h, &uris[i]) != ESP_OK) {
            httpd_ssl_stop(h);
            return NULL;
        }
    }
    if (start_http_redirect() == NULL) {
        httpd_ssl_stop(h);
        return NULL;
    }
    return h;
}
