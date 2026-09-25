import asyncio
import httpx
import time
import os
import sys
import ssl
import logging
import ipaddress
import warnings
from typing import Optional, Tuple, Dict, Any, AsyncIterator
from urllib.parse import urlparse, unquote
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response
import redis.asyncio as redis
from cryptography.fernet import Fernet, InvalidToken
from contextlib import asynccontextmanager

warnings.filterwarnings('ignore', category=UserWarning, module='httpx')

if os.name == 'posix' and os.geteuid() == 0:
    logging.warning("[SECURITY AUDIT] Running as ROOT. Ensure containerized isolation in production.")

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE-4: HYPER-GATEWAY] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

SHARED_SSL_CONTEXT = ssl.create_default_context()
SHARED_SSL_CONTEXT.check_hostname = False
SHARED_SSL_CONTEXT.verify_mode = ssl.CERT_NONE

DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
try:
    cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))
except Exception as e:
    logging.critical(f"FATAL: Invalid PROXY_ENCRYPTION_KEY configuration: {e}")
    sys.exit(1)

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)

MAX_SOCKET_CONNECTIONS = int(os.environ.get("MAX_SOCKET_CONNECTIONS", 4000))
DATA_FLUSH_THRESHOLD_BYTES = int(os.environ.get("DATA_FLUSH_THRESHOLD_BYTES", 1048576))
CACHE_TTL = float(os.environ.get("KEY_CACHE_TTL_SECONDS", 10.0))

redis_pool_proxies = redis.ConnectionPool(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD, 
    max_connections=MAX_SOCKET_CONNECTIONS, socket_timeout=5.0, socket_connect_timeout=3.0, retry_on_timeout=True
)
redis_pool_keys = redis.ConnectionPool(
    host=REDIS_HOST, port=REDIS_PORT, db=1, password=REDIS_PASSWORD, decode_responses=True, 
    max_connections=MAX_SOCKET_CONNECTIONS, socket_timeout=5.0, socket_connect_timeout=3.0, retry_on_timeout=True
)

redis_vault_proxies = redis.Redis(connection_pool=redis_pool_proxies)
redis_vault_keys = redis.Redis(connection_pool=redis_pool_keys)

pool_starvation_event = asyncio.Event()
LOCAL_KEY_CACHE: Dict[str, Dict[str, Any]] = {}
TARGET_DNS_CACHE: Dict[str, Tuple[bool, float]] = {}
TELEMETRY_SAMPLE_COUNTER = 0

CGNAT_NETWORK = ipaddress.IPv4Network('100.64.0.0/10')
BLOCKED_INTERNAL_NAMES = {'localhost', 'internal', 'metadata.google.internal', '0.0.0.0', '127.0.0.1', '::1', '169.254.169.254'}

async def close_gateway_resources():
    try:
        await redis_vault_proxies.aclose()
        await redis_pool_proxies.disconnect()
        await redis_vault_keys.aclose()
        await redis_pool_keys.disconnect()
        logging.info("[ENGINE 4] Gateway Redis connection pools closed cleanly.")
    except Exception as ex:
        logging.error(f"[ENGINE 4] Error closing gateway Redis pools: {ex}")

@asynccontextmanager
async def gateway_lifespan(app_instance: FastAPI):
    logging.info("[ENGINE 4] NanoStream Hyper-Scale Gateway operational.")
    yield
    await close_gateway_resources()

app = FastAPI(title="NanoStream 4X Hyper-Scale Gateway", version="21.0.0", lifespan=gateway_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_real_client_ip(request: Request) -> str:
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

async def dispatch_gateway_telemetry(status: str, client_slot: str, target_domain: str, exec_time: float, http_status_code: int = 200):
    global TELEMETRY_SAMPLE_COUNTER
    TELEMETRY_SAMPLE_COUNTER += 1
    
    if TELEMETRY_SAMPLE_COUNTER % 20 != 0 and status == "tunnel_established":
        return

    ui_broadcast = getattr(app.state, "ui_broadcast", None)
    if ui_broadcast:
        payload = {
            "engine": "master_4_gateway",
            "status": status,
            "client_slot": client_slot,
            "target_domain": target_domain,
            "execution_time_sec": round(exec_time, 4),
            "gateway_status": "Active" if status not in ["error", "upstream_timeout", "upstream_network_error", "auth_failed"] else "Alert",
            "active_client": client_slot,
            "throughput": f"{round(exec_time, 2)}s",
            "http_status": str(http_status_code)
        }
        try:
            if asyncio.iscoroutinefunction(ui_broadcast):
                await asyncio.wait_for(ui_broadcast(payload), timeout=1.5)
            else:
                ui_broadcast(payload)
        except Exception:
            pass

async def is_forbidden_ip_or_host(hostname: str) -> bool:
    if not hostname or hostname in BLOCKED_INTERNAL_NAMES:
        return True

    now = time.time()
    if hostname in TARGET_DNS_CACHE:
        cached_result, exp_time = TARGET_DNS_CACHE[hostname]
        if now < exp_time:
            return cached_result
        else:
            TARGET_DNS_CACHE.pop(hostname, None)

    if len(TARGET_DNS_CACHE) > 5000:
        TARGET_DNS_CACHE.clear()

    try:
        ascii_hostname = hostname.encode('idna').decode('ascii')
    except Exception:
        ascii_hostname = hostname

    try:
        ip = ipaddress.ip_address(ascii_hostname)
        is_bad = (ip.is_unspecified or ip.is_private or ip.is_loopback or 
                  ip.is_link_local or ip.is_reserved or ip.is_multicast or 
                  (ip.version == 4 and ip in CGNAT_NETWORK))
        TARGET_DNS_CACHE[hostname] = (is_bad, now + 300.0)
        return is_bad
    except ValueError:
        pass

    if ascii_hostname.endswith(('.local', '.internal', '.localhost')):
        TARGET_DNS_CACHE[hostname] = (True, now + 300.0)
        return True

    try:
        loop = asyncio.get_running_loop()
        addr_info = await asyncio.wait_for(loop.getaddrinfo(ascii_hostname, None), timeout=2.5)
        for _, _, _, _, sockaddr in addr_info:
            resolved_ip = ipaddress.ip_address(sockaddr[0])
            if (resolved_ip.is_unspecified or resolved_ip.is_private or 
                resolved_ip.is_loopback or resolved_ip.is_link_local or 
                resolved_ip.is_reserved or resolved_ip.is_multicast or 
                (resolved_ip.version == 4 and resolved_ip in CGNAT_NETWORK)):
                TARGET_DNS_CACHE[hostname] = (True, now + 300.0)
                return True
        TARGET_DNS_CACHE[hostname] = (False, now + 300.0)
        return False
    except Exception:
        return True

def smart_decode_target_url(raw_url: str) -> str:
    clean_url = raw_url.strip()
    for _ in range(3):
        if clean_url.startswith(("http://", "https://")):
            break
        candidate = unquote(clean_url)
        if candidate == clean_url:
            break
        clean_url = candidate

    clean_url = clean_url.replace(" ", "%20")
    if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
        clean_url = "https://" + clean_url

    return clean_url

async def sanitize_and_validate_target_url(raw_url: str) -> Tuple[str, str]:
    if not raw_url or not isinstance(raw_url, str):
        raise HTTPException(status_code=400, detail="Bad Request: Target URL parameter is missing.")
    
    clean_url = smart_decode_target_url(raw_url)
    parsed = urlparse(clean_url)
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    
    if await is_forbidden_ip_or_host(hostname):
        raise HTTPException(status_code=403, detail="Forbidden: SSRF Shield blocked internal target.")
        
    return clean_url, hostname

def resolve_stream_content_type(target_url: str, upstream_content_type: Optional[str]) -> str:
    if upstream_content_type and upstream_content_type.strip():
        return upstream_content_type.strip()
    
    url_path = urlparse(target_url).path.lower()
    if url_path.endswith(".m3u8"):
        return "application/vnd.apple.mpegurl"
    elif url_path.endswith(".ts"):
        return "video/mp2t"
    elif url_path.endswith(".mp4"):
        return "video/mp4"
    elif url_path.endswith(".mpd"):
        return "application/dash+xml"
    elif url_path.endswith(".key"):
        return "application/octet-stream"
    
    return "application/octet-stream"

def sanitize_headers(original_headers: dict) -> dict:
    safe_headers = dict(original_headers)
    strip_tags = [
        'host', 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'via',
        'x-admin-key', 'x-api-key', 'x-target-url', 'x-session-id', 'content-length',
        'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'upgrade'
    ]
    for tag in strip_tags:
        safe_headers.pop(tag, None)
    
    if not safe_headers.get('user-agent'):
        safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    
    safe_headers['Accept-Encoding'] = 'identity'
    return safe_headers

async def proxy_stream_generator(client: httpx.AsyncClient, response: httpx.Response, request: Request, auth_key: Optional[str] = None):
    pending_flush = 0
    chunk_count = 0
    try:
        async for chunk in response.aiter_bytes(chunk_size=65536):
            chunk_count += 1
            if chunk_count % 16 == 0 and await request.is_disconnected():
                break
                
            chunk_len = len(chunk)
            pending_flush += chunk_len
            
            if pending_flush >= DATA_FLUSH_THRESHOLD_BYTES:
                if auth_key:
                    try:
                        await redis_vault_keys.incrby(f"data_usage_bytes:{auth_key}", pending_flush)
                    except Exception:
                        pass
                pending_flush = 0
                
            yield chunk
    except (asyncio.CancelledError, GeneratorExit, httpx.HTTPError):
        pass
    finally:
        try:
            await response.aclose()
        except Exception:
            pass
        try:
            await client.aclose()
        except Exception:
            pass
        
        if auth_key and pending_flush > 0:
            try:
                await redis_vault_keys.incrby(f"data_usage_bytes:{auth_key}", pending_flush)
            except Exception:
                pass

async def purge_dead_proxy_everywhere(raw_token_bytes: Optional[bytes], raw_ip_port: Optional[str]):
    try:
        async with redis_vault_proxies.pipeline(transaction=False) as pipe:
            if raw_token_bytes:
                pipe.srem("vip_proxy_pool", raw_token_bytes)
            if raw_ip_port:
                clean = raw_ip_port.replace("http://", "").replace("https://", "").replace("socks5://", "").strip()
                pipe.srem("vip_proxy_ips", clean.encode('utf-8'))
            await pipe.execute()
    except Exception as e:
        logging.error(f"[ENGINE 4] Error during synchronized dead proxy purge: {e}")

async def fetch_single_valid_proxy(session_id: Optional[str] = None) -> Tuple[Optional[str], Optional[bytes], Optional[str]]:
    if session_id:
        cached_session_data = await redis_vault_proxies.get(f"session_proxy:{session_id}")
        if cached_session_data:
            try:
                decrypted_url, raw_token_hex, clean_ip = cached_session_data.decode('utf-8').split("|")
                token_bytes = bytes.fromhex(raw_token_hex) if raw_token_hex != "none" else None
                return decrypted_url, token_bytes, clean_ip
            except Exception:
                pass

    for _ in range(5):
        try:
            raw_ip_member = await redis_vault_proxies.srandmember("vip_proxy_pool")
            if not raw_ip_member:
                pool_starvation_event.set()
                return None, None, None
            
            raw_bytes = raw_ip_member.encode('utf-8') if isinstance(raw_ip_member, str) else raw_ip_member
            try:
                decrypted = cipher_suite.decrypt(raw_bytes).decode('utf-8').strip(' "\'\t\r\n')
            except InvalidToken:
                decrypted = raw_bytes.decode('utf-8', errors='ignore').strip(' "\'\t\r\n')

            if ":" in decrypted:
                clean_ip_port = decrypted
                if not (decrypted.startswith("http://") or decrypted.startswith("https://") or decrypted.startswith("socks5://")):
                    decrypted = f"http://{decrypted}"
                
                if session_id:
                    token_hex = raw_bytes.hex() if raw_bytes else "none"
                    session_payload = f"{decrypted}|{token_hex}|{clean_ip_port}"
                    await redis_vault_proxies.setex(f"session_proxy:{session_id}", 180, session_payload)

                return decrypted, raw_bytes, clean_ip_port
        except Exception:
            continue
            
    pool_starvation_event.set()
    return None, None, None

def extract_clean_target_url(request: Request, raw_target_param: Optional[str], raw_auth_key: Optional[str]) -> str:
    header_url = request.headers.get("x-target-url") or request.headers.get("X-Target-URL")
    if header_url and header_url.strip():
        return header_url.strip()

    raw_query = str(request.url.query)
    target_marker = None
    if "target_url=" in raw_query:
        target_marker = "target_url="
    elif "url=" in raw_query:
        target_marker = "url="

    if target_marker:
        parts = raw_query.split(target_marker, 1)
        candidate = parts[1]
        
        if raw_auth_key:
            for k in [raw_auth_key, unquote(raw_auth_key)]:
                for pattern in [f"&key={k}", f"&api_key={k}", f"key={k}&", f"api_key={k}&"]:
                    if pattern in candidate:
                        candidate = candidate.replace(pattern, "")

        if candidate:
            return smart_decode_target_url(candidate)

    if raw_target_param:
        return smart_decode_target_url(raw_target_param)

    raise HTTPException(status_code=400, detail="Bad Request: Missing 'target_url' parameter or 'X-Target-URL' header.")

def normalize_incoming_key(raw_key: str) -> str:
    clean_token = raw_key.strip()
    for _ in range(3):
        candidate = unquote(clean_token)
        if candidate == clean_token:
            break
        clean_token = candidate
    return clean_token

async def get_cached_client_profile(x_api_key: str) -> Tuple[Optional[str], str, int, Optional[str]]:
    now = time.time()
    cached = LOCAL_KEY_CACHE.get(x_api_key)
    if cached and (now - cached['cached_at']) < cached.get('ttl_window', CACHE_TTL):
        return cached['name'], cached['tier'], cached['max_rps'], cached['bound_ip']

    if len(LOCAL_KEY_CACHE) > 50000:
        LOCAL_KEY_CACHE.clear()

    pipe = redis_vault_keys.pipeline()
    pipe.get(f"api_key:{x_api_key}")
    pipe.get(f"api_key_tier:{x_api_key}")
    pipe.get(f"api_key_rps:{x_api_key}")
    pipe.get(f"api_key_ip:{x_api_key}")
    pipe.ttl(f"api_key:{x_api_key}")
    results = await pipe.execute()

    client_name = results[0]
    tier = results[1] or "standard"
    raw_rps = results[2]
    bound_ip = results[3]
    ttl = results[4]

    if not client_name or ttl == -2:
        LOCAL_KEY_CACHE.pop(x_api_key, None)
        return None, "standard", 0, None

    try:
        max_rps = int(raw_rps) if raw_rps is not None else (10000 if tier == "enterprise" else 25)
    except ValueError:
        max_rps = 10000 if tier == "enterprise" else 25

    ttl_window = min(CACHE_TTL, ttl) if (ttl and ttl > 0) else CACHE_TTL

    LOCAL_KEY_CACHE[x_api_key] = {
        'name': client_name,
        'tier': tier,
        'max_rps': max_rps,
        'bound_ip': bound_ip,
        'cached_at': now,
        'ttl_window': ttl_window
    }
    return client_name, tier, max_rps, bound_ip

@app.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.api_route("/proxy/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway_proxy_handler(
    request: Request, 
    background_tasks: BackgroundTasks, 
    target_url: Optional[str] = None
):
    if request.method == "OPTIONS":
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Max-Age": "86400",
            }
        )

    start_time = time.time()
    client_ip = get_real_client_ip(request)

    if await redis_vault_keys.exists(f"auto_blocked_ip:{client_ip}") or await redis_vault_keys.exists(f"auto_blocked:{client_ip}"):
        raise HTTPException(status_code=403, detail="Forbidden: Hostile activity detected earlier. IP quarantined.")

    raw_key = (
        request.headers.get("x-api-key") 
        or request.headers.get("X-API-Key")
        or request.query_params.get("key")
        or request.query_params.get("api_key")
    )
    
    if not raw_key:
        raise HTTPException(status_code=401, detail="Unauthorized: API Key missing in headers or query parameters.")
        
    x_api_key = normalize_incoming_key(raw_key)
    client_slot_name, tier, allocated_rps, bound_ip = await get_cached_client_profile(x_api_key)

    if not client_slot_name:
        was_registered = await redis_vault_keys.sismember("active_keys_registry", x_api_key)
        if was_registered:
            LOCAL_KEY_CACHE.pop(x_api_key, None)
            pipe = redis_vault_keys.pipeline()
            pipe.srem("active_keys_registry", x_api_key)
            pipe.srem("enterprise_b2b_registry", x_api_key)
            pipe.srem("standard_keys_registry", x_api_key)
            pipe.delete(
                f"api_key_ip:{x_api_key}", f"api_key_rps:{x_api_key}", f"api_key_tier:{x_api_key}",
                f"api_key_country:{x_api_key}", f"api_key_purpose:{x_api_key}", f"api_key_slot:{x_api_key}",
                f"request_count:{x_api_key}", f"data_usage_bytes:{x_api_key}"
            )
            await pipe.execute()
            await dispatch_gateway_telemetry("auth_failed", "Expired Client", "N/A", time.time() - start_time, 403)
            raise HTTPException(status_code=403, detail="Forbidden: API Key / Subscription has expired. Please renew.")

        fail_key = f"invalid_key_attempts:{client_ip}"
        fails = await redis_vault_keys.incr(fail_key)
        if fails == 1:
            await redis_vault_keys.expire(fail_key, 60)
            
        if fails >= 10:
            await redis_vault_keys.setex(f"auto_blocked_ip:{client_ip}", 1800, "brute_force_exceeded")
            logging.critical(f"BRUTE-FORCE ALERT: IP {client_ip} banned after {fails} wrong attempts.")
            raise HTTPException(status_code=403, detail="Forbidden: Too many invalid attempts. Auto-blocked.")

        await dispatch_gateway_telemetry("auth_failed", "Unknown Client", "N/A", time.time() - start_time, 401)
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API Key.")

    background_tasks.add_task(redis_vault_keys.incr, f"request_count:{x_api_key}")

    is_master_passport = (x_api_key in ["gk(GK)321", "GK_Master_Client"])

    if not is_master_passport:
        if not bound_ip:
            was_set = await redis_vault_keys.set(f"api_key_ip:{x_api_key}", client_ip, nx=True)
            if was_set:
                ttl = await redis_vault_keys.ttl(f"api_key:{x_api_key}")
                if ttl and ttl > 0:
                    await redis_vault_keys.expire(f"api_key_ip:{x_api_key}", ttl)
                if x_api_key in LOCAL_KEY_CACHE:
                    LOCAL_KEY_CACHE[x_api_key]['bound_ip'] = client_ip
                logging.info(f"[{tier.upper()} LOCK] Client '{client_slot_name}' auto-bound to IP: {client_ip}")
            else:
                bound_ip = await redis_vault_keys.get(f"api_key_ip:{x_api_key}")

        if bound_ip and bound_ip != client_ip:
            error_prefix = "Enterprise Server" if tier == "enterprise" else "Device"
            raise HTTPException(
                status_code=403, 
                detail=f"Forbidden: Key is locked to registered {error_prefix} IP ({bound_ip}). Contact admin to reset binding."
            )

        current_second = int(time.time())
        if tier == "enterprise":
            if allocated_rps > 0:
                rate_key = f"b2b_rps:{x_api_key}:{current_second}"
                count = await redis_vault_keys.incr(rate_key)
                if count == 1:
                    await redis_vault_keys.expire(rate_key, 2)
                if count > allocated_rps:
                    raise HTTPException(status_code=429, detail=f"Too Many Requests: Enterprise contracted quota reached ({allocated_rps:,} req/sec).")
        else:
            std_limit = allocated_rps if allocated_rps > 0 else 25
            rate_key = f"std_rps:{x_api_key}:{current_second}"
            count = await redis_vault_keys.incr(rate_key)
            if count == 1:
                await redis_vault_keys.expire(rate_key, 2)
            
            if count > (std_limit * 3):
                await redis_vault_keys.setex(f"auto_blocked_ip:{client_ip}", 900, "std_flood_exceeded")
                raise HTTPException(status_code=403, detail=f"Forbidden: Heavy attack detected. IP Quarantined for 15 minutes.")
            elif count > std_limit:
                raise HTTPException(status_code=429, detail=f"Too Many Requests: Standard quota exceeded (Max {std_limit} req/sec). Slow down.")

    resolved_raw_url = extract_clean_target_url(request, target_url, raw_key)
    final_target_url, target_domain = await sanitize_and_validate_target_url(resolved_raw_url)
    session_id = request.headers.get("x-session-id") or request.query_params.get("session")

    request_content = request.stream() if request.method in ["POST", "PUT", "PATCH"] else None
    camouflaged_headers = sanitize_headers(request.headers)
    SAFE_TIMEOUT = httpx.Timeout(connect=3.5, read=7200.0, write=15.0, pool=15.0)

    last_network_error = None
    for proxy_attempt in range(3):
        proxy_url, raw_token_bytes, clean_ip_port = await fetch_single_valid_proxy(session_id)
        if not proxy_url:
            break

        proxy_client = None
        upstream_response = None
        try:
            transport = httpx.AsyncHTTPTransport(
                proxy=proxy_url, 
                verify=SHARED_SSL_CONTEXT, 
                limits=httpx.Limits(max_keepalive_connections=0, max_connections=1)
            )
            proxy_client = httpx.AsyncClient(transport=transport, timeout=SAFE_TIMEOUT, follow_redirects=False)
            
            req = proxy_client.build_request(
                method=request.method,
                url=final_target_url,
                headers=camouflaged_headers,
                content=request_content,
            )
            upstream_response = await proxy_client.send(req, stream=True)

            if upstream_response.status_code == 407:
                await upstream_response.aclose()
                await proxy_client.aclose()
                await purge_dead_proxy_everywhere(raw_token_bytes, clean_ip_port)
                if session_id:
                    await redis_vault_proxies.delete(f"session_proxy:{session_id}")
                continue
            
            exec_time = time.time() - start_time
            background_tasks.add_task(
                dispatch_gateway_telemetry, 
                "tunnel_established", 
                client_slot_name, 
                target_domain, 
                exec_time, 
                upstream_response.status_code
            )
            
            excluded_headers = {
                'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
                'te', 'trailers', 'transfer-encoding', 'upgrade', 'content-encoding',
                'access-control-allow-origin', 'access-control-allow-credentials',
                'access-control-allow-methods', 'access-control-allow-headers',
                'content-type', 'via', 'x-cache'
            }
            
            if upstream_response.status_code != 206 and 'content-range' not in upstream_response.headers:
                excluded_headers.add('content-length')

            response_headers = {
                k: v for k, v in upstream_response.headers.items() 
                if k.lower() not in excluded_headers
            }
            
            response_headers['Access-Control-Allow-Origin'] = '*'
            response_headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS'
            response_headers['Access-Control-Allow-Headers'] = '*'
            response_headers['X-Accel-Buffering'] = 'no'
            response_headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response_headers['Accept-Ranges'] = 'bytes'
            
            final_media_type = resolve_stream_content_type(
                final_target_url, 
                upstream_response.headers.get("content-type")
            )

            if request.method == "HEAD" or upstream_response.status_code in [204, 304]:
                await upstream_response.aclose()
                await proxy_client.aclose()
                return Response(
                    status_code=upstream_response.status_code,
                    headers=response_headers,
                    media_type=final_media_type
                )
            
            return StreamingResponse(
                proxy_stream_generator(proxy_client, upstream_response, request, x_api_key), 
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=final_media_type
            )
        except (httpx.ProxyError, httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.TimeoutException, httpx.NetworkError) as conn_err:
            if upstream_response:
                try:
                    await upstream_response.aclose()
                except Exception:
                    pass
            if proxy_client:
                await proxy_client.aclose()
            
            await purge_dead_proxy_everywhere(raw_token_bytes, clean_ip_port)
            if session_id:
                await redis_vault_proxies.delete(f"session_proxy:{session_id}")
            
            last_network_error = conn_err
            continue
        except Exception as e:
            if upstream_response:
                try:
                    await upstream_response.aclose()
                except Exception:
                    pass
            if proxy_client:
                await proxy_client.aclose()
            logging.error(f"Routing exception: {e}")
            raise HTTPException(status_code=500, detail="Internal Server Error: Secure tunnel failure.")

    await dispatch_gateway_telemetry("upstream_network_error", client_slot_name, target_domain, time.time() - start_time, 502)
    raise HTTPException(status_code=502, detail=f"Bad Gateway: All proxy attempts exhausted ({last_network_error or 'Pool unreadable'}).")

@app.get("/health")
async def health_check():
    try:
        vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
        enterprise_count = await redis_vault_keys.scard("enterprise_b2b_registry")
        standard_count = await redis_vault_keys.scard("standard_keys_registry")
        
        ent_max = int(await redis_vault_keys.get("sys:config:ent_max_slots") or os.environ.get("ENTERPRISE_MAX_SLOTS", 5))
        std_max = int(await redis_vault_keys.get("sys:config:std_max_slots") or os.environ.get("STANDARD_MAX_SLOTS", 500))

        return {
            "status": "hyper_scale_gateway_online", 
            "shield": "active", 
            "available_proxy_ips": vault_count, 
            "enterprise_slots_used": f"{enterprise_count}/{ent_max}",
            "standard_slots_used": f"{standard_count}/{std_max}",
            "max_socket_pool": MAX_SOCKET_CONNECTIONS
        }
    except Exception as e:
        return {"status": "degraded", "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("core.master4_gateway:app", host="0.0.0.0", port=8000, reload=False, workers=1)
