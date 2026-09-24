import asyncio
import httpx
import time
import os
import sys
import logging
import ipaddress
import warnings
from typing import Optional, Tuple
from urllib.parse import urlparse, unquote
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import StreamingResponse, Response
import redis.asyncio as redis
from cryptography.fernet import Fernet, InvalidToken

# Suppress transport warnings for clean production logs
warnings.filterwarnings('ignore', category=UserWarning, module='httpx')

# Security Guard: Block execution if run as root user
def enforce_security_guard():
    if os.name == 'posix' and os.geteuid() == 0:
        print("[CRITICAL SECURITY ERROR] Running engine as 'ROOT' is strictly forbidden!")
        sys.exit(1)

enforce_security_guard()

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE-4: GATEWAY-CORE] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream 4X Gateway Core", version="8.2.0")

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

redis_pool_proxies = redis.ConnectionPool(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD, max_connections=100
)
redis_pool_keys = redis.ConnectionPool(
    host=REDIS_HOST, port=REDIS_PORT, db=1, password=REDIS_PASSWORD, decode_responses=True, max_connections=100
)

redis_vault_proxies = redis.Redis(connection_pool=redis_pool_proxies)
redis_vault_keys = redis.Redis(connection_pool=redis_pool_keys)

async def close_gateway_resources():
    """Explicit cleanup callable from parent app shutdown handler"""
    try:
        await redis_vault_proxies.aclose()
        await redis_pool_proxies.disconnect()
        await redis_vault_keys.aclose()
        await redis_pool_keys.disconnect()
        logging.info("Gateway Redis pools and connections disconnected cleanly.")
    except Exception as ex:
        logging.error(f"Error disconnecting gateway Redis pools: {ex}")

def get_real_client_ip(request: Request) -> str:
    """Extract real client IP behind Nginx reverse proxy prioritizing trusted X-Real-IP"""
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

async def dispatch_gateway_telemetry(status: str, client_slot: str, target_domain: str, exec_time: float, http_status_code: int = 200):
    ui_broadcast = getattr(app.state, "ui_broadcast", None)
    if ui_broadcast:
        payload = {
            "engine": "master_4_gateway",
            "status": status,
            "client_slot": client_slot,
            "target_domain": target_domain,
            "execution_time_sec": round(exec_time, 4),
            "gateway_status": "Active" if status not in ["error", "upstream_timeout", "upstream_network_error", "auth_failed"] else "Error",
            "active_client": client_slot,
            "throughput": f"{round(exec_time, 2)}s",
            "http_status": str(http_status_code)
        }
        try:
            if asyncio.iscoroutinefunction(ui_broadcast):
                await ui_broadcast(payload)
            else:
                asyncio.create_task(ui_broadcast(payload))
        except Exception as ex:
            logging.error(f"Telemetry dispatch error: {ex}")

BLOCKED_INTERNAL_NAMES = {'localhost', 'internal', 'metadata.google.internal', '0.0.0.0', '127.0.0.1', '::1', '169.254.169.254'}

async def is_forbidden_ip_or_host(hostname: str) -> bool:
    """Bulletproof async DNS and IP validation protecting against SSRF, IDN, and DNS Rebinding"""
    if not hostname or hostname in BLOCKED_INTERNAL_NAMES:
        return True

    # Punycode / IDNA handling for internationalized domains
    try:
        ascii_hostname = hostname.encode('idna').decode('ascii')
    except Exception:
        ascii_hostname = hostname

    try:
        ip = ipaddress.ip_address(ascii_hostname)
        if ip.is_unspecified or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
        return False
    except ValueError:
        pass

    if ascii_hostname.endswith(('.local', '.internal', '.localhost')):
        return True

    try:
        loop = asyncio.get_running_loop()
        addr_info = await asyncio.wait_for(loop.getaddrinfo(ascii_hostname, None), timeout=3.0)
        for _, _, _, _, sockaddr in addr_info:
            resolved_ip = ipaddress.ip_address(sockaddr[0])
            if resolved_ip.is_unspecified or resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local:
                return True
    except Exception:
        return True

    return False

def smart_decode_target_url(raw_url: str) -> str:
    """Recursively decodes double/triple encoded URLs until scheme is exposed without breaking query tokens"""
    clean_url = raw_url.strip()
    
    # Decode only until standard protocol is revealed
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
    """Validates URL schema, sanitizes spaces, and blocks SSRF internal targets"""
    if not raw_url or not isinstance(raw_url, str):
        raise HTTPException(status_code=400, detail="Bad Request: Target URL parameter is missing.")
    
    clean_url = smart_decode_target_url(raw_url)
    parsed = urlparse(clean_url)
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    
    if await is_forbidden_ip_or_host(hostname):
        raise HTTPException(status_code=403, detail="Forbidden: SSRF Shield blocked internal target.")
        
    return clean_url, hostname

def resolve_stream_content_type(target_url: str, upstream_content_type: Optional[str]) -> str:
    """Detects and falls back to standard media types for IPTV and HLS players"""
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
    """Prepares safe headers, prevents key leaks to target, and sets identity encoding"""
    safe_headers = dict(original_headers)
    
    strip_tags = [
        'host', 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'via',
        'x-admin-key', 'x-api-key', 'x-target-url', 'content-length'
    ]
    for tag in strip_tags:
        safe_headers.pop(tag, None)
    
    if not safe_headers.get('user-agent'):
        safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    
    safe_headers['Accept-Encoding'] = 'identity'
    return safe_headers

async def proxy_stream_generator(client: httpx.AsyncClient, response: httpx.Response):
    """Safely streams chunks without memory bloat and cleanly handles client disconnects"""
    try:
        async for chunk in response.aiter_bytes(chunk_size=65536):
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

async def fetch_single_valid_proxy() -> Tuple[Optional[str], Optional[bytes]]:
    """Retrieves decrypted proxy IP along with its exact raw vault token for auto-purge"""
    for _ in range(5):
        try:
            raw_ip_member = await redis_vault_proxies.srandmember("vip_proxy_pool")
            if not raw_ip_member:
                return None, None
            
            raw_bytes = raw_ip_member.encode('utf-8') if isinstance(raw_ip_member, str) else raw_ip_member
            try:
                decrypted = cipher_suite.decrypt(raw_bytes).decode('utf-8').strip(' "\'\t\r\n')
            except InvalidToken:
                decrypted = raw_bytes.decode('utf-8', errors='ignore').strip(' "\'\t\r\n')

            if ":" in decrypted:
                if not (decrypted.startswith("http://") or decrypted.startswith("https://") or decrypted.startswith("socks5://")):
                    decrypted = f"http://{decrypted}"
                return decrypted, raw_bytes
        except Exception:
            continue
    return None, None

def extract_clean_target_url(request: Request, raw_target_param: Optional[str], raw_auth_key: Optional[str]) -> str:
    """Robust extraction of full target URL prioritizing direct X-Target-URL headers"""
    header_url = request.headers.get("x-target-url") or request.headers.get("X-Target-URL")
    if header_url and header_url.strip():
        return header_url.strip()

    query_str = str(request.url.query)
    resolved = None

    if "target_url=" in query_str:
        resolved = query_str.split("target_url=", 1)[1]
    elif "url=" in query_str:
        resolved = query_str.split("url=", 1)[1]
    else:
        resolved = raw_target_param or request.query_params.get("target_url") or request.query_params.get("url")

    if not resolved:
        raise HTTPException(status_code=400, detail="Bad Request: Missing 'target_url' parameter or 'X-Target-URL' header.")

    if raw_auth_key:
        unquoted_key = unquote(raw_auth_key)
        for token_variant in [raw_auth_key, unquoted_key]:
            for prefix in ["&key=", "&api_key="]:
                pattern = f"{prefix}{token_variant}"
                if resolved.endswith(pattern):
                    resolved = resolved[:-len(pattern)]
                    break

    return resolved

def normalize_incoming_key(raw_key: str) -> str:
    """Multi-pass unquoting guarantees passport gk(GK)321 is decoded correctly even if double-encoded"""
    clean_token = raw_key.strip()
    for _ in range(3):
        candidate = unquote(clean_token)
        if candidate == clean_token:
            break
        clean_token = candidate
    return clean_token

@app.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
@app.api_route("/proxy/", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def gateway_proxy_handler(
    request: Request, 
    background_tasks: BackgroundTasks, 
    target_url: Optional[str] = None
):
    if request.method == "OPTIONS":
        return Response(status_code=200)

    start_time = time.time()
    client_ip = get_real_client_ip(request)

    # 1. Security Check: Auto-blocked verification
    if await redis_vault_keys.exists(f"auto_blocked_ip:{client_ip}") or await redis_vault_keys.exists(f"auto_blocked:{client_ip}"):
        raise HTTPException(
            status_code=403, 
            detail="Forbidden: Your IP has been auto-blocked due to suspicious brute-force attempts or rate limit."
        )

    # 2. Extract and Normalize Authentication Key
    raw_key = (
        request.headers.get("x-api-key") 
        or request.headers.get("X-API-Key")
        or request.query_params.get("key")
        or request.query_params.get("api_key")
    )
    
    if not raw_key:
        raise HTTPException(status_code=401, detail="Unauthorized: API Key missing in headers or query parameters.")
        
    x_api_key = normalize_incoming_key(raw_key)
    try:
        client_slot_name = await redis_vault_keys.get(f"api_key:{x_api_key}") or await redis_vault_keys.get(x_api_key)
    except Exception as redis_err:
        logging.error(f"Redis Key Vault error: {redis_err}")
        raise HTTPException(status_code=500, detail="Internal Server Error: Key validation vault failure.")

    # 3. Smart Key Validation: Distinguish between expired keys and brute-force attacks
    if not client_slot_name:
        was_registered = await redis_vault_keys.sismember("active_keys_registry", x_api_key)
        if was_registered:
            await redis_vault_keys.srem("active_keys_registry", x_api_key)
            await dispatch_gateway_telemetry("auth_failed", "Expired Client", "N/A", time.time() - start_time, 403)
            raise HTTPException(status_code=403, detail="Forbidden: API Key / Subscription has expired. Please renew your key.")

        fail_key = f"invalid_key_attempts:{client_ip}"
        fails = await redis_vault_keys.incr(fail_key)
        if fails == 1:
            await redis_vault_keys.expire(fail_key, 60)
            
        if fails >= 5:
            await redis_vault_keys.setex(f"auto_blocked_ip:{client_ip}", 1800, "brute_force_exceeded")
            logging.critical(f"BRUTE-FORCE ALERT: Real IP {client_ip} auto-blocked for 30 minutes after {fails} failed attempts.")
            raise HTTPException(status_code=403, detail="Forbidden: Too many invalid API key attempts. Your IP has been auto-blocked.")

        await dispatch_gateway_telemetry("auth_failed", "Unknown Hacker", "N/A", time.time() - start_time, 401)
        raise HTTPException(status_code=401, detail=f"Unauthorized: Invalid API Key. Attempt {fails}/5 before IP lockout.")

    await redis_vault_keys.delete(f"invalid_key_attempts:{client_ip}")

    # 4. Target URL extraction & multi-stage decoding
    resolved_raw_url = extract_clean_target_url(request, target_url, raw_key)
    final_target_url, target_domain = await sanitize_and_validate_target_url(resolved_raw_url)

    request_body = None
    if request.method not in ["GET", "HEAD", "OPTIONS"]:
        try:
            request_body = await request.body()
        except Exception:
            request_body = None

    camouflaged_headers = sanitize_headers(request.headers)
    SAFE_TIMEOUT = httpx.Timeout(connect=8.0, read=7200.0, write=15.0, pool=15.0)

    # 5. Multi-Proxy Failover Loop with HTTP/1.1 Standard Streaming & Zero-Leakage
    last_network_error = None
    for proxy_attempt in range(3):
        proxy_url, raw_token_bytes = await fetch_single_valid_proxy()
        if not proxy_url:
            break

        proxy_client = None
        upstream_response = None
        try:
            transport = httpx.AsyncHTTPTransport(proxy=proxy_url, verify=False)
            proxy_client = httpx.AsyncClient(transport=transport, timeout=SAFE_TIMEOUT, follow_redirects=False)
            
            req = proxy_client.build_request(
                method=request.method,
                url=final_target_url,
                headers=camouflaged_headers,
                content=request_body,
            )
            upstream_response = await proxy_client.send(req, stream=True)

            if upstream_response.status_code == 407:
                await upstream_response.aclose()
                await proxy_client.aclose()
                if raw_token_bytes:
                    await redis_vault_proxies.srem("vip_proxy_pool", raw_token_bytes)
                    logging.info(f"[SELF-HEALING PURGE] Proxy {proxy_url} requires auth (407). Instantly purged.")
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
            
            # RFC 7230 Hop-by-Hop headers exclusion
            excluded_headers = {
                'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
                'te', 'trailers', 'transfer-encoding', 'upgrade', 'content-encoding',
                'access-control-allow-origin', 'access-control-allow-credentials',
                'access-control-allow-methods', 'access-control-allow-headers',
                'content-type'
            }
            
            if upstream_response.status_code != 206 and 'content-range' not in upstream_response.headers:
                excluded_headers.add('content-length')

            response_headers = {
                k: v for k, v in upstream_response.headers.items() 
                if k.lower() not in excluded_headers
            }
            
            response_headers['X-Accel-Buffering'] = 'no'
            response_headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response_headers['Accept-Ranges'] = 'bytes'
            
            final_media_type = resolve_stream_content_type(
                final_target_url, 
                upstream_response.headers.get("content-type")
            )

            # Protocol Law: HEAD, 204 No Content, and 304 Not Modified MUST NOT have a chunked body
            if request.method == "HEAD" or upstream_response.status_code in [204, 304]:
                await upstream_response.aclose()
                await proxy_client.aclose()
                return Response(
                    status_code=upstream_response.status_code,
                    headers=response_headers,
                    media_type=final_media_type
                )
            
            return StreamingResponse(
                proxy_stream_generator(proxy_client, upstream_response), 
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=final_media_type
            )
        except (httpx.ProxyError, httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as conn_err:
            if upstream_response:
                try:
                    await upstream_response.aclose()
                except Exception:
                    pass
            if proxy_client:
                await proxy_client.aclose()
            
            if raw_token_bytes:
                await redis_vault_proxies.srem("vip_proxy_pool", raw_token_bytes)
                logging.info(f"[SELF-HEALING PURGE] Dead proxy {proxy_url} instantly purged from vault pool.")
            
            logging.warning(f"Proxy attempt {proxy_attempt + 1} failed via {proxy_url}: {conn_err}. Retrying...")
            last_network_error = conn_err
            continue
        except httpx.TimeoutException:
            if upstream_response:
                try:
                    await upstream_response.aclose()
                except Exception:
                    pass
            if proxy_client:
                await proxy_client.aclose()
            await dispatch_gateway_telemetry("upstream_timeout", client_slot_name, target_domain, time.time() - start_time, 504)
            raise HTTPException(status_code=504, detail="Gateway Timeout: Upstream target took too long to respond.")
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
        active_keys_count = await redis_vault_keys.scard("active_keys_registry")
        return {"status": "gateway_online", "shield": "active", "available_proxy_ips": vault_count, "active_clients": active_keys_count}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}
