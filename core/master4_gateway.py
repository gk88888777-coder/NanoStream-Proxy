import asyncio
import httpx
import time
import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis
from cryptography.fernet import Fernet, InvalidToken
from urllib.parse import urlparse

# Security Guard: Block execution if run as root user
def enforce_security_guard():
    if os.name == 'posix' and os.geteuid() == 0:
        print("[CRITICAL SECURITY ERROR] Running engine as 'ROOT' is strictly forbidden!")
        sys.exit(1)

enforce_security_guard()

# Professional logging setup for Engine 4 Gateway
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE-4: GATEWAY-CORE] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream 4X Gateway Core", version="6.0.0")

# --- CORS MIDDLEWARE ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enterprise-grade fixed encryption key synchronized across engines
DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
try:
    cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))
except Exception as e:
    logging.critical(f"FATAL: Invalid PROXY_ENCRYPTION_KEY configuration: {e}")
    sys.exit(1)

# Environment-driven secure Redis configuration (Matches main.py DB 0 & DB 1)
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

# --- TELEMETRY BROADCAST HELPER ---
async def dispatch_gateway_telemetry(request: Request, status: str, client_slot: str, target_domain: str, exec_time: float):
    """Safely dispatches telemetry events to main.py's master WebSocket broadcaster without blocking."""
    ui_broadcast = getattr(request.app.state, "ui_broadcast", None)
    if ui_broadcast:
        payload = {
            "engine": "master_4_gateway",
            "status": status,
            "client_slot": client_slot,
            "target_domain": target_domain,
            "execution_time_sec": round(exec_time, 4)
        }
        try:
            if asyncio.iscoroutinefunction(ui_broadcast):
                await ui_broadcast(payload)
            else:
                asyncio.create_task(ui_broadcast(payload))
        except Exception as ex:
            logging.error(f"Telemetry dispatch error: {ex}")

# --- PROXY CORE ROUTING & SECURITY ---
BLOCKED_INTERNAL_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', 'internal', 'metadata.google.internal'}

def url_sentinel_shield(target_url: str) -> str:
    """SSRF Shield: Blocks attacks against internal network resources, metadata endpoints, and local loopbacks."""
    try:
        if not target_url or not isinstance(target_url, str):
            raise HTTPException(status_code=400, detail="Bad Request: Target URL is missing or invalid.")
        parsed_url = urlparse(target_url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise HTTPException(status_code=400, detail="Bad Request: Malformed target URL schema.")
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else "unknown_domain"
        if hostname in BLOCKED_INTERNAL_HOSTS or hostname.startswith(('192.168.', '10.', '172.16.', '127.', '0.')):
            raise HTTPException(status_code=403, detail="Forbidden: SSRF Shield blocked internal routing.")
        return hostname
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Bad Request: Malformed target URL parsing failed.")

def sanitize_headers(original_headers: dict) -> dict:
    """Strips tracking headers and sets clean User-Agent for anti-bot/scraping safety."""
    safe_headers = dict(original_headers)
    for tag in ['host', 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'via', 'x-admin-key']:
        safe_headers.pop(tag, None)
    safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    return safe_headers

async def proxy_stream_generator(client: httpx.AsyncClient, response: httpx.Response):
    """Securely streams data chunks and guarantees absolute connection cleanup."""
    try:
        async for chunk in response.aiter_bytes(chunk_size=65536):
            yield chunk
    finally:
        try:
            await response.aclose()
        except Exception:
            pass
        try:
            await client.aclose()
        except Exception:
            pass

# --- MASTER UNIVERSAL PROXY ROUTE (Mounted under /gateway in main.py -> Becomes /gateway/proxy) ---
@app.api_route("/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway_proxy_handler(request: Request, background_tasks: BackgroundTasks, target_url: str):
    """
    Master High-Performance Universal Proxy Routing Engine:
    - Fully supports Video Streaming, E-Commerce Automation (Amazon/Flipkart session/cookie persistence), Web Scraping & API Testing.
    - Supports GET/POST/PUT/DELETE/PATCH methods, request body payloads, and upstream response header relaying.
    """
    start_time = time.time()
    x_api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: API Key missing.")
        
    try:
        client_slot_name = await redis_vault_keys.get(f"api_key:{x_api_key}") or await redis_vault_keys.get(x_api_key)
    except Exception as redis_err:
        logging.error(f"Redis Key Vault error: {redis_err}")
        raise HTTPException(status_code=500, detail="Internal Server Error: Key validation vault failure.")

    if not client_slot_name:
        await dispatch_gateway_telemetry(request, "auth_failed", "Unknown Hacker", "N/A", time.time() - start_time)
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API Key.")

    target_domain = url_sentinel_shield(target_url)
    
    # BULLETPROOF PROXY RETRY LOOP (Tries up to 3 times to get a valid, decryptable proxy IP without exhausting pool)
    decrypted_ip = None
    for attempt in range(3):
        try:
            encrypted_ip_bytes = await redis_vault_proxies.srandmember("vip_proxy_pool")
            if not encrypted_ip_bytes:
                break
            if isinstance(encrypted_ip_bytes, str):
                encrypted_ip_bytes = encrypted_ip_bytes.encode('utf-8')
            decrypted_ip = cipher_suite.decrypt(encrypted_ip_bytes).decode('utf-8')
            break
        except InvalidToken:
            continue
        except Exception:
            continue

    if not decrypted_ip:
        await dispatch_gateway_telemetry(request, "vault_empty_error", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=503, detail="Service Unavailable: Proxy Vault is empty or contains unreadable tokens.")

    proxy_url = f"http://{decrypted_ip}"
    camouflaged_headers = sanitize_headers(request.headers)

    try:
        request_body = await request.body()
    except Exception:
        request_body = b""

    # 2-Hour Maximum Timeout (7200 seconds) for heavy scraping, automation, and long video downloads
    SAFE_TIMEOUT = httpx.Timeout(
        connect=15.0, 
        read=7200.0, 
        write=15.0, 
        pool=15.0
    )

    proxy_client = None
    try:
        transport = httpx.AsyncHTTPTransport(proxy=proxy_url)
        proxy_client = httpx.AsyncClient(transport=transport, timeout=SAFE_TIMEOUT, follow_redirects=True)
        
        upstream_response = await proxy_client.request(
            method=request.method,
            url=target_url,
            headers=camouflaged_headers,
            content=request_body if request_body else None,
            stream=True
        )
        
        exec_time = time.time() - start_time
        background_tasks.add_task(dispatch_gateway_telemetry, request, "tunnel_established", client_slot_name, target_domain, exec_time)
        
        # Forward upstream response headers (like Set-Cookie, Authorization tokens) safely to client/scraper
        excluded_headers = {'content-encoding', 'content-length', 'transfer-encoding', 'connection'}
        response_headers = {
            k: v for k, v in upstream_response.headers.items() 
            if k.lower() not in excluded_headers
        }
        
        return StreamingResponse(
            proxy_stream_generator(proxy_client, upstream_response), 
            status_code=upstream_response.status_code,
            headers=response_headers
        )
    except httpx.TimeoutException:
        if proxy_client:
            try:
                await proxy_client.aclose()
            except Exception:
                pass
        await dispatch_gateway_telemetry(request, "upstream_timeout", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=504, detail="Gateway Timeout: Upstream target took too long to respond.")
    except httpx.RequestError as req_err:
        if proxy_client:
            try:
                await proxy_client.aclose()
            except Exception:
                pass
        logging.error(f"Upstream network error via proxy {decrypted_ip}: {req_err}")
        await dispatch_gateway_telemetry(request, "upstream_network_error", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=502, detail="Bad Gateway: Proxy tunnel or upstream connection failed.")
    except Exception as e:
        if proxy_client:
            try:
                await proxy_client.aclose()
            except Exception:
                pass
        logging.error(f"Unexpected proxy routing exception: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error: Secure tunnel failure.")

@app.get("/health")
async def health_check():
    """System health metrics endpoint for the Gateway."""
    try:
        vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
        active_keys_count = len(await redis_vault_keys.keys("api_key:*"))
        return {"status": "gateway_online", "shield": "active", "available_proxy_ips": vault_count, "active_clients": active_keys_count}
    except Exception as e:
        return {"status": "degraded", "error": str(e)}
