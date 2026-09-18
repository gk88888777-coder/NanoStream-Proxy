import asyncio
import httpx
import time
import os
import sys
import logging
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
import redis.asyncio as redis
from cryptography.fernet import Fernet
from urllib.parse import urlparse

# Security Guard: Block execution if run as root user
def enforce_security_guard():
    if os.name == 'posix' and os.geteuid() == 0:
        print("[CRITICAL SECURITY ERROR] Running engine as 'ROOT' is strictly forbidden!")
        sys.exit(1)

enforce_security_guard()

# Professional logging setup for Engine 4 Ultra-Gateway
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE-4: ULTRA-GATEWAY] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream 4X Gateway", version="5.4.0")

# Enterprise-Grade Fixed Shared Encryption Key synchronized with Engines 2 and 3
DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

# Secure environment-driven Redis configuration
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

async def emit_gateway_telemetry(status: str, client_slot: str, target_domain: str, execution_time: float):
    """Safely broadcasts real-time routing telemetry to the WebSocket UI dashboard."""
    if hasattr(app.state, 'ui_broadcast') and app.state.ui_broadcast:
        payload = {
            "engine": "master_4_gateway",
            "status": status,
            "client_slot": client_slot,
            "target_domain": target_domain,
            "execution_time_sec": round(execution_time, 4)
        }
        try:
            await app.state.ui_broadcast(payload)
        except Exception:
            pass

# Block internal network access to prevent Server-Side Request Forgery (SSRF) vulnerabilities
BLOCKED_INTERNAL_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'}

def url_sentinel_shield(target_url: str, client_slot: str) -> str:
    """Validates target URL and blocks unauthorized internal network requests."""
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else "unknown_domain"
        
        if hostname in BLOCKED_INTERNAL_HOSTS or hostname.startswith(('192.168.', '10.', '172.16.')):
            logging.critical(f"SSRF ATTACK BLOCKED! Client '{client_slot}' tried accessing internal host: {hostname}")
            raise HTTPException(status_code=403, detail="Forbidden: Security Shield blocked internal server routing.")
            
        return hostname
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Bad Request: Malformed or invalid target URL detected.")

def sanitize_headers(original_headers: dict) -> dict:
    """Strips sensitive tracking headers and normalizes User-Agent for seamless camouflaging."""
    safe_headers = dict(original_headers)
    suspicious_tags = ['host', 'x-forwarded-for', 'x-real-ip', 'x-vercel-id', 'cf-connecting-ip', 'via']
    for tag in suspicious_tags:
        safe_headers.pop(tag, None)
        
    safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    return safe_headers

async def proxy_stream_generator(client: httpx.AsyncClient, response: httpx.Response):
    """Streams proxy response chunks securely and ensures clean resource closure."""
    try:
        async for chunk in response.aiter_bytes(chunk_size=65536):
            yield chunk
    except Exception as e:
        logging.error(f"Streaming error encountered: {e}")
    finally:
        try:
            await response.aclose()
        except Exception:
            pass
        try:
            await client.aclose()
        except Exception:
            pass

@app.get("/proxy")
async def gateway_proxy_handler(
    request: Request, 
    background_tasks: BackgroundTasks, 
    target_url: str
):
    """Main high-performance proxy routing endpoint with API key authentication, Fernet decryption, and SSRF defense."""
    start_time = time.time()

    x_api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: API Key missing in request headers.")
        
    client_slot_name = await redis_vault_keys.get(f"api_key:{x_api_key}") or await redis_vault_keys.get(x_api_key)
    if not client_slot_name:
        background_tasks.add_task(emit_gateway_telemetry, "auth_failed", "Unknown Hacker", "N/A", time.time() - start_time)
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid, revoked, or expired API Key.")

    target_domain = url_sentinel_shield(target_url, client_slot_name)

    encrypted_ip_bytes = await redis_vault_proxies.spop("vip_proxy_pool")
    if not encrypted_ip_bytes:
        background_tasks.add_task(emit_gateway_telemetry, "vault_empty_error", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=503, detail="Service Unavailable: VIP Proxy Vault is temporarily empty. Supply chain recovering...")
        
    try:
        if isinstance(encrypted_ip_bytes, str):
            encrypted_ip_bytes = encrypted_ip_bytes.encode('utf-8')
        decrypted_ip = cipher_suite.decrypt(encrypted_ip_bytes).decode('utf-8')
    except Exception:
        logging.error("Vault decryption failure on retrieved proxy token.")
        raise HTTPException(status_code=500, detail="Internal Security Error: Vault token decryption failed.")

    proxy_url = f"http://{decrypted_ip}"
    camouflaged_headers = sanitize_headers(request.headers)

    try:
        transport = httpx.AsyncHTTPTransport(proxy=proxy_url)
        timeout_config = httpx.Timeout(connect=15.0, read=None, write=30.0, pool=10.0)
        
        proxy_client = httpx.AsyncClient(transport=transport, timeout=timeout_config, follow_redirects=True)
        upstream_response = await proxy_client.get(target_url, headers=camouflaged_headers, stream=True)
        
        exec_time = time.time() - start_time
        background_tasks.add_task(emit_gateway_telemetry, "tunnel_established", client_slot_name, target_domain, exec_time)
        
        return StreamingResponse(
            proxy_stream_generator(proxy_client, upstream_response), 
            status_code=upstream_response.status_code,
            media_type=upstream_response.headers.get("content-type")
        )
            
    except Exception as e:
        logging.error(f"Proxy routing failed via IP {decrypted_ip} for target {target_url}. Error: {str(e)}")
        background_tasks.add_task(emit_gateway_telemetry, "upstream_timeout", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=502, detail="Bad Gateway: Upstream server dropped or rejected the connection.")

@app.get("/health")
async def health_check():
    """System health check endpoint returning live vault metrics and active client counts."""
    vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
    active_keys_count = len(await redis_vault_keys.keys("api_key:*"))
    return {
        "status": "online",
        "shield": "active",
        "available_proxy_ips": vault_count,
        "active_clients": active_keys_count
    }
