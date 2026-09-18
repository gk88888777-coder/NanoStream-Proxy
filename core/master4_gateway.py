import asyncio
import httpx
import time
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
import redis.asyncio as redis
from cryptography.fernet import Fernet
import os
import logging
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE-4: ULTRA-GATEWAY] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream 4X Gateway", version="5.1.0")

ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode('utf-8'))
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

redis_pool_proxies = redis.ConnectionPool(host='127.0.0.1', port=6379, db=0, max_connections=100)
redis_pool_keys = redis.ConnectionPool(host='127.0.0.1', port=6379, db=1, decode_responses=True, max_connections=100)

redis_vault_proxies = redis.Redis(connection_pool=redis_pool_proxies)
redis_vault_keys = redis.Redis(connection_pool=redis_pool_keys)

async def emit_gateway_telemetry(status: str, client_slot: str, target_domain: str, execution_time: float):
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

BLOCKED_INTERNAL_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'}

def url_sentinel_shield(target_url: str, client_slot: str) -> str:
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
    safe_headers = dict(original_headers)
    suspicious_tags = ['host', 'x-forwarded-for', 'x-real-ip', 'x-vercel-id', 'cf-connecting-ip', 'via']
    for tag in suspicious_tags:
        safe_headers.pop(tag, None)
        
    safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    return safe_headers

async def proxy_stream_generator(client: httpx.AsyncClient, response: httpx.Response):
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
    vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
    active_keys_count = len(await redis_vault_keys.keys("api_key:*"))
    return {
        "status": "online",
        "shield": "active",
        "available_proxy_ips": vault_count,
        "active_clients": active_keys_count
    }
