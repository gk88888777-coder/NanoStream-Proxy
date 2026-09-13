import asyncio
import httpx
import time
from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
import redis.asyncio as redis
from cryptography.fernet import Fernet
import os
import logging
from urllib.parse import urlparse

# Professional logging setup for enterprise monitoring
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE 4: GATEWAY] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream 4X Gateway", version="3.0.0")

ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode('utf-8'))
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

# Vault 0: Storing Proxies
redis_vault_proxies = redis.Redis(host='127.0.0.1', port=6379, db=0)
# Vault 1: Storing Valid API Keys (The Control Panel Database)
redis_vault_keys = redis.Redis(host='127.0.0.1', port=6379, db=1, decode_responses=True)

# ----------------- TELEMETRY BROADCASTER -----------------

async def emit_gateway_telemetry(status: str, client_slot: str, target_domain: str, execution_time: float):
    if hasattr(app.state, 'ui_broadcast') and app.state.ui_broadcast:
        payload = {
            "engine": "master_4_gateway",
            "status": status,
            "client_slot": client_slot,
            "target_domain": target_domain,
            "execution_time_sec": round(execution_time, 4)
        }
        await app.state.ui_broadcast(payload)

# ----------------- SECURITY FUNCTIONS -----------------

def url_sentinel_shield(target_url: str, client_slot: str) -> str:
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else "unknown_domain"
        
        blocked_domains = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254']
        if hostname in blocked_domains or hostname.startswith('192.168.') or hostname.startswith('10.'):
            logging.critical(f"SSRF Attack Blocked from {client_slot}! Target: {hostname}")
            raise HTTPException(status_code=403, detail="Forbidden: Security Shield blocked internal routing.")
            
        return hostname
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Bad Request: Malformed URL detected.")

def sanitize_headers(original_headers: dict) -> dict:
    safe_headers = dict(original_headers)
    suspicious_tags = ['host', 'x-forwarded-for', 'x-real-ip', 'x-vercel-id']
    for tag in suspicious_tags:
        safe_headers.pop(tag, None)
        
    safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    return safe_headers

# ----------------- MAIN PROXY ENDPOINT -----------------

@app.get("/proxy")
async def gateway_proxy_handler(
    request: Request, 
    background_tasks: BackgroundTasks, 
    target_url: str, 
    x_api_key: str = Header(None)
):
    start_time = time.time()

    # 1. Dynamic Zero Trust Authentication (Reads directly from DB 1)
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: API Key missing.")
        
    client_slot_name = await redis_vault_keys.get(f"api_key:{x_api_key}")
    
    if not client_slot_name:
        background_tasks.add_task(emit_gateway_telemetry, "auth_failed", "Unknown Hacker", "N/A", time.time() - start_time)
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or Revoked API Key.")

    # 2. URL Sentinel Shield Validation
    target_domain = url_sentinel_shield(target_url, client_slot_name)

    # 3. Instant Vault Access & Decryption (Reads from DB 0)
    encrypted_ip_bytes = await redis_vault_proxies.spop("vip_proxy_pool")
    if not encrypted_ip_bytes:
        background_tasks.add_task(emit_gateway_telemetry, "vault_empty_error", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=503, detail="Service Unavailable: Vault is completely empty.")
        
    try:
        if isinstance(encrypted_ip_bytes, str):
            encrypted_ip_bytes = encrypted_ip_bytes.encode('utf-8')
        decrypted_ip = cipher_suite.decrypt(encrypted_ip_bytes).decode('utf-8')
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Security Error: Vault decryption failed.")

    proxy_url = f"http://{decrypted_ip}"
    proxies = {"http://": proxy_url, "https://": proxy_url}
    
    # 4. Header Sanitization
    camouflaged_headers = sanitize_headers(request.headers)

    # 5. Nano-Second Streaming
    try:
        async with httpx.AsyncClient(proxies=proxies, timeout=60.0) as client:
            upstream_request = client.build_request("GET", target_url, headers=camouflaged_headers)
            upstream_response = await client.send(upstream_request, stream=True)
            
            exec_time = time.time() - start_time
            background_tasks.add_task(emit_gateway_telemetry, "tunnel_established", client_slot_name, target_domain, exec_time)
            
            return StreamingResponse(
                upstream_response.aiter_bytes(), 
                status_code=upstream_response.status_code,
                media_type=upstream_response.headers.get("content-type")
            )
            
    except Exception as e:
        logging.error(f"Proxy routing failed via {decrypted_ip}. Target: {target_url}. Error: {str(e)}")
        background_tasks.add_task(emit_gateway_telemetry, "upstream_timeout", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=502, detail="Bad Gateway: Upstream server dropped the connection.")

# ----------------- DASHBOARD HEALTH ENDPOINT -----------------

@app.get("/health")
async def health_check():
    vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
    active_keys_count = len(await redis_vault_keys.keys("api_key:*"))
    return {
        "status": "online",
        "shield": "active",
        "available_ips": vault_count,
        "active_clients": active_keys_count
    }
