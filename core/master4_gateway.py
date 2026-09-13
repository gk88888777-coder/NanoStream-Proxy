import asyncio
import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse
import redis.asyncio as redis
from cryptography.fernet import Fernet
import os
import logging
from urllib.parse import urlparse

# Professional logging setup
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE 4: GATEWAY] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Initialize the Ultra-Fast API Server
app = FastAPI(title="PhantomShield 4X Gateway", version="2.0.0")

# SECURITY LAYER: Must match Engine 2 & 3 exactly
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode('utf-8'))
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

# Connect to the invisible localhost Redis vault
redis_vault = redis.Redis(host='127.0.0.1', port=6379, db=0)

# Zero Trust API Key System
VALID_API_KEYS = {
    "vercel_master_key_xyz123": "Slot 1 - Vercel Video Downloader",
    "client_slot2_key_abc": "Slot 2 - Premium B2B Client"
}

# ----------------- SECURITY FUNCTIONS -----------------

def url_sentinel_shield(target_url: str):
    """
    Blocks SSRF attacks, local network probing, and malformed URLs.
    """
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname.lower()
        
        # Block internal network scanning (SSRF Protection)
        blocked_domains = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254']
        if hostname in blocked_domains or hostname.startswith('192.168.') or hostname.startswith('10.'):
            logging.critical(f"SSRF Attack Blocked! Attempted access to internal IP: {hostname}")
            raise HTTPException(status_code=403, detail="Forbidden: Security Shield blocked internal routing.")
            
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Bad Request: Malformed URL detected.")

def sanitize_headers(original_headers: dict) -> dict:
    """
    Strips away Vercel's identifying headers and injects standard Chrome headers 
    to trick the target site into thinking it's a real human.
    """
    safe_headers = dict(original_headers)
    
    # Strip identifying tags
    suspicious_tags = ['host', 'x-forwarded-for', 'x-real-ip', 'x-vercel-id']
    for tag in suspicious_tags:
        safe_headers.pop(tag, None)
        
    # Inject camouflage
    safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    return safe_headers

# ----------------- MAIN PROXY ENDPOINT -----------------

@app.get("/proxy")
async def gateway_proxy_handler(request: Request, target_url: str, x_api_key: str = Header(None)):
    """
    The Nano-Second Tunnel: Authenticates, decrypts a proxy, sanitizes the request, 
    and streams the video data back in real-time.
    """
    # 1. Zero Trust Authentication
    if not x_api_key or x_api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API Key.")
        
    # 2. URL Sentinel Shield Validation
    url_sentinel_shield(target_url)

    # 3. Instant Vault Access & Decryption
    encrypted_ip_bytes = await redis_vault.spop("vip_proxy_pool")
    if not encrypted_ip_bytes:
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

    # 5. Nano-Second Binary Streaming (No RAM filling)
    try:
        # We use a large timeout because video files take time to stream
        async with httpx.AsyncClient(proxies=proxies, timeout=60.0) as client:
            upstream_request = client.build_request("GET", target_url, headers=camouflaged_headers)
            upstream_response = await client.send(upstream_request, stream=True)
            
            return StreamingResponse(
                upstream_response.aiter_bytes(), 
                status_code=upstream_response.status_code,
                media_type=upstream_response.headers.get("content-type")
            )
            
    except Exception as e:
        logging.error(f"Proxy routing failed via {decrypted_ip}. Target: {target_url}. Error: {str(e)}")
        raise HTTPException(status_code=502, detail="Bad Gateway: Upstream server dropped the connection.")

# ----------------- DASHBOARD / HEALTH MONITORING -----------------

@app.get("/health")
async def health_check():
    """Returns gateway status for the UI Dashboard."""
    vault_count = await redis_vault.scard("vip_proxy_pool")
    return {
        "status": "online",
        "shield": "active",
        "available_ips": vault_count
    }
