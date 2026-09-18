import asyncio
import httpx
import time
import os
import sys
import logging
import secrets
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import redis.asyncio as redis
from cryptography.fernet import Fernet
from urllib.parse import urlparse

# Security Guard: Block execution if run as root user
def enforce_security_guard():
    if os.name == 'posix' and os.geteuid() == 0:
        print("[CRITICAL SECURITY ERROR] Running engine as 'ROOT' is strictly forbidden!")
        sys.exit(1)

enforce_security_guard()

# Professional logging setup for Engine 4 Master Gateway
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE-4: ULTRA-GATEWAY] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream 4X Gateway", version="5.5.0")

# Enterprise-grade fixed encryption key synchronized across engines
DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

# Master Admin Key for Control Panel authentication
MASTER_ADMIN_KEY = os.environ.get("MASTER_ADMIN_KEY", "nanostream_master_secure_2026")

# Environment-driven secure Redis configuration
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

# --- REAL-TIME WEBSOCKET CONNECTION MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, data: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                pass

manager = ConnectionManager()

async def emit_gateway_telemetry(status: str, client_slot: str, target_domain: str, execution_time: float):
    """Broadcasts real-time routing telemetry to dashboard via WebSocket."""
    payload = {
        "engine": "master_4_gateway",
        "status": status,
        "client_slot": client_slot,
        "target_domain": target_domain,
        "execution_time_sec": round(execution_time, 4)
    }
    await manager.broadcast(payload)

app.state.ui_broadcast = emit_gateway_telemetry

@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """Live WebSocket channel for real-time frontend dashboard streaming."""
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- ADMIN API ENDPOINTS ---
class KeyGenRequest(BaseModel):
    client_name: str
    expiry_seconds: int | None = None

@app.post("/admin/keys/generate")
async def generate_api_key(req: KeyGenRequest, request: Request):
    """Generates and stores a new client API key in Redis DB 1."""
    admin_header = request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key")
    if admin_header != MASTER_ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid Master Admin Key.")
    
    api_key = f"ns_{secrets.token_hex(16)}"
    key_prefix = api_key[:8] + "..."
    
    await redis_vault_keys.set(f"api_key:{api_key}", req.client_name)
    logging.info(f"API Key successfully generated for client: {req.client_name}")
    return {"client_name": req.client_name, "api_key": api_key, "key_prefix": key_prefix}

@app.get("/admin/keys/list")
async def list_active_keys(request: Request):
    """Retrieves active client list from Redis DB 1 vault."""
    admin_header = request.headers.get("x-admin-key") or request.headers.get("X-Admin-Key")
    if admin_header != MASTER_ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Forbidden: Invalid Master Admin Key.")
    
    keys = await redis_vault_keys.keys("api_key:*")
    active_clients = []
    for k in keys:
        client_name = await redis_vault_keys.get(k)
        raw_key = k.replace("api_key:", "")
        active_clients.append({
            "client_name": client_name,
            "key_prefix": raw_key[:8] + "...",
            "type": "Permanent"
        })
    return {"active_clients": active_clients}

# --- PROXY CORE ROUTING & SECURITY ---
BLOCKED_INTERNAL_HOSTS = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'}

def url_sentinel_shield(target_url: str, client_slot: str) -> str:
    """Blocks SSRF attacks against internal network resources."""
    try:
        parsed_url = urlparse(target_url)
        hostname = parsed_url.hostname.lower() if parsed_url.hostname else "unknown_domain"
        if hostname in BLOCKED_INTERNAL_HOSTS or hostname.startswith(('192.168.', '10.', '172.16.')):
            raise HTTPException(status_code=403, detail="Forbidden: SSRF Shield blocked internal routing.")
        return hostname
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Bad Request: Malformed target URL.")

def sanitize_headers(original_headers: dict) -> dict:
    """Strips tracking headers and normalizes User-Agent."""
    safe_headers = dict(original_headers)
    for tag in ['host', 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip', 'via']:
        safe_headers.pop(tag, None)
    safe_headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    return safe_headers

async def proxy_stream_generator(client: httpx.AsyncClient, response: httpx.Response):
    """Streams data chunks securely and closes connections."""
    try:
        async for chunk in response.aiter_bytes(chunk_size=65536):
            yield chunk
    finally:
        await response.aclose()
        await client.aclose()

@app.get("/proxy")
async def gateway_proxy_handler(request: Request, background_tasks: BackgroundTasks, target_url: str):
    """High-performance proxy routing endpoint with API key check and Vault decryption."""
    start_time = time.time()
    x_api_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
    
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Unauthorized: API Key missing.")
        
    client_slot_name = await redis_vault_keys.get(f"api_key:{x_api_key}") or await redis_vault_keys.get(x_api_key)
    if not client_slot_name:
        background_tasks.add_task(emit_gateway_telemetry, "auth_failed", "Unknown Hacker", "N/A", time.time() - start_time)
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API Key.")

    target_domain = url_sentinel_shield(target_url, client_slot_name)
    encrypted_ip_bytes = await redis_vault_proxies.spop("vip_proxy_pool")
    
    if not encrypted_ip_bytes:
        background_tasks.add_task(emit_gateway_telemetry, "vault_empty_error", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=503, detail="Service Unavailable: Proxy Vault is empty.")
        
    try:
        if isinstance(encrypted_ip_bytes, str):
            encrypted_ip_bytes = encrypted_ip_bytes.encode('utf-8')
        decrypted_ip = cipher_suite.decrypt(encrypted_ip_bytes).decode('utf-8')
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Security Error: Token decryption failed.")

    proxy_url = f"http://{decrypted_ip}"
    camouflaged_headers = sanitize_headers(request.headers)

    try:
        transport = httpx.AsyncHTTPTransport(proxy=proxy_url)
        proxy_client = httpx.AsyncClient(transport=transport, timeout=httpx.Timeout(15.0, read=None), follow_redirects=True)
        upstream_response = await proxy_client.get(target_url, headers=camouflaged_headers, stream=True)
        
        exec_time = time.time() - start_time
        background_tasks.add_task(emit_gateway_telemetry, "tunnel_established", client_slot_name, target_domain, exec_time)
        
        return StreamingResponse(proxy_stream_generator(proxy_client, upstream_response), status_code=upstream_response.status_code)
    except Exception as e:
        background_tasks.add_task(emit_gateway_telemetry, "upstream_timeout", client_slot_name, target_domain, time.time() - start_time)
        raise HTTPException(status_code=502, detail="Bad Gateway: Upstream connection failed.")

@app.get("/health")
async def health_check():
    """System health metrics endpoint."""
    vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
    active_keys_count = len(await redis_vault_keys.keys("api_key:*"))
    return {"status": "online", "shield": "active", "available_proxy_ips": vault_count, "active_clients": active_keys_count}
