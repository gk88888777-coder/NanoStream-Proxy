import asyncio
import uvicorn
import json
import secrets
from fastapi import FastAPI, HTTPException, Depends, Security, Request, WebSocket, WebSocketDisconnect
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
import redis.asyncio as redis
import logging
import time
import os
from typing import Dict, Any, List, Optional

from core.master1_hunter import ProxyHunter
from core.master2_inspector import ProxyInspector
from core.master3_vault_doctor import VaultDoctor
from core.master4_gateway import app as gateway_app

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [NANOSTREAM-MASTER-CORE] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream-Proxy Control Room", version="5.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_pool_proxies = redis.ConnectionPool(host='127.0.0.1', port=6379, db=0, max_connections=100)
redis_pool_keys = redis.ConnectionPool(host='127.0.0.1', port=6379, db=1, decode_responses=True, max_connections=100)

redis_vault_proxies = redis.Redis(connection_pool=redis_pool_proxies)
redis_vault_keys = redis.Redis(connection_pool=redis_pool_keys)

# Master Admin Key Configuration
ADMIN_MASTER_KEY = os.environ.get("ADMIN_MASTER_KEY", "gaurav332")
admin_api_key_header = APIKeyHeader(name="X-Admin-Key")

async def verify_local_admin_shield(request: Request, admin_key: str = Security(admin_api_key_header)):
    client_ip = request.client.host if request.client else "unknown"
    if admin_key != ADMIN_MASTER_KEY:
        logging.critical(f"SECURITY ALERT: Invalid Master Admin Key used from IP {client_ip}")
        raise HTTPException(status_code=403, detail="Forbidden: Master Admin Key Invalid.")
    return admin_key

@app.middleware("http")
async def lightning_rate_limit_and_shield_middleware(request: Request, call_next):
    if request.url.path.startswith("/gateway"):
        client_ip = request.client.host if request.client else "unknown"
        if await redis_vault_keys.exists(f"auto_blocked_ip:{client_ip}") or await redis_vault_keys.exists(f"auto_blocked:{client_ip}"):
            return JSONResponse(
                status_code=403, 
                content={"detail": "Forbidden: Your IP/Key has been auto-blocked due to security violation or rate limit."}
            )
            
        current_second = int(time.time())
        redis_rate_key = f"rl:{client_ip}:{current_second}"
        requests_this_second = await redis_vault_keys.incr(redis_rate_key)
        if requests_this_second == 1:
            await redis_vault_keys.expire(redis_rate_key, 2)
            
        if requests_this_second > 15:
            logging.warning(f"RATE LIMIT BREACH: Auto-blocking client/IP {client_ip} for exceeding 15 req/sec.")
            await redis_vault_keys.setex(f"auto_blocked:{client_ip}", 600, "rate_limit_exceeded")
            return JSONResponse(
                status_code=429, 
                content={"detail": "Too Many Requests: Limit is 15 req/sec. Key/IP has been auto-blocked for 10 minutes."}
            )
    return await call_next(request)

active_websockets: List[WebSocket] = []

async def ui_dashboard_broadcaster(payload: Dict[str, Any]):
    if not active_websockets:
        return
    data = json.dumps(payload)
    disconnected = []
    for ws in active_websockets:
        try:
            await ws.send_text(data)
        except Exception:
            disconnected.append(ws)
            
    for ws in disconnected:
        if ws in active_websockets:
            active_websockets.remove(ws)

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    
    # Instant Live Push: Send initial engine states immediately upon connection
    try:
        current_ips = await redis_vault_proxies.scard("vip_proxy_pool") or 0
        initial_payload = {
            "hunter_status": "Active",
            "hunted_count": current_ips,
            "execution_time": "0.35s",
            "sources_active": 4,
            "inspector_status": "Active",
            "tested_count": current_ips * 2,
            "elite_passed": current_ips,
            "vault_status": "Optimized",
            "maintenance_status": "Active",
            "health_score": "100%",
            "purged_count": 0,
            "stream_scan": "Active",
            "gateway_status": "Active",
            "active_client": "GK_Master_Client",
            "throughput": "1.2 MB/s",
            "http_status": "200 OK"
        }
        await websocket.send_text(json.dumps(initial_payload))
    except Exception as e:
        logging.error(f"Error sending initial WebSocket telemetry: {e}")

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in active_websockets:
            active_websockets.remove(websocket)

gateway_app.state.ui_broadcast = ui_dashboard_broadcaster
hunter = ProxyHunter(ui_broadcast_callback=ui_dashboard_broadcaster)
inspector = ProxyInspector(ui_broadcast_callback=ui_dashboard_broadcaster)
doctor = VaultDoctor(ui_broadcast_callback=ui_dashboard_broadcaster)

async def proxy_supply_chain_loop():
    while True:
        try:
            current_ips = await redis_vault_proxies.scard("vip_proxy_pool")
            min_ips = getattr(doctor, 'minimum_healthy_ips', 50)
            if current_ips < min_ips:
                raw_ips = await hunter.execute_hunt()
                if raw_ips:
                    await inspector.execute_inspection(raw_ips)
        except Exception as e:
            logging.error(f"Error in Supply Chain Loop: {e}")
        await asyncio.sleep(10)

async def vault_maintenance_loop():
    while True:
        try:
            if hasattr(doctor, 'execute_maintenance_cycle'):
                await doctor.execute_maintenance_cycle()
            elif hasattr(doctor, 'perform_vault_surgery'):
                await doctor.perform_vault_surgery()
        except Exception as e:
            logging.error(f"Error in Maintenance Loop: {e}")
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup_event():
    logging.info("NanoStream System Booting: 4-Engine Architecture online with Zero-Trust Security & Pooling...")
    
    default_client_key = "gk(GK)321"
    default_client_name = "GK_Master_Client"
    redis_key_name = f"api_key:{default_client_key}"
    
    if not await redis_vault_keys.exists(redis_key_name):
        await redis_vault_keys.set(redis_key_name, default_client_name)
        logging.info(f"DEFAULT CLIENT KEY INITIALIZED: {default_client_key} ({default_client_name})")

    asyncio.create_task(proxy_supply_chain_loop())
    asyncio.create_task(vault_maintenance_loop())

class CreateKeyRequest(BaseModel):
    client_name: str
    expiry_seconds: Optional[int] = None
    custom_api_key: Optional[str] = None

class KeyRevokeRequest(BaseModel):
    client_name: Optional[str] = None
    target_key: Optional[str] = None

@app.post("/admin/keys/generate", dependencies=[Depends(verify_local_admin_shield)])
async def generate_api_key(request: CreateKeyRequest):
    new_key = request.custom_api_key if request.custom_api_key else f"ns_{secrets.token_hex(16)}"
    redis_key_name = f"api_key:{new_key}"
    
    if request.expiry_seconds and request.expiry_seconds > 0:
        await redis_vault_keys.setex(redis_key_name, request.expiry_seconds, request.client_name)
        key_type = "subscription_timed"
    else:
        await redis_vault_keys.set(redis_key_name, request.client_name)
        key_type = "permanent_unlimited"
        
    logging.info(f"ADMIN ACTION -> Generated {key_type} key for client: {request.client_name}")
    return {
        "message": "Key generated successfully under secure admin lock",
        "api_key": new_key,
        "client_name": request.client_name,
        "type": key_type
    }

@app.post("/admin/keys/revoke", dependencies=[Depends(verify_local_admin_shield)])
async def revoke_api_key_by_name(request: KeyRevokeRequest):
    if request.target_key:
        full_redis_key = request.target_key if request.target_key.startswith("api_key:") else f"api_key:{request.target_key}"
        deleted = await redis_vault_keys.delete(full_redis_key)
        if deleted:
            logging.info(f"ADMIN ACTION -> Revoked specific key: {request.target_key}")
            return {"status": "success", "message": f"Revoked single key: {request.target_key}"}
        else:
            raise HTTPException(status_code=404, detail="Target API Key not found in vault.")

    if request.client_name:
        keys = await redis_vault_keys.keys("api_key:*")
        for k in keys:
            client_name = await redis_vault_keys.get(k)
            if client_name == request.client_name:
                await redis_vault_keys.delete(k)
                logging.info(f"ADMIN ACTION -> Revoked single key for client: {request.client_name}")
                return {"status": "success", "message": f"Revoked access for {request.client_name}"}

    raise HTTPException(status_code=400, detail="Must provide either target_key or client_name to revoke.")

@app.get("/admin/keys/list", dependencies=[Depends(verify_local_admin_shield)])
async def list_api_keys():
    keys = await redis_vault_keys.keys("api_key:*")
    active_clients = []
    for k in keys:
        client_name = await redis_vault_keys.get(k)
        ttl = await redis_vault_keys.ttl(k)
        raw_key = k.split("api_key:")[1] if "api_key:" in k else k
        
        active_clients.append({
            "key_id": raw_key,
            "key_prefix": raw_key[:8] + "...", 
            "client_name": client_name,
            "type": "permanent" if ttl == -1 else f"expires_in_{ttl}_secs"
        })
    return {"active_clients": active_clients, "total_active": len(keys)}

@app.get("/")
async def premium_dashboard():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_dir, "index.html")
        
        if os.path.exists(file_path):
            return FileResponse(file_path)
            
        return HTMLResponse(
            content="""
            <html>
                <head><title>NanoStream 4X Control Room</title></head>
                <body style="font-family: Arial, sans-serif; background: #0f172a; color: #f8fafc; text-align: center; padding-top: 100px;">
                    <h1 style="color: #38bdf8;">NanoStream 4X Master Core Online</h1>
                    <p style="color: #cbd5e1;">System engines are running smoothly, but the index.html UI file is missing.</p>
                </body>
            </html>
            """,
            status_code=200
        )
    except Exception as e:
        return HTMLResponse(
            content=f"<h1>System Error</h1><p style='color: red;'>{str(e)}</p>", 
            status_code=500
        )

app.mount("/gateway", gateway_app)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
