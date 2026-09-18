import asyncio
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import redis.asyncio as redis
import uuid
import logging
import time
import os
from typing import Dict, Any

# 1. Importing the 4 Engines
from core.master1_hunter import ProxyHunter
from core.master2_inspector import ProxyInspector
from core.master3_vault_doctor import VaultDoctor
from core.master4_gateway import app as gateway_app

# Professional Logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ORCHESTRATOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 2. Initialize the Main Orchestrator App
app = FastAPI(title="NanoStream-Proxy Control Room", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis connections
redis_vault_proxies = redis.Redis(host='127.0.0.1', port=6379, db=0)
redis_vault_keys = redis.Redis(host='127.0.0.1', port=6379, db=1, decode_responses=True)

# --- SECURITY LAYER 1: ADMIN MASTER KEY ---
# Only you (the owner) will have this key. Without it, no one can generate API keys.
ADMIN_MASTER_KEY = os.environ.get("ADMIN_MASTER_KEY", "nano_admin_777_secure")
admin_api_key_header = APIKeyHeader(name="X-Admin-Key")

def verify_admin(admin_key: str = Security(admin_api_key_header)):
    if admin_key != ADMIN_MASTER_KEY:
        logging.critical(f"Hacking Attempt: Invalid Admin Key used -> {admin_key}")
        raise HTTPException(status_code=403, detail="Forbidden: Master Admin Key Invalid.")
    return admin_key

# --- SECURITY LAYER 2: DDoS & RATE LIMITING SHIELD ---
@app.middleware("http")
async def ddos_protection_middleware(request: Request, call_next):
    # Apply strict rate limiting to the gateway tunnel
    if request.url.path.startswith("/gateway/proxy"):
        client_id = request.headers.get("x-api-key", request.client.host)
        current_second = int(time.time())
        redis_rate_key = f"rate_limit:{client_id}:{current_second}"
        
        # Count requests per second
        requests_this_second = await redis_vault_keys.incr(redis_rate_key)
        if requests_this_second == 1:
            await redis_vault_keys.expire(redis_rate_key, 2) # Clean up memory instantly
            
        # Limit: 50 requests per second per client
        if requests_this_second > 50:
            logging.warning(f"DDoS Shield Active: Blocked {client_id} for exceeding 50 req/sec.")
            return JSONResponse(
                status_code=429, 
                content={"detail": "Too Many Requests: DDoS protection triggered. Slow down."}
            )
            
    return await call_next(request)

# ----------------- UI WEBSOCKET BROADCASTER -----------------
async def ui_dashboard_broadcaster(payload: Dict[str, Any]):
    logging.info(f"[TELEMETRY] -> {payload}")

gateway_app.state.ui_broadcast = ui_dashboard_broadcaster

hunter = ProxyHunter(ui_broadcast_callback=ui_dashboard_broadcaster)
inspector = ProxyInspector(ui_broadcast_callback=ui_dashboard_broadcaster)
doctor = VaultDoctor(ui_broadcast_callback=ui_dashboard_broadcaster)

# ----------------- BACKGROUND ORCHESTRATION LOOPS -----------------
async def proxy_supply_chain_loop():
    logging.info("Starting Proxy Supply Chain Loop...")
    while True:
        try:
            current_ips = await redis_vault_proxies.scard("vip_proxy_pool")
            if current_ips < doctor.minimum_healthy_ips:
                logging.warning(f"Vault low ({current_ips} IPs). Triggering Hunt & Inspect cycle.")
                raw_ips = await hunter.execute_hunt()
                if raw_ips:
                    await inspector.execute_inspection(raw_ips)
            else:
                logging.debug(f"Vault healthy ({current_ips} IPs). Sleeping...")
        except Exception as e:
            logging.error(f"Error in Supply Chain Loop: {e}")
        await asyncio.sleep(30) 

async def vault_maintenance_loop():
    logging.info("Starting Vault Maintenance Loop...")
    while True:
        try:
            await doctor.execute_maintenance_cycle()
        except Exception as e:
            logging.error(f"Error in Maintenance Loop: {e}")
        await asyncio.sleep(300)

@app.on_event("startup")
async def startup_event():
    logging.info("System Booting: Igniting 4-Engine Architecture with DDoS Shield...")
    asyncio.create_task(proxy_supply_chain_loop())
    asyncio.create_task(vault_maintenance_loop())

# ----------------- CONTROL PANEL APIs (SECURED) -----------------

class CreateKeyRequest(BaseModel):
    client_name: str

@app.post("/admin/keys/generate", dependencies=[Depends(verify_admin)])
async def generate_api_key(request: CreateKeyRequest):
    new_key = f"ns_{uuid.uuid4().hex}"
    await redis_vault_keys.set(f"api_key:{new_key}", request.client_name)
    return {"message": "Key generated successfully", "api_key": new_key, "client_name": request.client_name}

@app.delete("/admin/keys/revoke/{api_key}", dependencies=[Depends(verify_admin)])
async def revoke_api_key(api_key: str):
    result = await redis_vault_keys.delete(f"api_key:{api_key}")
    if result == 0:
        raise HTTPException(status_code=404, detail="API Key not found.")
    return {"message": "Key revoked successfully"}

@app.get("/admin/keys/list", dependencies=[Depends(verify_admin)])
async def list_api_keys():
    keys = await redis_vault_keys.keys("api_key:*")
    active_clients = []
    for k in keys:
        client_name = await redis_vault_keys.get(k)
        active_clients.append({"key_prefix": k.split(":")[1][:8] + "...", "client_name": client_name})
    return {"active_clients": active_clients, "total_active": len(keys)}

# ----------------- SERVING THE PREMIUM UI -----------------
@app.get("/")
async def premium_dashboard():
    return FileResponse("index.html")

# ----------------- MOUNTING THE GATEWAY -----------------
app.mount("/gateway", gateway_app)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
