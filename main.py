import asyncio
import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import redis.asyncio as redis
import uuid
import logging
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
app = FastAPI(title="NanoStream-Proxy Control Room", version="1.0.0")

# Enable CORS for the future UI Dashboard
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

# ----------------- UI WEBSOCKET BROADCASTER (DUMMY FOR NOW) -----------------
# When we build the actual UI Dashboard, this function will push real-time JSON to the browser.
async def ui_dashboard_broadcaster(payload: Dict[str, Any]):
    # For now, it logs the telemetry to the terminal so we can see the engines working.
    logging.info(f"[TELEMETRY] -> {payload}")

# Attach the broadcaster to the Gateway app so it can send live data
gateway_app.state.ui_broadcast = ui_dashboard_broadcaster

# Initialize Core Engines
hunter = ProxyHunter(ui_broadcast_callback=ui_dashboard_broadcaster)
inspector = ProxyInspector(ui_broadcast_callback=ui_dashboard_broadcaster)
doctor = VaultDoctor(ui_broadcast_callback=ui_dashboard_broadcaster)

# ----------------- BACKGROUND ORCHESTRATION LOOPS -----------------

async def proxy_supply_chain_loop():
    """
    Continuous loop: Monitors the vault. If IPs fall below the safe threshold,
    triggers the Hunter to scrape raw IPs, then passes them to the Inspector.
    """
    logging.info("Starting Proxy Supply Chain Loop...")
    while True:
        try:
            current_ips = await redis_vault_proxies.scard("vip_proxy_pool")
            # Using the threshold defined in the Doctor (5000)
            if current_ips < doctor.minimum_healthy_ips:
                logging.warning(f"Vault low ({current_ips} IPs). Triggering Hunt & Inspect cycle.")
                raw_ips = await hunter.execute_hunt()
                if raw_ips:
                    await inspector.execute_inspection(raw_ips)
            else:
                logging.debug(f"Vault healthy ({current_ips} IPs). Sleeping...")
        except Exception as e:
            logging.error(f"Error in Supply Chain Loop: {e}")
            
        # Check every 30 seconds
        await asyncio.sleep(30) 

async def vault_maintenance_loop():
    """
    Continuous loop: Triggers the Vault Doctor to purge dead IPs every 5 minutes.
    """
    logging.info("Starting Vault Maintenance Loop...")
    while True:
        try:
            # Let the doctor do its purge cycle
            await doctor.execute_maintenance_cycle()
        except Exception as e:
            logging.error(f"Error in Maintenance Loop: {e}")
            
        # Run maintenance every 5 minutes (300 seconds)
        await asyncio.sleep(300)

# ----------------- SERVER LIFECYCLE -----------------

@app.on_event("startup")
async def startup_event():
    """Starts the background loops when the main server boots up."""
    logging.info("System Booting: Igniting 4-Engine Architecture...")
    asyncio.create_task(proxy_supply_chain_loop())
    asyncio.create_task(vault_maintenance_loop())
    logging.info("All engines online. System is ready.")

# ----------------- CONTROL PANEL APIs (API KEY MANAGEMENT) -----------------

class CreateKeyRequest(BaseModel):
    client_name: str

@app.post("/admin/keys/generate")
async def generate_api_key(request: CreateKeyRequest):
    """Admin API: Generates a new API Key for a client/software."""
    new_key = f"ns_{uuid.uuid4().hex}"
    # Store in Redis Vault 1
    await redis_vault_keys.set(f"api_key:{new_key}", request.client_name)
    return {"message": "Key generated successfully", "api_key": new_key, "client_name": request.client_name}

@app.delete("/admin/keys/revoke/{api_key}")
async def revoke_api_key(api_key: str):
    """Admin API: Instantly revokes access for a specific API Key."""
    result = await redis_vault_keys.delete(f"api_key:{api_key}")
    if result == 0:
        raise HTTPException(status_code=404, detail="API Key not found.")
    return {"message": "Key revoked successfully"}

@app.get("/admin/keys/list")
async def list_api_keys():
    """Admin API: Lists all active clients (hides the full key for security)."""
    keys = await redis_vault_keys.keys("api_key:*")
    active_clients = []
    for k in keys:
        client_name = await redis_vault_keys.get(k)
        active_clients.append({"key_prefix": k.split(":")[1][:8] + "...", "client_name": client_name})
    return {"active_clients": active_clients, "total_active": len(keys)}


# ----------------- MOUNTING THE GATEWAY -----------------
# We mount Engine 4 (The Gateway) onto the main orchestrator at the /gateway path.
# So requests will go to: http://your-server-ip:8000/gateway/proxy?...
app.mount("/gateway", gateway_app)

# ----------------- RUN THE SERVER -----------------
if __name__ == "__main__":
    # Runs the Orchestrator on port 8000
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
