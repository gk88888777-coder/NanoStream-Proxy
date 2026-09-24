import asyncio
import uvicorn
import json
import secrets
import re
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
from core.master4_gateway import app as gateway_app, close_gateway_resources

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [NANOSTREAM-MASTER-CORE] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

app = FastAPI(title="NanoStream-Proxy Control Room", version="7.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_URL = os.environ.get("BASE_URL", "https://nanostream4x.duckdns.org")

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

ADMIN_MASTER_KEY = os.environ.get("ADMIN_MASTER_KEY", "gaurav332").strip()
admin_api_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)

background_worker_tasks: List[asyncio.Task] = []

def get_real_client_ip(request: Request) -> str:
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

async def verify_local_admin_shield(request: Request, admin_key: Optional[str] = Security(admin_api_key_header)):
    client_ip = get_real_client_ip(request)
    
    if client_ip not in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"]:
        if await redis_vault_keys.exists(f"auto_blocked_ip:{client_ip}") or await redis_vault_keys.exists(f"auto_blocked:{client_ip}"):
            raise HTTPException(
                status_code=403, 
                detail="Forbidden: Your IP has been locked out due to repeated security violations."
            )

    submitted_key = admin_key or request.headers.get("x-admin-key") or request.query_params.get("admin_key")
    clean_submitted_key = submitted_key.strip() if submitted_key else ""
    
    if not secrets.compare_digest(clean_submitted_key, ADMIN_MASTER_KEY):
        if client_ip not in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"]:
            fail_key = f"admin_fail_attempts:{client_ip}"
            fails = await redis_vault_keys.incr(fail_key)
            if fails == 1:
                await redis_vault_keys.expire(fail_key, 60)
                
            if fails >= 5:
                await redis_vault_keys.setex(f"auto_blocked_ip:{client_ip}", 1800, "admin_brute_force")
                logging.critical(f"ADMIN BRUTE FORCE ALERT: IP {client_ip} banned for 30 minutes after {fails} wrong attempts.")
                raise HTTPException(status_code=403, detail="Forbidden: Too many invalid admin key attempts. IP banned for 30 minutes.")

            logging.critical(f"SECURITY ALERT: Invalid Master Admin Key attempt ({fails}/5) from IP {client_ip}")
            raise HTTPException(status_code=403, detail=f"Forbidden: Master Admin Key Invalid. Attempt {fails}/5.")
        else:
            raise HTTPException(status_code=403, detail="Forbidden: Master Admin Key Invalid.")

    await redis_vault_keys.delete(f"admin_fail_attempts:{client_ip}")
    return clean_submitted_key

@app.middleware("http")
async def lightning_rate_limit_and_shield_middleware(request: Request, call_next):
    if request.url.path.startswith("/gateway"):
        client_ip = get_real_client_ip(request)
        
        if client_ip not in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost", "unknown"]:
            try:
                if await redis_vault_keys.exists(f"auto_blocked_ip:{client_ip}") or await redis_vault_keys.exists(f"auto_blocked:{client_ip}"):
                    return JSONResponse(
                        status_code=403, 
                        content={"detail": "Forbidden: Your IP/Key has been auto-blocked due to security violation or rate limit."}
                    )
                    
                current_second = int(time.time())
                redis_rate_key = f"rl:{client_ip}:{current_second}"
                
                pipe = redis_vault_keys.pipeline()
                pipe.incr(redis_rate_key)
                pipe.expire(redis_rate_key, 2)
                results = await pipe.execute()
                requests_this_second = results[0]
                    
                if requests_this_second > 60:
                    logging.warning(f"RATE LIMIT BREACH: Auto-blocking client/IP {client_ip} for exceeding 60 req/sec.")
                    await redis_vault_keys.setex(f"auto_blocked:{client_ip}", 600, "rate_limit_exceeded")
                    return JSONResponse(
                        status_code=429, 
                        content={"detail": "Too Many Requests: Limit is 60 req/sec. Key/IP has been auto-blocked for 10 minutes."}
                    )
            except Exception as ex:
                logging.error(f"Rate limit middleware redis error (fail-open): {ex}")
    return await call_next(request)

active_websockets: List[WebSocket] = []

async def send_ws_payload(ws: WebSocket, data: str) -> Optional[WebSocket]:
    try:
        await asyncio.wait_for(ws.send_text(data), timeout=1.5)
        return None
    except Exception:
        return ws

async def ui_dashboard_broadcaster(payload: Dict[str, Any]):
    if not active_websockets:
        return
    data = json.dumps(payload)
    sockets_snapshot = list(active_websockets)
    
    results = await asyncio.gather(*[send_ws_payload(ws, data) for ws in sockets_snapshot], return_exceptions=True)
    
    for dead_ws in results:
        if isinstance(dead_ws, WebSocket) and dead_ws in active_websockets:
            try:
                await dead_ws.close()
            except Exception:
                pass
            active_websockets.remove(dead_ws)

@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    
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
        
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        if websocket in active_websockets:
            try:
                await websocket.close()
            except Exception:
                pass
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
                logging.info(f"[SUPPLY CHAIN] Pool count ({current_ips}) below minimum ({min_ips}). Activating Hunter...")
                raw_ips = await hunter.execute_hunt()
                if raw_ips:
                    await inspector.execute_inspection(raw_ips)
        except asyncio.CancelledError:
            break
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
        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"Error in Maintenance Loop: {e}")
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup_event():
    logging.info("NanoStream System Booting: 4-Engine Architecture online with Zero-Trust Security & Pooling...")
    
    # 1. Enable Hard-Disk Persistence (AOF) on Redis so data is NEVER lost across reboots
    try:
        await redis_vault_keys.config_set("appendonly", "yes")
        await redis_vault_keys.config_set("save", "900 1 300 10 60 10000")
        logging.info("[DATA PERSISTENCE SHIELD] Redis AOF disk-persistence verified and active.")
    except Exception as persist_err:
        logging.warning(f"[DATA PERSISTENCE] Redis CONFIG command restricted or preset by host: {persist_err}")

    # 2. Master Client Passport Persistence
    default_client_key = "gk(GK)321"
    default_client_name = "GK_Master_Client"
    redis_key_name = f"api_key:{default_client_key}"
    
    try:
        if not await redis_vault_keys.exists(redis_key_name):
            await redis_vault_keys.set(redis_key_name, default_client_name)
            logging.info(f"DEFAULT CLIENT KEY INITIALIZED: {default_client_key} ({default_client_name})")
        
        await redis_vault_keys.persist(redis_key_name)
        await redis_vault_keys.sadd("active_keys_registry", default_client_key)

        existing_keys = await redis_vault_keys.keys("api_key:*")
        if existing_keys:
            tokens = [k.replace("api_key:", "") for k in existing_keys]
            await redis_vault_keys.sadd("active_keys_registry", *tokens)
            logging.info(f"[KEY RECOVERY] Successfully loaded {len(tokens)} existing client keys into active registry.")
            
    except Exception as e:
        logging.error(f"Startup Redis synchronization failed: {e}")

    task1 = asyncio.create_task(proxy_supply_chain_loop())
    task2 = asyncio.create_task(vault_maintenance_loop())
    background_worker_tasks.extend([task1, task2])

@app.on_event("shutdown")
async def shutdown_event():
    logging.info("NanoStream System Shutdown initiated. Cleaning up worker tasks and Redis pools...")
    for task in background_worker_tasks:
        task.cancel()
    await asyncio.gather(*background_worker_tasks, return_exceptions=True)
    await redis_vault_proxies.aclose()
    await redis_pool_proxies.disconnect()
    await redis_vault_keys.aclose()
    await redis_pool_keys.disconnect()
    await close_gateway_resources()
    logging.info("Cleanup complete. Shutdown successful.")

class CreateKeyRequest(BaseModel):
    client_name: str
    expiry_seconds: Optional[int] = None
    custom_api_key: Optional[str] = None

class KeyRevokeRequest(BaseModel):
    client_name: Optional[str] = None
    target_key: Optional[str] = None

SAFE_KEY_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.\(\)]+$')

@app.post("/admin/keys/generate", dependencies=[Depends(verify_local_admin_shield)])
async def generate_api_key(request: CreateKeyRequest):
    clean_client_name = request.client_name.strip()
    if not clean_client_name:
        raise HTTPException(status_code=400, detail="Client name cannot be empty.")

    clean_custom_key = request.custom_api_key.strip() if request.custom_api_key else None
    if clean_custom_key:
        if not SAFE_KEY_PATTERN.match(clean_custom_key):
            raise HTTPException(
                status_code=400, 
                detail="Bad Request: Custom API key contains invalid characters. Only alphanumeric, '_', '-', '.', and '()' are allowed."
            )

    new_key = clean_custom_key if clean_custom_key else f"ns_{secrets.token_hex(16)}"
    redis_key_name = f"api_key:{new_key}"
    
    if await redis_vault_keys.exists(redis_key_name):
        raise HTTPException(status_code=409, detail=f"Conflict: API Key '{new_key}' already exists in vault.")

    if request.expiry_seconds and request.expiry_seconds > 0:
        await redis_vault_keys.setex(redis_key_name, request.expiry_seconds, clean_client_name)
        key_type = "subscription_timed"
    else:
        await redis_vault_keys.set(redis_key_name, clean_client_name)
        key_type = "permanent_unlimited"
        
    await redis_vault_keys.sadd("active_keys_registry", new_key)
    logging.info(f"ADMIN ACTION -> Generated {key_type} key for client: {clean_client_name}")

    stream_url = f"{BASE_URL}/gateway/proxy?key={new_key}&target_url="
    curl_command = f'curl -H "x-api-key: {new_key}" "{BASE_URL}/gateway/proxy?target_url=https://httpbin.org/ip"'

    return {
        "message": "Key generated successfully under secure admin lock",
        "api_key": new_key,
        "key_id": new_key,
        "full_key": new_key,
        "key_prefix": new_key,
        "client_name": clean_client_name,
        "type": key_type,
        "stream_url": stream_url,
        "curl_cmd": curl_command,
        "curl_command": curl_command
    }

@app.post("/admin/keys/revoke", dependencies=[Depends(verify_local_admin_shield)])
async def revoke_api_key_by_name(request: KeyRevokeRequest):
    if request.target_key:
        clean_target = request.target_key.strip()
        raw_token = clean_target.replace("api_key:", "")
        if raw_token in ["gk(GK)321", "GK_Master_Client"]:
            raise HTTPException(status_code=403, detail="Forbidden: Cannot revoke Master Client Passport.")

        full_redis_key = f"api_key:{raw_token}"
        deleted = await redis_vault_keys.delete(full_redis_key)
        await redis_vault_keys.srem("active_keys_registry", raw_token)
        
        if deleted:
            logging.info(f"ADMIN ACTION -> Revoked specific key: {raw_token}")
            return {"status": "success", "message": f"Revoked single key: {raw_token}"}
        else:
            raise HTTPException(status_code=404, detail="Target API Key not found in vault.")

    if request.client_name:
        clean_name = request.client_name.strip()
        if clean_name in ["GK_Master_Client"]:
            raise HTTPException(status_code=403, detail="Forbidden: Cannot revoke Master Client Passport.")

        all_registered_keys = await redis_vault_keys.smembers("active_keys_registry")
        revoked_count = 0
        
        for k in all_registered_keys:
            if k == "gk(GK)321":
                continue
            stored_name = await redis_vault_keys.get(f"api_key:{k}")
            if stored_name == clean_name:
                await redis_vault_keys.delete(f"api_key:{k}")
                await redis_vault_keys.srem("active_keys_registry", k)
                revoked_count += 1
                
        if revoked_count > 0:
            logging.info(f"ADMIN ACTION -> Revoked {revoked_count} keys for client: {clean_name}")
            return {"status": "success", "message": f"Revoked {revoked_count} keys for client: {clean_name}"}
        else:
            raise HTTPException(status_code=404, detail=f"No active keys found for client: {clean_name}")

    raise HTTPException(status_code=400, detail="Must provide either target_key or client_name to revoke.")

@app.get("/admin/keys/list", dependencies=[Depends(verify_local_admin_shield)])
async def list_api_keys():
    all_keys = list(await redis_vault_keys.smembers("active_keys_registry"))
    if not all_keys:
        return {"active_clients": [], "total_active": 0}

    pipe = redis_vault_keys.pipeline()
    for raw_key in all_keys:
        k = f"api_key:{raw_key}"
        pipe.ttl(k)
        pipe.get(k)
    results = await pipe.execute()

    active_clients = []
    dead_keys = []

    for idx, raw_key in enumerate(all_keys):
        ttl = results[idx * 2]
        client_name = results[idx * 2 + 1]

        if ttl == -2 or not client_name:
            dead_keys.append(raw_key)
            continue

        stream_url = f"{BASE_URL}/gateway/proxy?key={raw_key}&target_url="
        curl_command = f'curl -H "x-api-key: {raw_key}" "{BASE_URL}/gateway/proxy?target_url=https://httpbin.org/ip"'

        active_clients.append({
            "key_id": raw_key,
            "key_prefix": raw_key,
            "full_key": raw_key,
            "client_name": client_name,
            "type": "permanent" if ttl == -1 else f"expires_in_{ttl}_secs",
            "stream_url": stream_url,
            "curl_cmd": curl_command,
            "curl_command": curl_command
        })

    if dead_keys:
        await redis_vault_keys.srem("active_keys_registry", *dead_keys)
        
    active_clients.sort(key=lambda x: (x["type"] != "permanent", x["client_name"].lower()))
    return {"active_clients": active_clients, "total_active": len(active_clients)}

@app.get("/health")
async def root_health_check():
    try:
        vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
        active_keys_count = await redis_vault_keys.scard("active_keys_registry")
        return {
            "status": "system_healthy",
            "shield": "active",
            "vip_pool_ips": vault_count,
            "active_clients": active_keys_count,
            "engines_online": 4
        }
    except Exception as e:
        return {"status": "degraded", "error": str(e)}

@app.get("/")
async def premium_dashboard():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_dir, "index.html")
        
        if os.path.exists(file_path):
            return FileResponse(
                file_path,
                headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
            )
            
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
