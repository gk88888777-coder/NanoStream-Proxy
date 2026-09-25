import asyncio
import uvicorn
import json
import secrets
import re
import inspect
from datetime import datetime
from contextlib import asynccontextmanager
from urllib.parse import urlparse
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
from core.master4_gateway import (
    app as gateway_app, 
    close_gateway_resources, 
    pool_starvation_event, 
    LOCAL_KEY_CACHE,
    start_background_tcp_proxy  # <-- Added to handle 8080 properly from main
)

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [NANOSTREAM-MASTER-CORE] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# --- Domain & Port Settings ---
BASE_URL = os.environ.get("BASE_URL", "https://nanostream4x.duckdns.org").rstrip('/')
PROXY_DOMAIN = urlparse(BASE_URL).hostname or "nanostream4x.duckdns.org"
PROXY_PORT = int(os.environ.get("PROXY_PORT", 8080))
WEB_PORT = int(os.environ.get("PORT", 8000))
# ------------------------------

REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)

MAX_SOCKET_CONNECTIONS = int(os.environ.get("MAX_SOCKET_CONNECTIONS", 4000))

redis_pool_proxies = redis.ConnectionPool(
    host=REDIS_HOST, port=REDIS_PORT, db=0, password=REDIS_PASSWORD, 
    max_connections=MAX_SOCKET_CONNECTIONS, socket_timeout=5.0, socket_connect_timeout=3.0, retry_on_timeout=True
)
redis_pool_keys = redis.ConnectionPool(
    host=REDIS_HOST, port=REDIS_PORT, db=1, password=REDIS_PASSWORD, decode_responses=True, 
    max_connections=MAX_SOCKET_CONNECTIONS, socket_timeout=5.0, socket_connect_timeout=3.0, retry_on_timeout=True
)

redis_vault_proxies = redis.Redis(connection_pool=redis_pool_proxies)
redis_vault_keys = redis.Redis(connection_pool=redis_pool_keys)

ADMIN_MASTER_KEY = os.environ.get("ADMIN_MASTER_KEY", "gaurav332").strip()
admin_api_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)

background_worker_tasks: List[asyncio.Task] = []
slot_allocation_lock = asyncio.Lock()

LATEST_TELEMETRY_CACHE: Dict[str, Any] = {
    "hunter_status": "Active",
    "hunted_count": 0,
    "execution_time": "0.00s",
    "sources_active": 55,
    "inspector_status": "Active",
    "tested_count": 0,
    "elite_passed": 0,
    "vault_status": "Optimized",
    "maintenance_status": "Active",
    "health_score": "100%",
    "purged_count": 0,
    "stream_scan": "Idle",
    "gateway_status": "Active",
    "active_client": "Fleet Core",
    "target_domain": "Standby",
    "throughput": "0.00s",
    "http_status": "200 OK",
    "enterprise_slots": "0/5 Active",
    "standard_slots": "0/500 Active"
}

async def get_max_enterprise_slots() -> int:
    val = await redis_vault_keys.get("sys:config:ent_max_slots")
    if val and str(val).isdigit():
        return int(val)
    return int(os.environ.get("ENTERPRISE_MAX_SLOTS", 5))

async def get_max_standard_slots() -> int:
    val = await redis_vault_keys.get("sys:config:std_max_slots")
    if val and str(val).isdigit():
        return int(val)
    return int(os.environ.get("STANDARD_MAX_SLOTS", 500))

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
            raise HTTPException(status_code=403, detail="Forbidden: Admin IP quarantined due to brute-force violation.")

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
                logging.critical(f"ADMIN BRUTE FORCE ALERT: IP {client_ip} banned after {fails} wrong attempts.")
                raise HTTPException(status_code=403, detail="Forbidden: Master Admin Key Invalid. IP banned.")

            logging.critical(f"SECURITY ALERT: Invalid Master Admin Key attempt ({fails}/5) from IP {client_ip}")
            raise HTTPException(status_code=403, detail=f"Forbidden: Master Admin Key Invalid. Attempt {fails}/5.")
        else:
            raise HTTPException(status_code=403, detail="Forbidden: Master Admin Key Invalid.")

    await redis_vault_keys.delete(f"admin_fail_attempts:{client_ip}")
    return clean_submitted_key

active_websockets: List[WebSocket] = []

async def send_ws_payload(ws: WebSocket, data: str) -> Optional[WebSocket]:
    try:
        await asyncio.wait_for(ws.send_text(data), timeout=1.5)
        return None
    except Exception:
        return ws

async def ui_dashboard_broadcaster(payload: Dict[str, Any]):
    global LATEST_TELEMETRY_CACHE
    LATEST_TELEMETRY_CACHE.update(payload)

    if not active_websockets:
        return

    data = json.dumps(LATEST_TELEMETRY_CACHE)
    sockets_snapshot = list(active_websockets)
    
    results = await asyncio.gather(*[send_ws_payload(ws, data) for ws in sockets_snapshot], return_exceptions=True)
    
    for dead_ws in results:
        if isinstance(dead_ws, WebSocket) and dead_ws in active_websockets:
            try:
                await dead_ws.close()
            except Exception:
                pass
            active_websockets.remove(dead_ws)

async def handle_websocket_subscription(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    
    try:
        current_ips = await redis_vault_proxies.scard("vip_proxy_pool") or 0
        enterprise_count = await redis_vault_keys.scard("enterprise_b2b_registry") or 0
        standard_count = await redis_vault_keys.scard("standard_keys_registry") or 0
        
        ent_max = await get_max_enterprise_slots()
        std_max = await get_max_standard_slots()

        LATEST_TELEMETRY_CACHE["hunted_count"] = current_ips
        LATEST_TELEMETRY_CACHE["enterprise_slots"] = f"{enterprise_count}/{ent_max} Active"
        LATEST_TELEMETRY_CACHE["standard_slots"] = f"{standard_count}/{std_max} Active"

        await websocket.send_text(json.dumps(LATEST_TELEMETRY_CACHE))
        
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

def resilient_instantiate(cls, **kwargs):
    try:
        sig = inspect.signature(cls.__init__)
        valid_kwargs = {k: v for k, v in kwargs.items() if k in sig.parameters}
        return cls(**valid_kwargs)
    except Exception:
        try:
            return cls(ui_broadcast_callback=kwargs.get('ui_broadcast_callback'))
        except Exception:
            return cls()

gateway_app.state.ui_broadcast = ui_dashboard_broadcaster

hunter = resilient_instantiate(ProxyHunter, ui_broadcast_callback=ui_dashboard_broadcaster)
inspector = resilient_instantiate(ProxyInspector, ui_broadcast_callback=ui_dashboard_broadcaster)
doctor = resilient_instantiate(VaultDoctor, ui_broadcast_callback=ui_dashboard_broadcaster)

async def proxy_supply_chain_loop():
    PROACTIVE_HUNT_INTERVAL = 300.0
    last_hunt_time = 0.0

    while True:
        try:
            now = time.time()
            current_ips = await redis_vault_proxies.scard("vip_proxy_pool") or 0
            
            MAX_VAULT_CAPACITY = 100000
            RESUME_VAULT_THRESHOLD = 99950
            if current_ips >= MAX_VAULT_CAPACITY:
                logging.info(f"[SUPPLY CHAIN] Vault capacity reached ({current_ips:,}/{MAX_VAULT_CAPACITY:,} VIP IPs). Throttling engines to standby mode...")
                while current_ips > RESUME_VAULT_THRESHOLD:
                    try:
                        await asyncio.sleep(15)
                    except asyncio.CancelledError:
                        break
                    current_ips = await redis_vault_proxies.scard("vip_proxy_pool") or 0
                logging.info(f"[SUPPLY CHAIN] Vault headroom available ({current_ips:,} IPs). Resuming Hunter and Inspector engines...")

            min_ips = getattr(doctor, 'minimum_healthy_ips', 50)
            
            is_starved = pool_starvation_event.is_set()
            is_low_pool = (current_ips < min_ips)
            is_interval_due = (now - last_hunt_time >= PROACTIVE_HUNT_INTERVAL)

            if is_starved or is_low_pool or is_interval_due:
                pool_starvation_event.clear()
                reason = "Starvation event" if is_starved else ("Low pool" if is_low_pool else "Periodic proactive refresh")
                logging.info(f"[SUPPLY CHAIN] Triggering Harvester (Reason: {reason} | Vault Pool: {current_ips} IPs)...")
                
                raw_ips = None
                if hasattr(hunter, 'execute_hunt'):
                    raw_ips = await hunter.execute_hunt()
                elif hasattr(hunter, 'hunt_proxies'):
                    raw_ips = await hunter.hunt_proxies()
                
                if raw_ips:
                    logging.info(f"[SUPPLY CHAIN] Passing {len(raw_ips):,} raw candidates to Inspector...")
                    if hasattr(inspector, 'execute_inspection'):
                        await inspector.execute_inspection(raw_ips)
                    elif hasattr(inspector, 'inspect_proxies'):
                        await inspector.inspect_proxies(raw_ips)
                
                last_hunt_time = time.time()

            try:
                await asyncio.wait_for(pool_starvation_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass

        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"[SUPPLY CHAIN] Error in Supply Chain Loop: {e}")
            await asyncio.sleep(5)

async def vault_maintenance_loop():
    await asyncio.sleep(15)
    while True:
        try:
            if hasattr(doctor, 'perform_vault_surgery'):
                await doctor.perform_vault_surgery()
            elif hasattr(doctor, 'execute_maintenance_cycle'):
                await doctor.execute_maintenance_cycle()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logging.error(f"[VAULT DOCTOR] Error in Maintenance Loop: {e}")
        await asyncio.sleep(90)

@asynccontextmanager
async def app_lifespan(app_instance: FastAPI):
    logging.info("NanoStream Booting: Hyper-Scale Event-Driven Engine Online...")
    
    try:
        await redis_vault_keys.config_set("appendonly", "yes")
        await redis_vault_keys.config_set("appendfsync", "everysec")
        await redis_vault_keys.config_set("save", "900 1 300 10 60 10000")
        logging.info("[DATA PERSISTENCE SHIELD] Redis AOF persistence active.")
    except Exception as persist_err:
        logging.warning(f"[DATA PERSISTENCE] Redis CONFIG command preset by host: {persist_err}")

    default_client_key = "gk(GK)321"
    default_client_name = "GK_Master_Client"
    redis_key_name = f"api_key:{default_client_key}"
    
    try:
        if not await redis_vault_keys.exists(redis_key_name):
            await redis_vault_keys.set(redis_key_name, default_client_name)
            await redis_vault_keys.set(f"api_key_tier:{default_client_key}", "master")
            await redis_vault_keys.set(f"api_key_country:{default_client_key}", "🌐 Global Master Root")
            await redis_vault_keys.set(f"api_key_purpose:{default_client_key}", "Root Super Admin Control")
            await redis_vault_keys.set(f"api_key_rps:{default_client_key}", 0)
            logging.info(f"DEFAULT CLIENT KEY INITIALIZED: {default_client_key} ({default_client_name})")
        
        await redis_vault_keys.persist(redis_key_name)
        await redis_vault_keys.sadd("active_keys_registry", default_client_key)

        existing_tokens = []
        async for raw_k in redis_vault_keys.scan_iter("api_key:*", count=250):
            token_str = raw_k.replace("api_key:", "")
            existing_tokens.append(token_str)

        if existing_tokens:
            await redis_vault_keys.sadd("active_keys_registry", *existing_tokens)
            
            pipe = redis_vault_keys.pipeline()
            for t in existing_tokens:
                if t != "gk(GK)321":
                    pipe.get(f"api_key_tier:{t}")
            tiers = await pipe.execute()
            
            ent_keys_to_add = []
            std_keys_to_add = []
            for t, tier in zip([t for t in existing_tokens if t != "gk(GK)321"], tiers):
                if tier == "enterprise":
                    ent_keys_to_add.append(t)
                else:
                    std_keys_to_add.append(t)
            
            if ent_keys_to_add:
                await redis_vault_keys.sadd("enterprise_b2b_registry", *ent_keys_to_add)
            if std_keys_to_add:
                await redis_vault_keys.sadd("standard_keys_registry", *std_keys_to_add)

            logging.info(f"[KEY RECOVERY] Restored {len(existing_tokens)} keys into registries atomically.")
            
    except Exception as e:
        logging.error(f"Startup Redis synchronization failed: {e}")

    task1 = asyncio.create_task(proxy_supply_chain_loop())
    task2 = asyncio.create_task(vault_maintenance_loop())
    
    # --- CRITICAL FIX: Ensure Engine 4 (TCP Proxy) starts cleanly on 8080 from main ---
    task3 = asyncio.create_task(start_background_tcp_proxy())
    background_worker_tasks.extend([task1, task2, task3])

    yield

    logging.info("NanoStream Shutdown initiated. Cleaning worker tasks and Redis pools...")
    for task in background_worker_tasks:
        task.cancel()
    await asyncio.gather(*background_worker_tasks, return_exceptions=True)
    
    if hasattr(hunter, 'close'):
        await hunter.close()
    if hasattr(inspector, 'close'):
        await inspector.close()
    if hasattr(doctor, 'close'):
        await doctor.close()
        
    await redis_vault_proxies.aclose()
    await redis_pool_proxies.disconnect()
    await redis_vault_keys.aclose()
    await redis_pool_keys.disconnect()
    await close_gateway_resources()
    logging.info("Cleanup complete. Shutdown successful.")

app = FastAPI(title="NanoStream-Proxy Control Room", version="21.0.0", lifespan=app_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/telemetry")
async def websocket_telemetry_primary(websocket: WebSocket):
    await handle_websocket_subscription(websocket)

@app.websocket("/ws")
async def websocket_telemetry_alias(websocket: WebSocket):
    await handle_websocket_subscription(websocket)

def format_bytes_to_human(byte_count: int) -> str:
    if not byte_count or byte_count <= 0:
        return "0.0 MB"
    mb = byte_count / (1024 * 1024)
    if mb < 1024:
        return f"{mb:.2f} MB"
    gb = mb / 1024
    if gb < 1024:
        return f"{gb:.2f} GB"
    tb = gb / 1024
    return f"{tb:.2f} TB"

async def auto_prune_expired_slots():
    for reg_name in ["enterprise_b2b_registry", "standard_keys_registry"]:
        keys = list(await redis_vault_keys.smembers(reg_name))
        if not keys:
            continue
        pipe = redis_vault_keys.pipeline()
        for k in keys:
            pipe.exists(f"api_key:{k}")
        exists_results = await pipe.execute()
        
        dead_keys = [k for k, ex in zip(keys, exists_results) if not ex]
        if dead_keys:
            del_pipe = redis_vault_keys.pipeline()
            for dk in dead_keys:
                del_pipe.srem(reg_name, dk)
                del_pipe.srem("active_keys_registry", dk)
                del_pipe.delete(
                    f"api_key_ip:{dk}", f"api_key_rps:{dk}", f"api_key_tier:{dk}", 
                    f"api_key_country:{dk}", f"api_key_purpose:{dk}", f"api_key_slot:{dk}",
                    f"request_count:{dk}", f"data_usage_bytes:{dk}"
                )
                LOCAL_KEY_CACHE.pop(dk, None)
            await del_pipe.execute()

async def allocate_next_available_slot(tier: str) -> int:
    registry_name = "enterprise_b2b_registry" if tier == "enterprise" else "standard_keys_registry"
    max_slots = await get_max_enterprise_slots() if tier == "enterprise" else await get_max_standard_slots()
    
    existing_keys = await redis_vault_keys.smembers(registry_name)
    used_slots = set()
    
    if existing_keys:
        pipe = redis_vault_keys.pipeline()
        for k in existing_keys:
            pipe.get(f"api_key_slot:{k}")
        results = await pipe.execute()
        for s in results:
            if s and str(s).isdigit():
                used_slots.add(int(s))
                
    for candidate in range(1, max_slots + 1):
        if candidate not in used_slots:
            return candidate
            
    return 0

class CreateKeyRequest(BaseModel):
    client_name: str
    tier: Optional[str] = "enterprise"
    purpose: Optional[str] = "General Media / Proxy Usage"
    expiry_seconds: Optional[int] = None
    custom_api_key: Optional[str] = None
    bind_ip: Optional[str] = None
    country: Optional[str] = "🌐 Global / Unspecified"
    allocated_rps: Optional[int] = 10000

class KeyRevokeRequest(BaseModel):
    client_name: Optional[str] = None
    target_key: Optional[str] = None

class AdjustExpiryRequest(BaseModel):
    target_key: str
    action: str
    seconds: Optional[int] = 0
    target_datetime: Optional[str] = None

class ResetIpRequest(BaseModel):
    target_key: str

class UnbanRequest(BaseModel):
    target_key_or_ip: str

class SystemCapacityConfigRequest(BaseModel):
    enterprise_max_slots: Optional[int] = None
    standard_max_slots: Optional[int] = None

SAFE_KEY_PATTERN = re.compile(r'^[A-Za-z0-9_\-\.\(\)]+$')

@app.post("/admin/system/config", dependencies=[Depends(verify_local_admin_shield)])
async def update_system_capacity(request: SystemCapacityConfigRequest):
    updates = {}
    if request.enterprise_max_slots and request.enterprise_max_slots > 0:
        await redis_vault_keys.set("sys:config:ent_max_slots", request.enterprise_max_slots)
        updates["enterprise_max_slots"] = request.enterprise_max_slots

    if request.standard_max_slots and request.standard_max_slots > 0:
        await redis_vault_keys.set("sys:config:std_max_slots", request.standard_max_slots)
        updates["standard_max_slots"] = request.standard_max_slots

    logging.info(f"SYSTEM FLEET SCALED -> {updates}")
    return {"status": "success", "message": "System capacity scaled successfully.", "new_config": updates}

@app.post("/admin/security/unban", dependencies=[Depends(verify_local_admin_shield)])
async def unban_quarantined_target(request: UnbanRequest):
    target = request.target_key_or_ip.strip()
    raw_token = target.replace("api_key:", "")

    pipe = redis_vault_keys.pipeline()
    pipe.delete(f"auto_blocked_ip:{raw_token}")
    pipe.delete(f"auto_blocked_key:{raw_token}")
    pipe.delete(f"auto_blocked:{raw_token}")
    await pipe.execute()

    LOCAL_KEY_CACHE.pop(raw_token, None)
    logging.info(f"ADMIN ACTION -> Released '{raw_token}' from quarantine.")
    return {"status": "success", "message": f"Target '{raw_token}' has been unblocked."}

@app.post("/admin/keys/generate", dependencies=[Depends(verify_local_admin_shield)])
async def generate_api_key(request: CreateKeyRequest):
    clean_client_name = request.client_name.strip()
    if not clean_client_name:
        raise HTTPException(status_code=400, detail="Name cannot be empty.")

    clean_tier = "enterprise" if request.tier == "enterprise" else "standard"
    clean_country = request.country.strip() if request.country else "🌐 Global / Unspecified"
    clean_purpose = request.purpose.strip() if request.purpose else "General Media / Proxy Usage"

    clean_custom_key = request.custom_api_key.strip() if request.custom_api_key else None
    if clean_custom_key:
        if not SAFE_KEY_PATTERN.match(clean_custom_key):
            raise HTTPException(status_code=400, detail="Bad Request: Custom API key contains invalid characters.")

    prefix = "ent_" if clean_tier == "enterprise" else "std_"
    new_key = clean_custom_key if clean_custom_key else f"{prefix}{secrets.token_hex(16)}"
    redis_key_name = f"api_key:{new_key}"

    async with slot_allocation_lock:
        await auto_prune_expired_slots()

        slot_num = await allocate_next_available_slot(clean_tier)
        if slot_num == 0:
            max_ent = await get_max_enterprise_slots()
            max_std = await get_max_standard_slots()
            if clean_tier == "enterprise":
                raise HTTPException(status_code=400, detail=f"Enterprise Slots Full: All {max_ent} Company slots are occupied.")
            else:
                raise HTTPException(status_code=400, detail=f"Standard Slots Full: All {max_std} Retail user slots are occupied.")
        
        if await redis_vault_keys.exists(redis_key_name):
            raise HTTPException(status_code=409, detail=f"Conflict: API Key '{new_key}' already exists in vault.")

        if request.expiry_seconds and request.expiry_seconds > 0:
            await redis_vault_keys.setex(redis_key_name, request.expiry_seconds, clean_client_name)
            key_type = "subscription_timed"
        else:
            await redis_vault_keys.set(redis_key_name, clean_client_name)
            key_type = "permanent_unlimited"
            
        await redis_vault_keys.sadd("active_keys_registry", new_key)
        await redis_vault_keys.set(f"api_key_tier:{new_key}", clean_tier)
        await redis_vault_keys.set(f"api_key_country:{new_key}", clean_country)
        await redis_vault_keys.set(f"api_key_purpose:{new_key}", clean_purpose)
        await redis_vault_keys.set(f"api_key_slot:{new_key}", slot_num)

        if clean_tier == "enterprise":
            await redis_vault_keys.sadd("enterprise_b2b_registry", new_key)
            allocated_rps = request.allocated_rps if request.allocated_rps is not None else 10000
        else:
            await redis_vault_keys.sadd("standard_keys_registry", new_key)
            allocated_rps = 25

        await redis_vault_keys.set(f"api_key_rps:{new_key}", allocated_rps)

        if request.bind_ip and request.bind_ip.strip():
            await redis_vault_keys.set(f"api_key_ip:{new_key}", request.bind_ip.strip())
            if request.expiry_seconds and request.expiry_seconds > 0:
                await redis_vault_keys.expire(f"api_key_ip:{new_key}", request.expiry_seconds)
        else:
            await redis_vault_keys.set(f"api_key_ip:{new_key}", "unbound")

        await redis_vault_keys.set(f"data_usage_bytes:{new_key}", 0)
        await redis_vault_keys.set(f"request_count:{new_key}", 0)

    LOCAL_KEY_CACHE.pop(new_key, None)
    logging.info(f"KEY GENERATED -> Tier: {clean_tier.upper()} | Slot #{slot_num} | Name: {clean_client_name}")

    proxy_endpoint = f"http://gk:{new_key}@{PROXY_DOMAIN}:{PROXY_PORT}"
    ytdlp_command = f'yt-dlp --proxy "http://gk:{new_key}@{PROXY_DOMAIN}:{PROXY_PORT}" "TARGET_VIDEO_URL"'
    curl_command = f'curl -x "http://gk:{new_key}@{PROXY_DOMAIN}:{PROXY_PORT}" "https://httpbin.org/ip"'

    return {
        "message": "Universal Access Passport Activated",
        "api_key": new_key,
        "key_id": new_key,
        "proxy_endpoint": proxy_endpoint,
        "proxy_host": PROXY_DOMAIN,
        "proxy_port": PROXY_PORT,
        "proxy_username": "gk",
        "proxy_password": new_key,
        "slot_number": slot_num,
        "client_name": clean_client_name,
        "tier": clean_tier,
        "country": clean_country,
        "purpose": clean_purpose,
        "type": key_type,
        "allocated_rps": "Unlimited (Tier 0)" if allocated_rps == 0 else f"{allocated_rps:,} req/sec",
        "bound_ip": request.bind_ip.strip() if request.bind_ip else "Unbound (Multi-Server / Cluster Ready)",
        "ytdlp_cmd": ytdlp_command,
        "curl_cmd": curl_command
    }

@app.post("/admin/keys/adjust_expiry", dependencies=[Depends(verify_local_admin_shield)])
async def adjust_key_expiry(request: AdjustExpiryRequest):
    clean_target = request.target_key.strip()
    raw_token = clean_target.replace("api_key:", "")

    if raw_token in ["gk(GK)321", "GK_Master_Client"]:
        raise HTTPException(status_code=403, detail="Forbidden: Master Client Passport is permanently immortal.")

    redis_key = f"api_key:{raw_token}"
    if not await redis_vault_keys.exists(redis_key):
        raise HTTPException(status_code=404, detail="Target API Key not found in vault.")

    current_ttl = await redis_vault_keys.ttl(redis_key)

    if request.action == "set_lifetime":
        await redis_vault_keys.persist(redis_key)
        await redis_vault_keys.persist(f"api_key_ip:{raw_token}")
        LOCAL_KEY_CACHE.pop(raw_token, None)
        return {"status": "success", "message": f"Key {raw_token} converted to Lifetime Permanent.", "new_type": "permanent"}

    elif request.action == "set_datetime":
        delta_seconds = request.seconds if (request.seconds and request.seconds > 0) else None
        
        if not delta_seconds and request.target_datetime:
            clean_dt_str = request.target_datetime.replace(" ", "T")
            if len(clean_dt_str) == 16:
                clean_dt_str += ":00"
            dt_obj = datetime.fromisoformat(clean_dt_str)
            delta_seconds = int(dt_obj.timestamp() - time.time())
            
        if not delta_seconds or delta_seconds <= 0:
            raise HTTPException(status_code=400, detail="Selected Calendar Date and Time must be in the future.")

        await redis_vault_keys.expire(redis_key, delta_seconds)
        await redis_vault_keys.expire(f"api_key_ip:{raw_token}", delta_seconds)
        LOCAL_KEY_CACHE.pop(raw_token, None)
        logging.info(f"CALENDAR ADJUSTMENT -> Key {raw_token} expiry set ({delta_seconds}s).")
        return {"status": "success", "message": f"Expiry updated successfully ({delta_seconds}s).", "new_ttl": delta_seconds}

    elif request.action == "extend":
        add_sec = request.seconds if (request.seconds and request.seconds > 0) else 86400
        if current_ttl == -1:
            return {"status": "success", "message": "Key is already Lifetime Permanent.", "new_type": "permanent"}
        
        new_ttl = (current_ttl if current_ttl > 0 else 0) + add_sec
        await redis_vault_keys.expire(redis_key, new_ttl)
        await redis_vault_keys.expire(f"api_key_ip:{raw_token}", new_ttl)
        LOCAL_KEY_CACHE.pop(raw_token, None)
        return {"status": "success", "message": f"Key extended by {add_sec}s.", "new_ttl": new_ttl}

    elif request.action == "reduce":
        sub_sec = request.seconds if (request.seconds and request.seconds > 0) else 86400
        if current_ttl == -1:
            raise HTTPException(status_code=400, detail="Key is Lifetime Permanent. Use Calendar Picker.")
        
        new_ttl = max(60, current_ttl - sub_sec)
        await redis_vault_keys.expire(redis_key, new_ttl)
        await redis_vault_keys.expire(f"api_key_ip:{raw_token}", new_ttl)
        LOCAL_KEY_CACHE.pop(raw_token, None)
        return {"status": "success", "message": f"Key reduced. New TTL: {new_ttl}s.", "new_ttl": new_ttl}

    elif request.action == "set_seconds":
        if not request.seconds or request.seconds <= 0:
            raise HTTPException(status_code=400, detail="Must provide positive seconds.")
        await redis_vault_keys.expire(redis_key, request.seconds)
        await redis_vault_keys.expire(f"api_key_ip:{raw_token}", request.seconds)
        LOCAL_KEY_CACHE.pop(raw_token, None)
        return {"status": "success", "message": f"Key expiry set to {request.seconds}s.", "new_ttl": request.seconds}

    raise HTTPException(status_code=400, detail="Invalid action. Choose: set_datetime, extend, reduce, set_lifetime, set_seconds.")

@app.post("/admin/keys/reset_ip", dependencies=[Depends(verify_local_admin_shield)])
async def reset_key_ip_lock(request: ResetIpRequest):
    clean_target = request.target_key.strip()
    raw_token = clean_target.replace("api_key:", "")

    ip_key = f"api_key_ip:{raw_token}"
    await redis_vault_keys.set(ip_key, "unbound")
    LOCAL_KEY_CACHE.pop(raw_token, None)
    logging.info(f"ADMIN ACTION -> Reset IP lock for key: {raw_token} (Set to Unbound)")
    return {"status": "success", "message": f"IP lock cleared for {raw_token}. It is now unrestricted and cluster-ready."}

@app.post("/admin/keys/revoke", dependencies=[Depends(verify_local_admin_shield)])
async def revoke_api_key_by_name(request: KeyRevokeRequest):
    if request.target_key:
        clean_target = request.target_key.strip()
        raw_token = clean_target.replace("api_key:", "")
        if raw_token in ["gk(GK)321", "GK_Master_Client"]:
            raise HTTPException(status_code=403, detail="Forbidden: Cannot revoke Master Client Passport.")

        full_redis_key = f"api_key:{raw_token}"
        deleted = await redis_vault_keys.delete(full_redis_key)
        await redis_vault_keys.delete(
            f"api_key_ip:{raw_token}", f"api_key_rps:{raw_token}", f"api_key_tier:{raw_token}",
            f"api_key_country:{raw_token}", f"api_key_purpose:{raw_token}", f"api_key_slot:{raw_token}",
            f"request_count:{raw_token}", f"data_usage_bytes:{raw_token}"
        )
        await redis_vault_keys.srem("active_keys_registry", raw_token)
        await redis_vault_keys.srem("enterprise_b2b_registry", raw_token)
        await redis_vault_keys.srem("standard_keys_registry", raw_token)
        LOCAL_KEY_CACHE.pop(raw_token, None)
        
        if deleted:
            logging.info(f"ADMIN ACTION -> Revoked key: {raw_token}")
            return {"status": "success", "message": f"Revoked key: {raw_token}"}
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
                await redis_vault_keys.delete(
                    f"api_key_ip:{k}", f"api_key_rps:{k}", f"api_key_tier:{k}",
                    f"api_key_country:{k}", f"api_key_purpose:{k}", f"api_key_slot:{k}",
                    f"request_count:{k}", f"data_usage_bytes:{k}"
                )
                await redis_vault_keys.srem("active_keys_registry", k)
                await redis_vault_keys.srem("enterprise_b2b_registry", k)
                await redis_vault_keys.srem("standard_keys_registry", k)
                LOCAL_KEY_CACHE.pop(k, None)
                revoked_count += 1
                
        if revoked_count > 0:
            logging.info(f"ADMIN ACTION -> Revoked {revoked_count} keys for: {clean_name}")
            return {"status": "success", "message": f"Revoked {revoked_count} keys for: {clean_name}"}
        else:
            raise HTTPException(status_code=404, detail=f"No active keys found for: {clean_name}")

    raise HTTPException(status_code=400, detail="Must provide either target_key or client_name to revoke.")

@app.get("/admin/keys/list", dependencies=[Depends(verify_local_admin_shield)])
async def list_api_keys():
    await auto_prune_expired_slots()

    all_keys = list(await redis_vault_keys.smembers("active_keys_registry"))
    ent_max = await get_max_enterprise_slots()
    std_max = await get_max_standard_slots()

    if not all_keys:
        return {
            "master_client": None,
            "enterprise_clients": [], 
            "standard_clients": [], 
            "enterprise_slots_used": 0, 
            "enterprise_slots_total": ent_max,
            "standard_slots_used": 0,
            "standard_slots_total": std_max,
            "total_active": 0
        }

    pipe = redis_vault_keys.pipeline()
    for raw_key in all_keys:
        k = f"api_key:{raw_key}"
        pipe.ttl(k)
        pipe.get(k)
        pipe.get(f"api_key_ip:{raw_key}")
        pipe.get(f"api_key_rps:{raw_key}")
        pipe.get(f"api_key_tier:{raw_key}")
        pipe.get(f"data_usage_bytes:{raw_key}")
        pipe.get(f"request_count:{raw_key}")
        pipe.get(f"api_key_country:{raw_key}")
        pipe.get(f"api_key_purpose:{raw_key}")
        pipe.get(f"api_key_slot:{raw_key}")
    results = await pipe.execute()

    master_client = None
    enterprise_clients = []
    standard_clients = []
    dead_keys = []

    for idx, raw_key in enumerate(all_keys):
        base_idx = idx * 10
        ttl = results[base_idx]
        client_name = results[base_idx + 1]
        bound_ip = results[base_idx + 2]
        allocated_rps = results[base_idx + 3]
        tier = results[base_idx + 4] or "standard"
        raw_bytes = results[base_idx + 5]
        raw_reqs = results[base_idx + 6]
        country = results[base_idx + 7] or "🌐 Global / Unspecified"
        purpose = results[base_idx + 8] or ("Enterprise Media / Scraper Core" if tier == "enterprise" else "General Media / API Client")
        raw_slot = results[base_idx + 9]

        if ttl == -2 or not client_name:
            dead_keys.append(raw_key)
            continue

        try:
            byte_count = int(raw_bytes) if raw_bytes else 0
        except ValueError:
            byte_count = 0

        try:
            req_count = int(raw_reqs) if raw_reqs else 0
        except ValueError:
            req_count = 0

        slot_number = int(raw_slot) if (raw_slot and str(raw_slot).isdigit()) else 1

        human_data = format_bytes_to_human(byte_count)
        rps_int = int(allocated_rps) if allocated_rps else (10000 if tier == "enterprise" else 25)

        target_timestamp = (int(time.time()) + ttl) if ttl > 0 else None
        is_active = (ttl != -2 and bool(client_name))

        display_ip = bound_ip if bound_ip and bound_ip.lower() not in ["unbound", "none", "any", "all", "dynamic"] else "Unbound (Cluster Ready)"

        proxy_str = f"http://gk:{raw_key}@{PROXY_DOMAIN}:{PROXY_PORT}"
        ytdlp_cmd = f'yt-dlp --proxy "{proxy_str}" "VIDEO_URL"'
        curl_cmd = f'curl -x "{proxy_str}" "https://httpbin.org/ip"'

        item = {
            "key_id": raw_key,
            "full_key": raw_key,
            "slot_number": slot_number,
            "client_name": client_name,
            "tier": tier,
            "country": country,
            "purpose": purpose,
            "is_active": is_active,
            "status_text": "Active" if is_active else "Deactivated / Expired",
            "type": "permanent" if ttl == -1 else f"expires_in_{ttl}_secs",
            "ttl_seconds": ttl,
            "target_timestamp": target_timestamp,
            "total_requests": req_count,
            "total_requests_display": f"{req_count:,}",
            "allocated_rps": f"{rps_int:,} req/sec" if rps_int > 0 else "Unlimited",
            "data_usage": human_data,
            "bound_ip": display_ip,
            "proxy_string": proxy_str,
            "proxy_host": PROXY_DOMAIN,
            "proxy_port": PROXY_PORT,
            "proxy_username": "gk",
            "proxy_password": raw_key,
            "ytdlp_cmd": ytdlp_cmd,
            "curl_cmd": curl_cmd
        }

        if raw_key == "gk(GK)321":
            master_client = item
        elif tier == "enterprise":
            enterprise_clients.append(item)
        else:
            standard_clients.append(item)

    if dead_keys:
        await redis_vault_keys.srem("active_keys_registry", *dead_keys)
        await redis_vault_keys.srem("enterprise_b2b_registry", *dead_keys)
        await redis_vault_keys.srem("standard_keys_registry", *dead_keys)

    enterprise_clients.sort(key=lambda x: x["slot_number"])
    standard_clients.sort(key=lambda x: x["slot_number"])

    return {
        "master_client": master_client,
        "enterprise_clients": enterprise_clients,
        "standard_clients": standard_clients,
        "enterprise_slots_used": len(enterprise_clients),
        "enterprise_slots_total": ent_max,
        "standard_slots_used": len(standard_clients),
        "standard_slots_total": std_max,
        "total_active": (1 if master_client else 0) + len(enterprise_clients) + len(standard_clients)
    }

@app.get("/health")
async def root_health_check():
    try:
        vault_count = await redis_vault_proxies.scard("vip_proxy_pool")
        enterprise_count = await redis_vault_keys.scard("enterprise_b2b_registry") or 0
        standard_count = await redis_vault_keys.scard("standard_keys_registry") or 0
        
        ent_max = await get_max_enterprise_slots()
        std_max = await get_max_standard_slots()

        return {
            "status": "system_healthy",
            "shield": "active",
            "vip_proxy_ips": vault_count,
            "enterprise_fleet_slots": f"{enterprise_count}/{ent_max}",
            "standard_retail_slots": f"{standard_count}/{std_max}",
            "max_socket_capacity": MAX_SOCKET_CONNECTIONS,
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
                    <h1 style="color: #38bdf8;">NanoStream 4X Multi-Fleet Core Online</h1>
                    <p style="color: #cbd5e1;">Zero-Hardcoding Dynamic Architecture active, but index.html is missing.</p>
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
app.include_router(gateway_app.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=WEB_PORT, reload=False)
