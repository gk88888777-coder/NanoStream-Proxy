import asyncio
import httpx
import logging
import time
import ssl
from cryptography.fernet import Fernet
import redis.asyncio as redis
from typing import Optional, Callable, List, Tuple, Set
import os
import random
import warnings

warnings.filterwarnings('ignore')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [ENGINE 3: VAULT DOCTOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

SHARED_SSL_CONTEXT = ssl.create_default_context()
SHARED_SSL_CONTEXT.check_hostname = False
SHARED_SSL_CONTEXT.verify_mode = ssl.CERT_NONE

class DoctorConfig:
    HEALTH_TIMEOUT = 4.0
    CONNECT_TIMEOUT = 2.5
    CONCURRENT_WORKERS = int(os.environ.get("DOCTOR_CONCURRENCY", 120))
    REDIS_SCAN_COUNT = 150
    ANOMALY_FAILURE_THRESHOLD = 0.85
    
    STANDARD_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Connection": "close"
    }

    TARGET_ENDPOINTS = [
        "http://checkip.amazonaws.com",
        "http://api.ipify.org?format=json",
        "http://icanhazip.com",
        "http://httpbin.org/get"
    ]

class CanaryHealthProbe:
    @staticmethod
    async def is_internet_and_target_healthy() -> bool:
        success_count = 0
        for target in DoctorConfig.TARGET_ENDPOINTS:
            try:
                async with httpx.AsyncClient(timeout=3.0, verify=SHARED_SSL_CONTEXT) as client:
                    res = await client.get(target, headers=DoctorConfig.STANDARD_HEADERS)
                    if res.status_code == 200:
                        success_count += 1
            except Exception:
                continue
        return success_count > 0

    @staticmethod
    async def verify_proxy_vitality(raw_ip: str) -> bool:
        target_url = random.choice(DoctorConfig.TARGET_ENDPOINTS)
        proxy_url = f"http://{raw_ip}"
        
        try:
            timeout = httpx.Timeout(DoctorConfig.HEALTH_TIMEOUT, connect=DoctorConfig.CONNECT_TIMEOUT)
            limits = httpx.Limits(max_keepalive_connections=0, max_connections=1)
            
            async with httpx.AsyncClient(
                proxy=proxy_url, 
                timeout=timeout, 
                verify=SHARED_SSL_CONTEXT, 
                limits=limits
            ) as client:
                res = await client.get(target_url, headers=DoctorConfig.STANDARD_HEADERS)
                if res.status_code == 200:
                    return True
        except Exception:
            pass
        return False

class VaultJanitor:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def scan_and_deduplicate_vault(self) -> Tuple[List[Tuple[bytes, str]], List[Tuple[bytes, str]], int]:
        unique_valid_items: List[Tuple[bytes, str]] = []
        items_to_purge_immediately: List[Tuple[bytes, str]] = []
        seen_raw_ips: Set[str] = set()
        total_count = 0

        async for enc_token in self.redis.sscan_iter("vip_proxy_pool", count=DoctorConfig.REDIS_SCAN_COUNT):
            total_count += 1
            try:
                raw_ip = cipher_suite.decrypt(enc_token).decode('utf-8')
                
                if raw_ip in seen_raw_ips:
                    items_to_purge_immediately.append((enc_token, ""))
                else:
                    seen_raw_ips.add(raw_ip)
                    unique_valid_items.append((enc_token, raw_ip))
            except Exception:
                items_to_purge_immediately.append((enc_token, ""))

        if seen_raw_ips:
            async with self.redis.pipeline(transaction=False) as sync_pipe:
                for ip in seen_raw_ips:
                    sync_pipe.sadd("vip_proxy_ips", ip.encode('utf-8'))
                await sync_pipe.execute()

        ghost_ips: List[bytes] = []
        async for member_ip in self.redis.sscan_iter("vip_proxy_ips", count=DoctorConfig.REDIS_SCAN_COUNT):
            ip_str = member_ip.decode('utf-8', errors='ignore') if isinstance(member_ip, bytes) else str(member_ip)
            if ip_str not in seen_raw_ips:
                ghost_ips.append(member_ip)

        if ghost_ips:
            async with self.redis.pipeline(transaction=False) as ghost_pipe:
                for ghost in ghost_ips:
                    ghost_pipe.srem("vip_proxy_ips", ghost)
                await ghost_pipe.execute()
            logging.info(f"[ENGINE 3] Reconciled shadow index: Purged {len(ghost_ips)} orphaned ghost IPs.")

        return unique_valid_items, items_to_purge_immediately, total_count

    async def purge_items_atomic(self, items_to_remove: List[Tuple[bytes, str]]):
        if not items_to_remove:
            return
            
        chunk_size = 250
        for i in range(0, len(items_to_remove), chunk_size):
            chunk = items_to_remove[i:i + chunk_size]
            try:
                async with self.redis.pipeline(transaction=False) as pipe:
                    for enc_token, raw_ip in chunk:
                        pipe.srem("vip_proxy_pool", enc_token)
                        if raw_ip:
                            pipe.srem("vip_proxy_ips", raw_ip.encode('utf-8'))
                    await pipe.execute()
            except Exception as e:
                logging.error(f"[ENGINE 3] Pipeline removal error: {e}")

class DoctorTelemetry:
    def __init__(self, ui_callback: Optional[Callable]):
        self.ui_callback = ui_callback

    async def emit(self, status: str, total_checked: int, total_purged: int, healthy_count: int):
        if not self.ui_callback:
            return

        ui_status = "Active" if status in ("running", "completed") else "Error"
        health_score = int((healthy_count / total_checked) * 100) if total_checked > 0 else 0
        
        payload = {
            "engine": "master_3_vault_doctor",
            "maintenance_status": ui_status,
            "health_score": f"{health_score}%",
            "purged_count": total_purged,
            "stream_scan": "Active" if status != "completed" else "Idle"
        }
        try:
            if asyncio.iscoroutinefunction(self.ui_callback):
                await asyncio.wait_for(self.ui_callback(payload), timeout=1.5)
            else:
                self.ui_callback(payload)
        except Exception as e:
            logging.debug(f"Telemetry non-critical bypass: {e}")

class VaultDoctor:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None, **kwargs):
        REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
        REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
        REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)
        
        self.pool = redis.ConnectionPool(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=0,
            password=REDIS_PASSWORD,
            decode_responses=False,
            max_connections=30,
            socket_timeout=5.0,
            socket_connect_timeout=3.0,
            retry_on_timeout=True
        )
        self.redis_vault = redis.Redis(connection_pool=self.pool)
        self.surgery_lock = asyncio.Lock()
        self.minimum_healthy_ips = 50
        
        self.canary = CanaryHealthProbe()
        self.janitor = VaultJanitor(self.redis_vault)
        self.telemetry = DoctorTelemetry(ui_broadcast_callback)
        self._is_closed = False

    async def perform_vault_surgery(self):
        async with self.surgery_lock:
            logging.info("Initiating Continuous Queue Vault Maintenance Cycle...")
            start_time = time.time()
            
            if not await self.canary.is_internet_and_target_healthy():
                logging.error("[VAULT DOCTOR] Pre-flight canary failed: Internet unreachable. Surgery aborted to prevent false purge.")
                await self.telemetry.emit("error", 0, 0, 0)
                return

            try:
                valid_items, immediate_purges, total_vault_size = await self.janitor.scan_and_deduplicate_vault()
            except Exception as e:
                logging.error(f"[ENGINE 3] Redis scan failed: {e}")
                await self.telemetry.emit("error", 0, 0, 0)
                return

            dead_count = len(immediate_purges)
            if immediate_purges:
                await self.janitor.purge_items_atomic(immediate_purges)
                logging.info(f"Purged {dead_count} unreadable or duplicate cryptographic tokens.")

            if not valid_items:
                logging.warning("Vault is currently empty. Maintenance completed.")
                await self.telemetry.emit("completed", 0, dead_count, 0)
                return

            await self.telemetry.emit("running", total_vault_size, dead_count, len(valid_items))
            logging.info(f"Checking vitality of {len(valid_items):,} unique proxies using continuous queue...")

            work_queue: asyncio.Queue = asyncio.Queue()
            for item in valid_items:
                work_queue.put_nowait(item)

            dead_proxies_to_purge: List[Tuple[bytes, str]] = []

            async def _doctor_worker():
                while True:
                    try:
                        item = work_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    
                    enc_token, raw_ip = item
                    try:
                        is_alive = await self.canary.verify_proxy_vitality(raw_ip)
                        if not is_alive:
                            dead_proxies_to_purge.append(item)
                    finally:
                        work_queue.task_done()

            worker_count = min(DoctorConfig.CONCURRENT_WORKERS, len(valid_items))
            workers = [asyncio.create_task(_doctor_worker()) for _ in range(worker_count)]
            await asyncio.gather(*workers)

            failed_count = len(dead_proxies_to_purge)
            total_valid = len(valid_items)

            if failed_count > 0:
                is_total_wipeout = (failed_count == total_valid)
                is_rate_anomaly = (total_valid >= 5 and (failed_count / total_valid) >= DoctorConfig.ANOMALY_FAILURE_THRESHOLD)

                if is_total_wipeout or is_rate_anomaly:
                    host_is_online = await self.canary.is_internet_and_target_healthy()
                    if not host_is_online:
                        logging.error("[CIRCUIT BREAKER] Host internet blip detected during sweep. Purge blocked to protect vault!")
                        await self.telemetry.emit("error", total_vault_size, dead_count, total_valid)
                        return
                    else:
                        logging.warning(f"[CIRCUIT BREAKER] Host internet online. Proxies are genuinely dead ({failed_count}/{total_valid}). Proceeding with purge.")

            if dead_proxies_to_purge:
                await self.janitor.purge_items_atomic(dead_proxies_to_purge)
                dead_count += len(dead_proxies_to_purge)

            healthy_count = total_vault_size - dead_count
            duration = time.time() - start_time
            logging.info(f"Vault Maintenance Complete in {round(duration, 2)}s. Purged: {dead_count} | Healthy Remaining: {healthy_count}")
            
            await self.telemetry.emit(
                status="completed", 
                total_checked=total_vault_size, 
                total_purged=dead_count, 
                healthy_count=healthy_count
            )

    async def execute_maintenance_cycle(self):
        await self.perform_vault_surgery()

    async def close(self):
        if not self._is_closed:
            self._is_closed = True
            await self.redis_vault.aclose()
            await self.pool.disconnect()

if __name__ == "__main__":
    async def dummy_ui_receiver(data):
        print(f"\n[LIVE UI TELEMETRY] {data}\n")

    doctor = VaultDoctor(ui_broadcast_callback=dummy_ui_receiver)
    asyncio.run(doctor.perform_vault_surgery())
    asyncio.run(doctor.close())
