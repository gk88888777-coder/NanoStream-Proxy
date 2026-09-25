import asyncio
import httpx
import logging
import time
import json
import re
import ssl
import socket
import ipaddress
from cryptography.fernet import Fernet
import redis.asyncio as redis
from typing import List, Optional, Callable, Dict, Any, Set
import os
import random
import warnings

warnings.filterwarnings('ignore')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [ENGINE 2: INSPECTOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

SHARED_SSL_CONTEXT = ssl.create_default_context()
SHARED_SSL_CONTEXT.check_hostname = False
SHARED_SSL_CONTEXT.verify_mode = ssl.CERT_NONE

class InspectorConfig:
    MAX_CONCURRENT_WORKERS = int(os.environ.get("INSPECTOR_CONCURRENCY", 200))
    INSPECTION_TIMEOUT = 4.5
    CONNECT_TIMEOUT = 2.5
    REDIS_PIPELINE_CHUNK = 250
    
    CGNAT_NETWORK = ipaddress.IPv4Network('100.64.0.0/10')
    DANGEROUS_PORTS = {21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 445, 
                       1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 
                       6379, 8001, 8008, 9200, 11211, 27017, 28017}

    STANDARD_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Connection": "close"
    }

    TEST_ENDPOINTS = [
        {"url": "http://checkip.amazonaws.com", "type": "plain"},
        {"url": "http://api.ipify.org?format=json", "type": "ipify"},
        {"url": "http://icanhazip.com", "type": "plain"},
        {"url": "http://httpbin.org/ip", "type": "httpbin"}
    ]

class ProxyValidator:
    def __init__(self):
        self.origin_ips: Set[str] = set()
        self._origin_last_checked = 0.0

    @staticmethod
    def sanitize_proxy_address(raw_str: str) -> Optional[str]:
        cleaned = raw_str.strip().lower()
        if cleaned.startswith("http://"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("https://"):
            cleaned = cleaned[8:]
        cleaned = cleaned.split("/")[0].strip()
        
        parts = cleaned.split(":")
        if len(parts) != 2:
            return None
        ip_str, port_str = parts[0], parts[1]
        
        try:
            port = int(port_str)
            if port in InspectorConfig.DANGEROUS_PORTS or port <= 0 or port > 65535:
                return None
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_global or ip_obj.is_private or ip_obj.is_loopback:
                return None
            if ip_obj.version == 4 and ip_obj in InspectorConfig.CGNAT_NETWORK:
                return None
            return f"{ip_str}:{port}"
        except Exception:
            return None

    async def fetch_host_origin_ips(self) -> bool:
        now = time.time()
        if self.origin_ips and (now - self._origin_last_checked < 3600.0):
            return True

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("1.1.1.1", 80))
                local_ip = s.getsockname()[0]
                if local_ip:
                    self.origin_ips.add(local_ip)
        except Exception:
            pass

        for target in InspectorConfig.TEST_ENDPOINTS:
            try:
                async with httpx.AsyncClient(timeout=3.0, verify=SHARED_SSL_CONTEXT) as client:
                    res = await client.get(target["url"], headers=InspectorConfig.STANDARD_HEADERS)
                    if res.status_code == 200:
                        m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', res.text)
                        if m:
                            self.origin_ips.add(m.group(0))
                            self._origin_last_checked = now
                            break
            except Exception:
                continue

        logging.info(f"[ENGINE 2] Host origin shield active. Guarded IPs: {self.origin_ips}")
        return len(self.origin_ips) > 0

    def _verify_anonymity_strict(self, content: str, target_type: str) -> bool:
        try:
            detected_ip = None
            if target_type == "plain":
                m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
                if m:
                    detected_ip = m.group(0)
            elif target_type == "ipify":
                data = json.loads(content)
                detected_ip = data.get("ip", "").strip()
            elif target_type == "httpbin":
                data = json.loads(content)
                origin = data.get("origin", "")
                if "," in origin:
                    return False
                detected_ip = origin.strip()

            if not detected_ip:
                return False

            for origin in self.origin_ips:
                if origin in detected_ip or detected_ip == origin:
                    return False

            ip_obj = ipaddress.ip_address(detected_ip)
            if not ip_obj.is_global or ip_obj.is_private or ip_obj.is_loopback:
                return False

            return True
        except Exception:
            return False

    async def test_proxy(self, clean_ip_port: str) -> Optional[str]:
        target = random.choice(InspectorConfig.TEST_ENDPOINTS)
        proxy_url = f"http://{clean_ip_port}"
        
        try:
            timeout = httpx.Timeout(InspectorConfig.INSPECTION_TIMEOUT, connect=InspectorConfig.CONNECT_TIMEOUT)
            limits = httpx.Limits(max_keepalive_connections=0, max_connections=1)
            
            async with httpx.AsyncClient(
                proxy=proxy_url, 
                timeout=timeout, 
                verify=SHARED_SSL_CONTEXT, 
                limits=limits
            ) as client:
                response = await client.get(target["url"], headers=InspectorConfig.STANDARD_HEADERS)
                if response.status_code == 200:
                    if self._verify_anonymity_strict(response.text, target["type"]):
                        return clean_ip_port
        except Exception:
            pass
        return None

class VaultStorageManager:
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    async def store_elite_proxies(self, elite_ips: List[str]) -> int:
        if not elite_ips:
            return 0

        stored_count = 0
        chunk_size = InspectorConfig.REDIS_PIPELINE_CHUNK

        for i in range(0, len(elite_ips), chunk_size):
            chunk = elite_ips[i:i + chunk_size]
            
            async with self.redis.pipeline(transaction=False) as check_pipe:
                for ip in chunk:
                    check_pipe.sismember("vip_proxy_ips", ip.encode('utf-8'))
                exists_results = await check_pipe.execute()

            new_ips = [chunk[idx] for idx, exists in enumerate(exists_results) if not exists]
            if not new_ips:
                continue

            async with self.redis.pipeline(transaction=False) as store_pipe:
                for ip in new_ips:
                    try:
                        encrypted = cipher_suite.encrypt(ip.encode('utf-8'))
                        store_pipe.sadd("vip_proxy_ips", ip.encode('utf-8'))
                        store_pipe.sadd("vip_proxy_pool", encrypted)
                        stored_count += 1
                    except Exception:
                        continue
                await store_pipe.execute()

        return stored_count

class InspectorTelemetry:
    def __init__(self, ui_callback: Optional[Callable]):
        self.ui_callback = ui_callback

    async def emit(self, status: str, tested: int, passed: int):
        if not self.ui_callback:
            return

        ui_status = "Active" if status in ("running", "completed") else "Error"
        payload = {
            "engine": "master_2_inspector",
            "inspector_status": ui_status,
            "tested_count": tested,
            "elite_passed": passed,
            "vault_status": "Optimized"
        }
        try:
            if asyncio.iscoroutinefunction(self.ui_callback):
                await asyncio.wait_for(self.ui_callback(payload), timeout=1.5)
            else:
                self.ui_callback(payload)
        except Exception as e:
            logging.debug(f"Telemetry non-critical bypass: {e}")

class ProxyInspector:
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
            max_connections=50,
            socket_timeout=5.0,
            socket_connect_timeout=3.0,
            retry_on_timeout=True
        )
        self.redis_vault = redis.Redis(connection_pool=self.pool)
        self.lock = asyncio.Lock()
        
        self.validator = ProxyValidator()
        self.vault_manager = VaultStorageManager(self.redis_vault)
        self.telemetry = InspectorTelemetry(ui_broadcast_callback)
        self._is_closed = False

    async def execute_inspection(self, raw_ips_list: List[str]) -> List[str]:
        async with self.lock:
            sanitized_candidates = set()
            for raw in raw_ips_list:
                cleaned = self.validator.sanitize_proxy_address(raw)
                if cleaned:
                    sanitized_candidates.add(cleaned)
                    
            unique_raw_list = list(sanitized_candidates)
            total_raw = len(unique_raw_list)
            
            if total_raw == 0:
                logging.warning("No valid public IPs provided for inspection. Cycle skipped.")
                return []

            logging.info(f"Initiating continuous queue inspection of {total_raw:,} unique IPs ({InspectorConfig.MAX_CONCURRENT_WORKERS} workers)...")
            start_time = time.time()
            
            await self.validator.fetch_host_origin_ips()
            await self.telemetry.emit(status="running", tested=0, passed=0)

            work_queue: asyncio.Queue = asyncio.Queue()
            for ip in unique_raw_list:
                work_queue.put_nowait(ip)

            all_elite_survivors: List[str] = []
            tested_counter = 0
            last_telemetry_time = time.time()

            async def _worker():
                nonlocal tested_counter, last_telemetry_time
                while True:
                    try:
                        ip = work_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    
                    try:
                        res = await self.validator.test_proxy(ip)
                        tested_counter += 1
                        if res:
                            all_elite_survivors.append(res)
                    finally:
                        work_queue.task_done()

                    now = time.time()
                    if now - last_telemetry_time > 1.5:
                        last_telemetry_time = now
                        await self.telemetry.emit(status="running", tested=tested_counter, passed=len(all_elite_survivors))

            worker_count = min(InspectorConfig.MAX_CONCURRENT_WORKERS, total_raw)
            workers = [asyncio.create_task(_worker()) for _ in range(worker_count)]
            await asyncio.gather(*workers)

            total_elite = len(all_elite_survivors)
            logging.info(f"Continuous inspection complete. {total_elite:,} 100% Elite VIP proxies verified.")

            if total_elite > 0:
                new_stored = await self.vault_manager.store_elite_proxies(all_elite_survivors)
                logging.info(f"Vault synchronized: {new_stored} fresh unique proxies added.")

            execution_time = time.time() - start_time
            logging.info(f"Cycle completed in {round(execution_time, 2)}s.")
            
            await self.telemetry.emit(
                status="completed", 
                tested=total_raw, 
                passed=total_elite
            )
            return all_elite_survivors

    async def inspect_proxies(self, raw_ips_list: List[str]) -> List[str]:
        return await self.execute_inspection(raw_ips_list)

    async def close(self):
        if not self._is_closed:
            self._is_closed = True
            await self.redis_vault.aclose()
            await self.pool.disconnect()

if __name__ == "__main__":
    async def dummy_ui_receiver(data):
        print(f"\n[LIVE UI TELEMETRY] {data}\n")

    inspector = ProxyInspector(ui_broadcast_callback=dummy_ui_receiver)
    sample_ips = ["185.199.108.153:80", "1.1.1.1:8080", "127.0.0.1:9050"]
    results = asyncio.run(inspector.execute_inspection(sample_ips))
    asyncio.run(inspector.close())
    print(f"Elite Proxies Passed: {len(results)}")
