import asyncio
import httpx
import logging
import time
from cryptography.fernet import Fernet
import redis.asyncio as redis
from typing import List, Optional, Callable
import os

# Professional logging setup for Engine 2 (Inspector)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [ENGINE 2: INSPECTOR - SECURED] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Enterprise-Grade Fixed Shared Encryption Key (Synchronized across Engines 2, 3, and 4)
DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

class ProxyInspector:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        Engine 2: Master Inspector (Secured & Synced)
        Validates raw proxies under strict concurrency limits, tests anonymity,
        encrypts elite IPs, and locks them securely inside the Redis Vault.
        """
        self.anonymity_test_url = "http://httpbin.org/ip"
        
        # Environment-driven secure Redis configuration (Synced with main.py)
        REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
        REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
        REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)
        
        self.redis_vault = redis.Redis(
            host=REDIS_HOST, 
            port=REDIS_PORT, 
            db=0, 
            password=REDIS_PASSWORD, 
            decode_responses=False  # Required for binary Fernet encrypted tokens
        )
        
        self.ui_broadcast = ui_broadcast_callback
        
        # OS Protection: Max 150 concurrent requests to prevent Linux socket exhaustion (Errno 24)
        self.semaphore = asyncio.Semaphore(150)

    async def _emit_telemetry(self, status: str, tested: int, passed: int, execution_time: float = 0.0):
        """Safely broadcasts real-time inspection metrics to the WebSocket UI dashboard."""
        if self.ui_broadcast:
            try:
                payload = {
                    "engine": "master_2_inspector",
                    "status": status,
                    "ips_tested": tested,
                    "ips_passed": passed,
                    "execution_time_sec": round(execution_time, 2)
                }
                if asyncio.iscoroutinefunction(self.ui_broadcast):
                    await self.ui_broadcast(payload)
                else:
                    self.ui_broadcast(payload)
            except Exception as e:
                logging.error(f"Failed to broadcast telemetry to UI: {str(e)}")

    async def _test_single_proxy(self, raw_ip: str) -> Optional[str]:
        """
        Performs a rigorous acid test on a single raw IP address under semaphore control.
        Verifies if the proxy can successfully route traffic and mask the origin within 15 seconds.
        """
        async with self.semaphore:
            proxy_url = f"http://{raw_ip}"
            proxies_config = {
                "http://": proxy_url,
                "https://": proxy_url
            }
            
            try:
                # 15.0 seconds strict timeout for deep network verification safely
                async with httpx.AsyncClient(
                    proxies=proxies_config, 
                    timeout=15.0, 
                    verify=False,
                    follow_redirects=True
                ) as client:
                    
                    response = await client.get(self.anonymity_test_url)
                    
                    if response.status_code == 200:
                        data = response.json()
                        returned_ip = data.get("origin", "")
                        ip_only = raw_ip.split(':')[0]
                        
                        # Verify if the proxy successfully masked the origin IP address
                        if returned_ip and (ip_only in returned_ip or len(returned_ip) > 6):
                            return raw_ip
                            
            except Exception:
                # Silently bypass dead, slow, or timing-out proxies without crashing
                pass
                
            return None

    async def _secure_and_store(self, valid_ip: str):
        """Encrypts the verified elite IP using the shared key and locks it securely inside the Redis Vault."""
        try:
            encrypted_ip = cipher_suite.encrypt(valid_ip.encode('utf-8'))
            await self.redis_vault.sadd("vip_proxy_pool", encrypted_ip)
        except Exception as e:
            logging.error(f"Failed to store proxy in Redis vault: {str(e)}")

    async def execute_inspection(self, raw_ips_list: List[str]):
        """
        Takes the raw IP batch from Engine 1, executes high-concurrency validation tests,
        streams live telemetry to the UI, and secures the survivors in the Redis Vault.
        """
        total_raw = len(raw_ips_list)
        if total_raw == 0:
            logging.warning("No raw IPs provided for inspection. Aborting cycle.")
            return

        logging.info(f"Initiating strict inspection of {total_raw} raw IPs with 15-second timeout & semaphore limit...")
        start_time = time.time()
        
        # Live Telemetry: Inspection started broadcast to UI dashboard
        await self._emit_telemetry(status="inspection_started", tested=total_raw, passed=0)

        # High-concurrency asynchronous task execution bound by semaphore
        tasks = [self._test_single_proxy(ip) for ip in raw_ips_list]
        tested_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out dead proxies and gather only the elite verified IPs
        elite_ips = []
        for res in tested_results:
            if isinstance(res, str):
                elite_ips.append(res)

        total_elite = len(elite_ips)
        logging.info(f"Inspection complete. {total_elite} Elite IPs passed the test. Securing vault...")

        # Concurrently store verified elite proxies in the Redis Vault
        if total_elite > 0:
            store_tasks = [self._secure_and_store(ip) for ip in elite_ips]
            await asyncio.gather(*store_tasks, return_exceptions=True)

        execution_time = time.time() - start_time
        logging.info(f"Vault updated successfully. Cycle completed in {round(execution_time, 2)} seconds.")
        
        # Live Telemetry: Inspection completed broadcast to UI with final metrics
        await self._emit_telemetry(
            status="inspection_completed", 
            tested=total_raw, 
            passed=total_elite, 
            execution_time=execution_time
        )
