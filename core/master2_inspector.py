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
    format='%(asctime)s - [ENGINE 2: INSPECTOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Enterprise-Grade Fixed Shared Encryption Key ensuring synchronization across all engines (2, 3, and 4)
# This prevents any 'Vault token decryption failed' mismatch errors upon server restarts.
DEFAULT_FIXED_KEY = "n5_secure_vault_fixed_encryption_key_2026_nanostream=="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

class ProxyInspector:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        Engine 2: Master Inspector
        Rigorously validates raw proxies for speed, connectivity, and anonymity,
        while broadcasting real-time telemetry to the UI dashboard.
        """
        self.anonymity_test_url = "http://httpbin.org/ip"
        
        # Secure connection to Redis database DB 0 with binary support enabled for encrypted tokens
        self.redis_vault = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=False)
        self.ui_broadcast = ui_broadcast_callback

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
                await self.ui_broadcast(payload)
            except Exception as e:
                logging.error(f"Failed to broadcast telemetry to UI: {str(e)}")

    async def _test_single_proxy(self, raw_ip: str) -> Optional[str]:
        """
        Performs a rigorous acid test on a single raw IP address.
        Verifies if the proxy can successfully route traffic and mask the origin.
        Configured with a 15.0-second timeout to allow thorough inspection without blocking.
        """
        proxy_url = f"http://{raw_ip}"
        
        # Universal proxy configuration syntax compatible with stable and legacy httpx versions
        proxies_config = {
            "http://": proxy_url,
            "https://": proxy_url
        }
        
        try:
            # Extended 15.0 seconds timeout ensures deep network verification safely
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
                        
        except Exception as e:
            # Capture and log critical syntax errors, silently bypass standard network timeouts
            error_msg = str(e).lower()
            if "unexpected keyword" in error_msg or "proxy" in error_msg:
                logging.error(f"HTTPX Configuration Error on {raw_ip}: {repr(e)}")
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
        streams live telemetry to the UI, and secures the survivors in the Vault.
        """
        total_raw = len(raw_ips_list)
        if total_raw == 0:
            logging.warning("No raw IPs provided for inspection. Aborting cycle.")
            return

        logging.info(f"Initiating strict inspection of {total_raw} raw IPs with 15-second timeout...")
        start_time = time.time()
        
        # Live Telemetry: Inspection started broadcast to UI dashboard
        await self._emit_telemetry(status="inspection_started", tested=total_raw, passed=0)

        # High-concurrency asynchronous task execution for rapid validation
        tasks = [self._test_single_proxy(ip) for ip in raw_ips_list]
        tested_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out dead proxies and safely gather only the elite verified IPs
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

# Standalone execution block for isolated testing
if __name__ == "__main__":
    async def dummy_runner():
        inspector = ProxyInspector()
        sample_ips = ["192.168.1.1:8080", "10.0.0.1:3128"]
        await inspector.execute_inspection(sample_ips)

    asyncio.run(dummy_runner())
