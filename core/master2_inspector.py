import asyncio
import httpx
import logging
import time
from cryptography.fernet import Fernet
import redis.asyncio as redis
from typing import List, Callable, Optional
import os

# Professional logging setup
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE 2: INSPECTOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# SECURITY LAYER: Fernet Encryption Key
# The Gateway (Engine 4) will need this exact same key to unlock the IPs.
# In production, this should be set via environment variable.
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode('utf-8'))
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

class ProxyInspector:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        Engine 2: Validates raw IPs for speed and Elite/High anonymity.
        Only stores bulletproof IPs into the Redis vault.
        """
        # Endpoint to test if the proxy actually hides our real IP
        self.anonymity_test_url = "https://httpbin.org/ip"
        
        # Connection to the local, shielded Redis Vault (Engine 3 territory)
        self.redis_vault = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=False)
        
        # Telemetry hook for the UI Dashboard
        self.ui_broadcast = ui_broadcast_callback

    async def _emit_telemetry(self, status: str, tested: int, passed: int, execution_time: float = 0.0):
        """Streams live validation metrics to the WebSocket dashboard."""
        if self.ui_broadcast:
            payload = {
                "engine": "master_2_inspector",
                "status": status,
                "ips_tested": tested,
                "ips_passed": passed,
                "execution_time_sec": round(execution_time, 2)
            }
            await self.ui_broadcast(payload)

    async def _test_single_proxy(self, raw_ip: str, client: httpx.AsyncClient) -> Optional[str]:
        """
        The Acid Test: Connects via the proxy and checks the returned IP.
        If it returns our server's real IP, it's a transparent proxy and must be dropped.
        """
        proxy_url = f"http://{raw_ip}"
        proxies = {"http://": proxy_url, "https://": proxy_url}
        
        try:
            # Strict 5.0 second timeout for elite performance
            response = await client.get(self.anonymity_test_url, proxies=proxies, timeout=5.0)
            
            if response.status_code == 200:
                data = response.json()
                returned_ip = data.get("origin", "")
                
                # Check if the proxy successfully hid our identity
                # (The returned IP should be the proxy's IP, or at least NOT our Oracle server IP)
                if raw_ip.split(':')[0] in returned_ip:
                    return raw_ip
                    
        except Exception:
            # Silently drop connection resets, timeouts, and slow IPs
            pass
            
        return None

    async def _secure_and_store(self, valid_ip: str):
        """Encrypts the validated IP and locks it in the Redis Vault."""
        encrypted_ip = cipher_suite.encrypt(valid_ip.encode('utf-8'))
        # Using Redis Set (sadd) automatically prevents duplicates in the vault
        await self.redis_vault.sadd("vip_proxy_pool", encrypted_ip)

    async def execute_inspection(self, raw_ips_list: List[str]):
        """
        Takes the raw list from Engine 1, tests them concurrently, 
        and stores the survivors in the vault.
        """
        total_raw = len(raw_ips_list)
        if total_raw == 0:
            logging.warning("No raw IPs provided to inspect. Aborting cycle.")
            return

        logging.info(f"Initiating strict inspection of {total_raw} raw IPs...")
        start_time = time.time()
        
        # Telemetry: Inspection started
        await self._emit_telemetry(status="inspection_started", tested=total_raw, passed=0)

        # High-concurrency testing using AsyncClient
        async with httpx.AsyncClient() as client:
            tasks = [self._test_single_proxy(ip, client) for ip in raw_ips_list]
            tested_results = await asyncio.gather(*tasks)

        # Filter out the dead/transparent proxies (None values)
        elite_ips = [ip for ip in tested_results if ip is not None]
        total_elite = len(elite_ips)
        
        logging.info(f"Inspection complete. {total_elite} Elite IPs passed the test. Securing vault...")

        # Store survivors concurrently
        if total_elite > 0:
            store_tasks = [self._secure_and_store(ip) for ip in elite_ips]
            await asyncio.gather(*store_tasks)

        execution_time = time.time() - start_time
        logging.info(f"Vault updated. Cycle completed in {round(execution_time, 2)} seconds.")
        
        # Telemetry: Inspection completed
        await self._emit_telemetry(
            status="inspection_completed", 
            tested=total_raw, 
            passed=total_elite, 
            execution_time=execution_time
        )

# Standalone execution block for testing
if __name__ == "__main__":
    async def dummy_ui_receiver(data):
        print(f"\n[UI TELEMETRY] {data}\n")

    # Mock list to test the engine directly
    mock_raw_ips = ["143.198.113.12:8080", "192.168.1.1:80", "8.8.8.8:8080"]
    inspector_engine = ProxyInspector(ui_broadcast_callback=dummy_ui_receiver)
    asyncio.run(inspector_engine.execute_inspection(mock_raw_ips))
