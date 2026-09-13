import asyncio
import httpx
import logging
import time
from cryptography.fernet import Fernet
import redis.asyncio as redis
from typing import Callable, Optional
import os

# Professional logging setup for enterprise monitoring
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE 3: VAULT DOCTOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# SECURITY LAYER: Must match Engine 2 & Engine 4 exactly
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode('utf-8'))
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

class VaultDoctor:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        Engine 3: Background maintenance protocol. 
        Continuously re-evaluates stored IPs in the Redis Vault to ensure 100% uptime.
        """
        self.redis_vault = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=False)
        self.test_url = "https://www.google.com/generate_204"
        self.ui_broadcast = ui_broadcast_callback
        
        # --- [ENTERPRISE SCALE THRESHOLDS] ---
        # 5,000 IPs is the absolute minimum buffer for millions of requests.
        self.minimum_healthy_ips = 5000 
        # Panic Threshold: Extreme emergency if it drops below 1,000
        self.panic_threshold_ips = 1000 

    async def _emit_telemetry(self, status: str, total_checked: int, purged: int, health_score: int):
        """Streams live health metrics to the WebSocket dashboard."""
        if self.ui_broadcast:
            payload = {
                "engine": "master_3_vault_doctor",
                "status": status,
                "total_ips_checked": total_checked,
                "dead_ips_purged": purged,
                "vault_health_score": health_score # Percentage 0-100
            }
            await self.ui_broadcast(payload)

    async def _reverify_proxy(self, encrypted_ip: bytes, client: httpx.AsyncClient) -> Optional[bytes]:
        """
        Decrypts an IP, tests its current speed, and returns it if it's still elite.
        Returns None if it's dead, signaling it should be purged.
        """
        try:
            decrypted_ip = cipher_suite.decrypt(encrypted_ip).decode('utf-8')
            proxy_url = f"http://{decrypted_ip}"
            proxies = {"http://": proxy_url, "https://": proxy_url}
            
            # Strict 5-second re-test for elite performance
            response = await client.get(self.test_url, proxies=proxies, timeout=5.0)
            if response.status_code == 204:
                return encrypted_ip # Still healthy
                
        except Exception:
            pass # Proxy is dead or slow
            
        return None

    async def execute_maintenance_cycle(self):
        """
        Extracts all IPs from the vault, tests them concurrently, 
        and rewrites the vault with only the surviving healthy IPs.
        """
        logging.info("Initiating Vault Maintenance Cycle (Purging Stale IPs)...")
        start_time = time.time()

        # 1. Pull everything from the vault
        all_encrypted_ips = await self.redis_vault.smembers("vip_proxy_pool")
        total_vault_size = len(all_encrypted_ips)
        
        if total_vault_size == 0:
            logging.warning("CRITICAL: Vault is completely empty! Hunter Engine needed immediately.")
            await self._emit_telemetry("critical_empty", 0, 0, 0)
            return

        await self._emit_telemetry("maintenance_started", total_vault_size, 0, 100)

        # 2. Re-test all IPs concurrently
        async with httpx.AsyncClient() as client:
            tasks = [self._reverify_proxy(enc_ip, client) for enc_ip in all_encrypted_ips]
            results = await asyncio.gather(*tasks)

        # 3. Filter results
        healthy_encrypted_ips = [ip for ip in results if ip is not None]
        total_healthy = len(healthy_encrypted_ips)
        dead_count = total_vault_size - total_healthy

        # 4. Atomic Vault Rewrite (Zero Downtime for Gateway)
        pipeline = self.redis_vault.pipeline()
        pipeline.delete("vip_proxy_pool")
        if total_healthy > 0:
            pipeline.sadd("vip_proxy_pool", *healthy_encrypted_ips)
        await pipeline.execute()

        # Calculate Vault Health Score (0-100%)
        health_score = int((total_healthy / total_vault_size) * 100) if total_vault_size > 0 else 0
        
        logging.info(f"Maintenance Complete. Checked: {total_vault_size} | Purged Dead: {dead_count} | Healthy Remaining: {total_healthy}")
        
        # --- [UPDATED SMART ALARM LOGIC] ---
        if total_healthy < self.panic_threshold_ips:
            logging.critical(f"RED ALERT: Vault is critically low ({total_healthy} IPs). Millions of requests will crash the system! Triggering emergency Hunter override.")
            await self._emit_telemetry("panic_empty", total_vault_size, dead_count, health_score)
            
        elif total_healthy < self.minimum_healthy_ips:
            logging.warning(f"Vault Health Warning! Only {total_healthy} IPs remain. Sending signal to wake up the Hunter Engine.")
        
        await self._emit_telemetry("maintenance_completed", total_vault_size, dead_count, health_score)

# Standalone execution block for testing
if __name__ == "__main__":
    async def dummy_ui_receiver(data):
        print(f"\n[UI TELEMETRY] {data}\n")

    doctor_engine = VaultDoctor(ui_broadcast_callback=dummy_ui_receiver)
    asyncio.run(doctor_engine.execute_maintenance_cycle())
