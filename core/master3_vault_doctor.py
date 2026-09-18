import asyncio
import httpx
import logging
import time
from cryptography.fernet import Fernet
import redis.asyncio as redis
from typing import List, Optional, Callable
import os

# Professional logging setup for Engine 3 (Vault Doctor)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [ENGINE 3: VAULT DOCTOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Secure Encryption Key for Vault Storage
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", Fernet.generate_key().decode('utf-8'))
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

class VaultDoctor:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        Engine 3: Vault Doctor
        Constantly monitors the Redis Vault, extracting encrypted proxies,
        testing them for continued vitality, and purging dead IPs to maintain 100% freshness.
        """
        self.health_check_url = "http://httpbin.org/get"
        self.redis_vault = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=False)
        self.ui_broadcast = ui_broadcast_callback

    async def _emit_telemetry(self, status: str, total_checked: int, total_purged: int, healthy_count: int, execution_time: float = 0.0):
        """Safely broadcasts real-time health metrics to the WebSocket UI dashboard."""
        if self.ui_broadcast:
            try:
                # Calculating Vault Health Score (Percentage)
                health_score = 0
                if total_checked > 0:
                    health_score = int((healthy_count / total_checked) * 100)

                payload = {
                    "engine": "master_3_vault_doctor",
                    "status": status,
                    "total_ips_checked": total_checked,
                    "dead_ips_purged": total_purged,
                    "vault_health_score": health_score,
                    "execution_time_sec": round(execution_time, 2)
                }
                await self.ui_broadcast(payload)
            except Exception as e:
                logging.error(f"Failed to broadcast telemetry to UI: {str(e)}")

    async def _verify_proxy_health(self, raw_ip: str) -> bool:
        """
        Performs a rapid health check on an existing elite proxy.
        Returns True if the proxy is still alive, False if it is dead.
        Configured with modern HTTPX syntax and identical 15.0-second timeout matching Engine 2.
        """
        proxy_url = f"http://{raw_ip}"
        
        # Universal proxy syntax to prevent false negatives
        proxies_config = {
            "http://": proxy_url,
            "https://": proxy_url
        }
        
        try:
            # Deep vitality check with 15.0 seconds timeout (Matched with Inspector)
            async with httpx.AsyncClient(
                proxies=proxies_config, 
                timeout=15.0, 
                verify=False,
                follow_redirects=True
            ) as client:
                
                response = await client.get(self.health_check_url)
                
                if response.status_code == 200:
                    return True
                    
        except Exception:
            # Silent fail for legitimately dead proxies or network timeouts
            pass
            
        return False

    async def perform_vault_surgery(self):
        """
        Executes a complete sweep of the Vault.
        Decrypts all proxies, checks their health, and strictly purges only the dead ones.
        """
        logging.info("Initiating Vault Maintenance Cycle (Checking health of all secured IPs)...")
        start_time = time.time()
        
        # 1. Fetch all encrypted proxies from the vault
        encrypted_proxies = await self.redis_vault.smembers("vip_proxy_pool")
        total_vault_size = len(encrypted_proxies)
        
        if total_vault_size == 0:
            logging.warning("Vault is currently empty. Maintenance cycle aborted.")
            await self._emit_telemetry("maintenance_aborted", 0, 0, 0, round(time.time() - start_time, 2))
            return

        # Live Telemetry: Surgery started
        await self._emit_telemetry("maintenance_started", total_vault_size, 0, total_vault_size)

        # 2. Decrypt proxies for testing
        proxy_map = {}
        for enc_proxy in encrypted_proxies:
            try:
                raw_ip = cipher_suite.decrypt(enc_proxy).decode('utf-8')
                proxy_map[enc_proxy] = raw_ip
            except Exception as e:
                logging.error(f"Decryption failed for a proxy entry: {str(e)}")
                proxy_map[enc_proxy] = None

        valid_raw_ips = [ip for ip in proxy_map.values() if ip is not None]
        logging.info(f"Strict vitality check initiated for {len(valid_raw_ips)} Elite IPs with 15-second timeout...")

        # 3. High-concurrency async health checking
        tasks = [self._verify_proxy_health(ip) for ip in valid_raw_ips]
        health_results = await asyncio.gather(*tasks, return_exceptions=True)

        # 4. Identify legitimately dead proxies and purge them
        dead_count = 0
        for enc_proxy, raw_ip in proxy_map.items():
            if raw_ip is None:
                # Purge corrupted/undecryptable entry
                await self.redis_vault.srem("vip_proxy_pool", enc_proxy)
                dead_count += 1
                continue
                
            index = valid_raw_ips.index(raw_ip)
            is_alive = health_results[index]
            
            if not isinstance(is_alive, bool) or not is_alive:
                # Strictly removing only confirmed dead proxies
                await self.redis_vault.srem("vip_proxy_pool", enc_proxy)
                dead_count += 1

        healthy_count = total_vault_size - dead_count
        execution_time = time.time() - start_time
        
        logging.info(f"Maintenance Complete. Checked: {total_vault_size} | Purged Dead: {dead_count} | Healthy Remaining: {healthy_count}")
        
        # Trigger emergency alert if vault is completely wiped
        if healthy_count == 0:
            logging.error("RED ALERT: Vault is critically low (0 IPs). Triggering emergency Hunter override.")
            await self._emit_telemetry("panic_empty", total_vault_size, dead_count, healthy_count, execution_time)
        else:
            logging.info(f"Vault maintained successfully in {round(execution_time, 2)} seconds.")
            await self._emit_telemetry("maintenance_completed", total_vault_size, dead_count, healthy_count, execution_time)

# Standalone execution for manual terminal testing
if __name__ == "__main__":
    doctor = VaultDoctor()
    asyncio.run(doctor.perform_vault_surgery())
