import asyncio
import httpx
import logging
import time
from cryptography.fernet import Fernet
import redis.asyncio as redis
from typing import Optional, Callable
import os

# Professional logging setup for Advanced Engine 3
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [ENGINE 3: ADVANCED VAULT DOCTOR] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Enterprise-Grade Fixed Shared Encryption Key (Strictly synchronized across Engines 2, 3, and 4)
DEFAULT_FIXED_KEY = "W3z9Lp7m1n4b6v8c0x3z5l7j9h1g3f5d7s9a2p4q6w8="
ENCRYPTION_KEY = os.environ.get("PROXY_ENCRYPTION_KEY", DEFAULT_FIXED_KEY)
cipher_suite = Fernet(ENCRYPTION_KEY.encode('utf-8'))

class VaultDoctor:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        Engine 3: Advanced Vault Doctor
        Uses non-blocking streaming scans, batch-chunked vitality checks,
        and positional token tracking to maintain a 100% pure proxy vault.
        """
        self.health_check_url = "http://httpbin.org/get"
        
        REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
        REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
        REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)
        
        self.redis_vault = redis.Redis(
            host=REDIS_HOST, 
            port=REDIS_PORT, 
            db=0, 
            password=REDIS_PASSWORD, 
            decode_responses=False  # Required for binary Fernet tokens
        )
        
        self.ui_broadcast = ui_broadcast_callback
        self.minimum_healthy_ips = 50
        
        # Concurrency control: Max 100 active network checks simultaneously
        self.semaphore = asyncio.Semaphore(100)

    async def _emit_telemetry(self, status: str, total_checked: int, total_purged: int, healthy_count: int, execution_time: float = 0.0):
        """Safely broadcasts real-time health metrics to the WebSocket UI dashboard."""
        if self.ui_broadcast:
            try:
                health_score = int((healthy_count / total_checked) * 100) if total_checked > 0 else 0
                payload = {
                    "engine": "master_3_vault_doctor",
                    "status": status,
                    "total_ips_checked": total_checked,
                    "dead_ips_purged": total_purged,
                    "vault_health_score": health_score,
                    "execution_time_sec": round(execution_time, 2)
                }
                if asyncio.iscoroutinefunction(self.ui_broadcast):
                    await self.ui_broadcast(payload)
                else:
                    self.ui_broadcast(payload)
            except Exception as e:
                logging.error(f"Failed to broadcast telemetry to UI: {str(e)}")

    async def _verify_proxy_health(self, raw_ip: str) -> bool:
        """Performs a rapid health check on an elite proxy under semaphore constraints."""
        async with self.semaphore:
            proxy_url = f"http://{raw_ip}"
            proxies_config = {"http://": proxy_url, "https://": proxy_url}
            
            try:
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
                pass
            return False

    async def perform_vault_surgery(self):
        """
        Executes an advanced, non-blocking sweep of the Redis Vault using 
        iterative scanning and memory-safe batch chunking.
        """
        logging.info("Initiating Advanced Vault Maintenance Cycle...")
        start_time = time.time()
        
        # 1. Advanced Non-Blocking Stream Scan (Replaces heavy smembers)
        valid_items = []  # Stores tuples of (enc_proxy, raw_ip)
        dead_count = 0
        total_vault_size = 0

        async for enc_proxy in self.redis_vault.sscan_iter("vip_proxy_pool", match=None, count=100):
            total_vault_size += 1
            try:
                raw_ip = cipher_suite.decrypt(enc_proxy).decode('utf-8')
                valid_items.append((enc_proxy, raw_ip))
            except Exception:
                # Purge corrupted/undecryptable cryptographic tokens instantly
                await self.redis_vault.srem("vip_proxy_pool", enc_proxy)
                dead_count += 1

        if total_vault_size == 0:
            logging.warning("Vault is currently empty. Maintenance cycle aborted.")
            await self._emit_telemetry("maintenance_aborted", 0, 0, 0, round(time.time() - start_time, 2))
            return

        # Broadcast maintenance start telemetry
        await self._emit_telemetry("maintenance_started", total_vault_size, 0, total_vault_size)
        logging.info(f"Scanning {len(valid_items)} valid entries in batches with semaphore protection...")

        # 2. Advanced Batch Chunking (Processes 200 proxies at a time to prevent RAM spikes)
        batch_size = 200
        for i in range(0, len(valid_items), batch_size):
            batch = valid_items[i:i + batch_size]
            tasks = [self._verify_proxy_health(item[1]) for item in batch]
            health_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Positional verification and purging per batch
            for j, (enc_proxy, raw_ip) in enumerate(batch):
                is_alive = health_results[j]
                if not isinstance(is_alive, bool) or not is_alive:
                    await self.redis_vault.srem("vip_proxy_pool", enc_proxy)
                    dead_count += 1

        healthy_count = total_vault_size - dead_count
        execution_time = time.time() - start_time
        
        # Emergency Alert State
        if healthy_count == 0:
            logging.error("RED ALERT: Vault is critically low (0 IPs). Triggering emergency override.")
            await self._emit_telemetry("panic_empty", total_vault_size, dead_count, healthy_count, execution_time)
        else:
            logging.info(f"Advanced Vault Maintenance Complete. Purged: {dead_count} | Healthy Remaining: {healthy_count}")
            await self._emit_telemetry("maintenance_completed", total_vault_size, dead_count, healthy_count, execution_time)
