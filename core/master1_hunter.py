import asyncio
import httpx
import re
import logging
import time
from typing import Set, List, Callable, Optional
from urllib.parse import urlparse

# Professional logging setup for Engine 1
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE 1: HUNTER - SECURED] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class ProxyHunter:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        Engine 1: Secure Proxy Harvester
        Scrapes raw IPs globally with strict SSRF protection and memory overflow limits.
        """
        self.target_sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
        ]
        
        # Strict Regex pattern to extract only valid IPv4:PORT structures
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b')
        self.ui_broadcast = ui_broadcast_callback
        
        # Anti-SSRF Guard: Block internal or local network source URLs
        self.blocked_hosts = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'}

    async def _emit_telemetry(self, status: str, count: int, source: str = "all", execution_time: float = 0.0):
        """Streams live telemetry data packets to the UI WebSocket dashboard safely."""
        if self.ui_broadcast:
            try:
                payload = {
                    "engine": "master_1_hunter",
                    "status": status,
                    "source": source,
                    "ips_found": count,
                    "execution_time_sec": round(execution_time, 2)
                }
                if asyncio.iscoroutinefunction(self.ui_broadcast):
                    await self.ui_broadcast(payload)
                else:
                    self.ui_broadcast(payload)
            except Exception as e:
                logging.error(f"Failed to emit telemetry: {str(e)}")

    async def _extract_from_source(self, url: str, client: httpx.AsyncClient) -> Set[str]:
        """
        Connects to a single source, verifies SSRF safety, streams content with 
        a strict 2MB size cap to prevent memory bombs, and extracts raw IPs.
        """
        extracted_ips = set()
        start_time = time.time()
        
        # 1. SSRF Safety Shield on URL Hostname
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            if hostname in self.blocked_hosts or hostname.startswith(('192.168.', '10.', '172.16.')):
                logging.warning(f"SSRF Shield Blocked unsafe source URL: {url}")
                return extracted_ips
        except Exception:
            return extracted_ips

        try:
            # 2. Strict 7.0-second timeout and streaming with 2MB ceiling to stop Tarpits/Memory crashes
            async with client.stream("GET", url, timeout=7.0) as response:
                if response.status_code == 200:
                    raw_payload = ""
                    async for chunk in response.aiter_text():
                        raw_payload += chunk
                        if len(raw_payload) > 2 * 1024 * 1024:  # Max 2MB limit
                            logging.warning(f"Payload size limit exceeded for {url}. Aborting download.")
                            break
                            
                    # 3. Filter via Regex
                    found_ips = self.ip_pattern.findall(raw_payload)
                    extracted_ips.update(found_ips)
                    
                    logging.info(f"Success: Extracted {len(found_ips)} raw IPs from {url}")
                    await self._emit_telemetry("source_success", len(found_ips), url, time.time() - start_time)
                else:
                    logging.warning(f"Target Unreachable: {url} returned status code {response.status_code}")
                    await self._emit_telemetry("source_failed", 0, url)
                    
        except Exception as e:
            logging.error(f"Execution Failure on {url}: {str(e)}")
            await self._emit_telemetry("source_error", 0, url)
            
        return extracted_ips

    async def execute_hunt(self) -> List[str]:
        """
        Executes a secure parallel scraping operation across all defined target sources.
        """
        hunt_start_time = time.time()
        logging.info("Initiating secure global scrape for raw IPv4 addresses...")
        await self._emit_telemetry("hunt_started", 0)
        
        unique_raw_ips = set() 
        
        # follow_redirects=False prevents malicious redirection-based SSRF attacks
        async with httpx.AsyncClient(follow_redirects=False) as client:
            async_tasks = [self._extract_from_source(url, client) for url in self.target_sources]
            gathered_results = await asyncio.gather(*async_tasks)
            
            for ip_dataset in gathered_results:
                unique_raw_ips.update(ip_dataset)
                
        total_unique = len(unique_raw_ips)
        total_time = time.time() - hunt_start_time
        logging.info(f"Hunt Cycle Completed. Total unique raw IPs aggregated: {total_unique}")
        
        await self._emit_telemetry(
            status="hunt_completed", 
            count=total_unique, 
            execution_time=total_time
        )
        
        return list(unique_raw_ips)

# Standalone test block
if __name__ == "__main__":
    async def dummy_ui_receiver(data):
        print(f"\n[UI DASHBOARD SIMULATION] {data}\n")

    hunter_engine = ProxyHunter(ui_broadcast_callback=dummy_ui_receiver)
    asyncio.run(hunter_engine.execute_hunt())
