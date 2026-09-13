import asyncio
import httpx
import re
import logging
import time
from typing import Set, List, Callable, Optional

# Professional logging setup for enterprise monitoring
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [ENGINE 1: HUNTER] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class ProxyHunter:
    def __init__(self, ui_broadcast_callback: Optional[Callable] = None):
        """
        ui_broadcast_callback: A function passed from the Main System (Gateway) 
        to stream live telemetry data to the WebSockets Dashboard.
        """
        # Target sources for scraping raw proxies globally
        self.target_sources = [
            "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"
        ]
        
        # Strict Regex pattern to extract only valid IPv4:PORT structures
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}\b')
        
        # The hook to send live data to the UI
        self.ui_broadcast = ui_broadcast_callback

    async def _emit_telemetry(self, status: str, count: int, source: str = "all", execution_time: float = 0.0):
        """
        Fires live data packets to the UI Dashboard if the callback is connected.
        """
        if self.ui_broadcast:
            payload = {
                "engine": "master_1_hunter",
                "status": status,
                "source": source,
                "ips_found": count,
                "execution_time_sec": round(execution_time, 2)
            }
            # Asynchronously send data to the WebSocket manager
            await self.ui_broadcast(payload)

    async def _extract_from_source(self, url: str, client: httpx.AsyncClient) -> Set[str]:
        """
        Connects to a single source, scrapes the raw text, and extracts IPs.
        """
        extracted_ips = set()
        start_time = time.time()
        
        try:
            # 10-second strict timeout to prevent engine blockages
            response = await client.get(url, timeout=10.0)
            if response.status_code == 200:
                raw_payload = response.text
                found_ips = self.ip_pattern.findall(raw_payload)
                extracted_ips.update(found_ips)
                
                logging.info(f"Success: Extracted {len(found_ips)} raw IPs from {url}")
                # Emit live UI data for this specific source
                await self._emit_telemetry(
                    status="source_success", 
                    count=len(found_ips), 
                    source=url,
                    execution_time=time.time() - start_time
                )
            else:
                logging.warning(f"Target Unreachable: {url} returned status code {response.status_code}")
                await self._emit_telemetry(status="source_failed", count=0, source=url)
                
        except Exception as e:
            logging.error(f"Execution Failure: Could not reach {url}. Exception: {str(e)}")
            await self._emit_telemetry(status="source_error", count=0, source=url)
            
        return extracted_ips

    async def execute_hunt(self) -> List[str]:
        """
        Executes a high-speed parallel scraping operation.
        Emits 'start' and 'complete' telemetry data to the UI.
        """
        hunt_start_time = time.time()
        logging.info("Initiating global scrape for raw IPv4 addresses...")
        
        # Tell the UI the hunt has started
        await self._emit_telemetry(status="hunt_started", count=0)
        
        unique_raw_ips = set() 
        
        # Establishing asynchronous client context for nano-second concurrency
        async with httpx.AsyncClient() as client:
            async_tasks = [self._extract_from_source(url, client) for url in self.target_sources]
            gathered_results = await asyncio.gather(*async_tasks)
            
            for ip_dataset in gathered_results:
                unique_raw_ips.update(ip_dataset)
                
        total_unique = len(unique_raw_ips)
        total_time = time.time() - hunt_start_time
        logging.info(f"Hunt Cycle Completed. Total unique raw IPs aggregated: {total_unique}")
        
        # Tell the UI the final result
        await self._emit_telemetry(
            status="hunt_completed", 
            count=total_unique, 
            execution_time=total_time
        )
        
        return list(unique_raw_ips)

# Standalone execution block for isolated testing
if __name__ == "__main__":
    # Dummy callback just to see what the UI would receive during a test
    async def dummy_ui_receiver(data):
        print(f"\n[UI DASHBOARD SIMULATION] Received live data: {data}\n")

    hunter_engine = ProxyHunter(ui_broadcast_callback=dummy_ui_receiver)
    asyncio.run(hunter_engine.execute_hunt())
