import requests
import asyncio
from typing import List, Dict, Any
import time

class FuzzerEngine:
    def __init__(self):
        self.is_running = False
        self.completed_requests = 0
        self.total_requests = 0

    async def run_fuzz(self, target_requests: List[Dict[str, Any]], delay_ms: int = 100, base_url: str = None) -> List[Dict[str, Any]]:
        self.is_running = True
        self.total_requests = len(target_requests)
        self.completed_requests = 0
        results = []
        
        # Create a persistent session to handle cookies/sessions
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

        # Initialize session by visiting the base URL once to grab initial cookies
        if base_url:
            try:
                await asyncio.to_thread(session.get, base_url, timeout=5)
            except Exception as e:
                print(f"Warning: Failed to initialize session cookies: {e}")

        for req_dict in target_requests:
            if not self.is_running:
                break
                
            url_to_test = req_dict["url"]
            method = req_dict.get("method", "GET")
            data = req_dict.get("data")
            payload = req_dict["payload"]
                
            try:
                start_time = time.time()
                
                # Execute using the persistent session
                if method == "POST":
                    response = await asyncio.to_thread(session.post, url_to_test, data=data, timeout=5)
                else:
                    response = await asyncio.to_thread(session.get, url_to_test, timeout=5)
                    
                end_time = time.time()
                
                results.append({
                    "payload": payload,
                    "url": url_to_test,
                    "method": method,
                    "status_code": response.status_code,
                    "length": len(response.text),
                    "response_body": response.text[:50000],  # Save chunk for signature matching
                    "time_ms": round((end_time - start_time) * 1000, 2),
                    "error": None
                })
            except Exception as e:
                results.append({
                    "payload": payload,
                    "url": url_to_test,
                    "method": method,
                    "status_code": 0,
                    "length": 0,
                    "response_body": "",
                    "time_ms": 0,
                    "error": str(e)
                })
                
            self.completed_requests += 1
            await asyncio.sleep(delay_ms / 1000.0)
            
        self.is_running = False
        return results

    def stop(self):
        self.is_running = False

fuzzer_instance = FuzzerEngine()
