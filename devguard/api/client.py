import asyncio
import logging
import time
from typing import Any, Dict, Optional, Union
import httpx

logger = logging.getLogger("devguard.api.client")

class ForemClient:
    def __init__(
        self,
        base_url: str = "https://dev.to/api",
        api_key: str = "",
        rate_limit_per_sec: int = 10,
        max_retries: int = 3,
        backoff_factor: float = 1.5
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.rate_limit_per_sec = rate_limit_per_sec
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        
        # Async HTTP client
        headers = {
            "Accept": "application/vnd.forem.api-v1+json",
        }
        if api_key:
            headers["api-key"] = api_key
            
        self.client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(15.0, connect=5.0),
            follow_redirects=True
        )
        
        # Rate limiting state
        self._last_request_time = 0.0
        self._rate_limit_delay = 1.0 / rate_limit_per_sec if rate_limit_per_sec > 0 else 0.0
        self._lock = asyncio.Lock()

    async def _throttle(self):
        """Enforces rate limiting using a sliding window or minimum delay between requests."""
        if self._rate_limit_delay <= 0:
            return
            
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._rate_limit_delay:
                wait_time = self._rate_limit_delay - elapsed
                await asyncio.sleep(wait_time)
            self._last_request_time = time.monotonic()

    async def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> httpx.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        
        retries = 0
        backoff = 1.0
        
        while True:
            await self._throttle()
            
            try:
                logger.debug(f"Sending request: {method} {url} with params={params}")
                response = await self.client.request(
                    method=method,
                    url=url,
                    params=params,
                    json=json_data,
                    headers=headers
                )
                
                # Check for rate limit responses (429) or server errors (5xx)
                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    wait_sec = float(retry_after) if retry_after and retry_after.isdigit() else backoff
                    logger.warning(f"Rate limited (429). Retrying in {wait_sec} seconds...")
                    await asyncio.sleep(wait_sec)
                    retries += 1
                    backoff *= self.backoff_factor
                    if retries >= self.max_retries:
                        response.raise_for_status()
                    continue
                    
                if response.status_code >= 500:
                    logger.warning(f"Server error ({response.status_code}). Retrying in {backoff} seconds...")
                    await asyncio.sleep(backoff)
                    retries += 1
                    backoff *= self.backoff_factor
                    if retries >= self.max_retries:
                        response.raise_for_status()
                    continue
                
                # Check other HTTP errors
                response.raise_for_status()
                return response
                
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP Error {e.response.status_code} for {method} {url}: {e.response.text}")
                raise
            except httpx.RequestError as e:
                logger.error(f"Network error requesting {method} {url}: {e}")
                retries += 1
                if retries >= self.max_retries:
                    raise
                await asyncio.sleep(backoff)
                backoff *= self.backoff_factor

    async def get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        response = await self.request("GET", path, params=params)
        try:
            return response.json()
        except ValueError:
            return response.text

    async def post(self, path: str, json_data: Optional[Dict[str, Any]] = None) -> Any:
        response = await self.request("POST", path, json_data=json_data)
        try:
            return response.json()
        except ValueError:
            return response.text

    async def put(self, path: str, json_data: Optional[Dict[str, Any]] = None) -> Any:
        response = await self.request("PUT", path, json_data=json_data)
        try:
            return response.json()
        except ValueError:
            return response.text

    async def close(self):
        await self.client.aclose()
