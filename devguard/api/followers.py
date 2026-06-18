from typing import Any, List, Dict, Optional
from devguard.api.client import ForemClient

class FollowersAPI:
    def __init__(self, client: ForemClient):
        self.client = client

    async def get_followers(self, page: int = 1, per_page: int = 80) -> List[Dict[str, Any]]:
        """List followers with pagination.
        
        GET /followers/users
        """
        params = {"page": page, "per_page": per_page}
        result = await self.client.get("/followers/users", params=params)
        if isinstance(result, list):
            return result
        return []
