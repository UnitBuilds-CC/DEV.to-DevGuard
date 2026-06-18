from typing import Any, List, Dict, Optional
from devguard.api.client import ForemClient

class ArticlesAPI:
    def __init__(self, client: ForemClient):
        self.client = client

    async def get_articles(
        self,
        page: int = 1,
        per_page: int = 30,
        username: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List articles with pagination, optionally filtered by username.
        
        GET /articles
        """
        params = {"page": page, "per_page": per_page}
        if username:
            params["username"] = username
            
        result = await self.client.get("/articles", params=params)
        if isinstance(result, list):
            return result
        return []

    async def get_latest_articles(self, page: int = 1, per_page: int = 30) -> List[Dict[str, Any]]:
        """Get latest articles.
        
        GET /articles/latest
        """
        params = {"page": page, "per_page": per_page}
        result = await self.client.get("/articles/latest", params=params)
        if isinstance(result, list):
            return result
        return []
