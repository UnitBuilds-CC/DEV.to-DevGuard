from typing import Any, List, Dict, Optional
from devguard.api.client import ForemClient

class CommentsAPI:
    def __init__(self, client: ForemClient):
        self.client = client

    async def get_comments_by_article(self, article_id: int) -> List[Dict[str, Any]]:
        """Fetch all comments for a specific article.
        
        GET /comments?a_id={article_id}
        """
        params = {"a_id": article_id}
        result = await self.client.get("/comments", params=params)
        if isinstance(result, list):
            return result
        return []

    async def get_comment(self, comment_id: str) -> Dict[str, Any]:
        """Fetch a single comment and its descendants.
        
        GET /comments/{id}
        """
        result = await self.client.get(f"/comments/{comment_id}")
        if isinstance(result, dict):
            return result
        return {}
