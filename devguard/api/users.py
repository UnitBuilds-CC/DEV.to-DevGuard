from typing import Any, Dict, Optional
from devguard.api.client import ForemClient

class UsersAPI:
    def __init__(self, client: ForemClient):
        self.client = client

    async def get_user_profile(self, user_id: int) -> Dict[str, Any]:
        """Fetch a user's profile by ID.
        
        GET /users/{id}
        """
        result = await self.client.get(f"/users/{user_id}")
        if isinstance(result, dict):
            return result
        return {}

    async def get_user_profile_by_username(self, username: str) -> Dict[str, Any]:
        """Fetch a user's profile by username.
        
        GET /users/by_username?url={username}
        """
        params = {"url": username}
        result = await self.client.get("/users/by_username", params=params)
        if isinstance(result, dict):
            return result
        return {}

    async def get_current_user(self) -> Dict[str, Any]:
        """Fetch the authenticated user (me).
        
        GET /users/me
        """
        result = await self.client.get("/users/me")
        if isinstance(result, dict):
            return result
        return {}

    async def suspend_user(self, user_id: int) -> bool:
        """Suspend a user (Requires Admin Key).
        
        PUT /api/admin/users/{id}/suspend
        or
        PUT /users/{id}/suspend
        """
        try:
            # Forem handles administrative API operations typically under /api/admin/users/{id}/suspend
            # or custom admin namespaces. We'll support both paths by falling back if one fails.
            await self.client.put(f"/api/admin/users/{user_id}/suspend")
            return True
        except Exception:
            try:
                await self.client.put(f"/users/{user_id}/suspend")
                return True
            except Exception:
                return False

    async def unpublish_user_content(self, user_id: int) -> bool:
        """Unpublish all content by a user (Requires Admin Key).
        
        PUT /api/admin/users/{id}/unpublish
        or
        PUT /users/{id}/unpublish
        """
        try:
            await self.client.put(f"/api/admin/users/{user_id}/unpublish")
            return True
        except Exception:
            try:
                await self.client.put(f"/users/{user_id}/unpublish")
                return True
            except Exception:
                return False
