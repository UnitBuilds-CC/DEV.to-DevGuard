import pytest
from unittest.mock import AsyncMock, MagicMock
from devguard.api.client import ForemClient
from devguard.api.users import UsersAPI
from devguard.api.comments import CommentsAPI
from devguard.api.articles import ArticlesAPI

@pytest.mark.asyncio
async def test_forem_client_headers():
    client = ForemClient(base_url="https://dev.to/api", api_key="test_token")
    assert client.client.headers["api-key"] == "test_token"
    assert client.client.headers["Accept"] == "application/vnd.forem.api-v1+json"
    await client.close()

@pytest.mark.asyncio
async def test_users_api():
    mock_client = AsyncMock()
    mock_client.get.return_value = {"id": 1234, "username": "testuser"}
    
    users_api = UsersAPI(mock_client)
    profile = await users_api.get_user_profile(1234)
    
    assert profile["username"] == "testuser"
    mock_client.get.assert_called_once_with("/users/1234")

@pytest.mark.asyncio
async def test_comments_api():
    mock_client = AsyncMock()
    mock_client.get.return_value = [{"id_code": "abc", "body": "hello"}]
    
    comments_api = CommentsAPI(mock_client)
    comments = await comments_api.get_comments_by_article(99)
    
    assert len(comments) == 1
    assert comments[0]["id_code"] == "abc"
    mock_client.get.assert_called_once_with("/comments", params={"a_id": 99})

@pytest.mark.asyncio
async def test_articles_api():
    mock_client = AsyncMock()
    mock_client.get.return_value = [{"id": 101, "title": "My Post"}]
    
    articles_api = ArticlesAPI(mock_client)
    articles = await articles_api.get_articles(page=2, per_page=10)
    
    assert len(articles) == 1
    assert articles[0]["id"] == 101
    mock_client.get.assert_called_once_with("/articles", params={"page": 2, "per_page": 10})
