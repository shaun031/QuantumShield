"""Authentication, object authorization, and bounded public inputs."""

from datetime import timedelta
from uuid import UUID, uuid4

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.auth import create_access_token
from app.core.config import settings
from app.models.user import User
from tests.test_files import register_and_login, upload
from tests.test_sharing import create_share


@pytest.mark.parametrize("authorization", [None, "Bearer nonsense", "Basic abc", "Bearer a.b.c"])
def test_invalid_or_missing_bearer_denied(client: TestClient, authorization: str | None) -> None:
    headers = {"Authorization": authorization} if authorization else {}
    for path in ("/api/users/me", "/api/files", "/api/shares/received", "/api/research/benchmarks/latest"):
        response = client.get(path, headers=headers)
        assert response.status_code == 401
        assert "Traceback" not in response.text


def test_expired_unknown_and_inactive_tokens_denied(client: TestClient, db_session: Session) -> None:
    registered, headers = register_and_login(client, "alice-security@example.com")
    valid = headers["Authorization"]
    assert client.get("/api/users/me", headers=headers).status_code == 200
    assert client.get("/api/users/me", headers=headers).status_code == 200  # replay before expiry
    expired = create_access_token(registered["id"], expires_delta=timedelta(seconds=-1))
    unknown = create_access_token(str(uuid4()))
    for token in (expired, unknown):
        assert client.get("/api/users/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    user = db_session.get(User, UUID(registered["id"]))
    assert user is not None
    user.is_active = False
    db_session.commit()
    assert client.get("/api/users/me", headers={"Authorization": valid}).status_code == 403


@pytest.mark.parametrize("claim,value", [("sub", "00000000-0000-4000-8000-000000000001"), ("type", "refresh"), ("exp", 1)])
def test_unsigned_payload_edit_is_rejected(client: TestClient, claim: str, value: str | int) -> None:
    _, headers = register_and_login(client, "jwt-security@example.com")
    token = headers["Authorization"].split(" ", 1)[1]
    decoded = jwt.decode(token, options={"verify_signature": False})
    decoded[claim] = value
    forged = jwt.encode(decoded, "attacker-key-that-is-not-the-server-secret", algorithm="HS256")
    response = client.get("/api/users/me", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401
    assert settings.secret_key.get_secret_value() not in response.text


def test_wrong_and_unknown_login_are_indistinguishable(client: TestClient) -> None:
    register_and_login(client, "login-security@example.com")
    attempts = [
        {"email": "login-security@example.com", "password": "WrongPassword123!"},
        {"email": "unknown-security@example.com", "password": "WrongPassword123!"},
    ]
    responses = [client.post("/api/auth/login", json=body) for body in attempts]
    assert [response.status_code for response in responses] == [401, 401]
    assert responses[0].json() == responses[1].json()


def test_file_and_share_idor_across_three_users(client: TestClient) -> None:
    alice, alice_h = register_and_login(client, "alice-idor@example.com")
    bob, bob_h = register_and_login(client, "bob-idor@example.com")
    _, charlie_h = register_and_login(client, "charlie-idor@example.com")
    file_id = upload(client, alice_h, content=b"owner secret").json()["id"]
    share_id = create_share(client, alice_h, file_id, bob["id"]).json()["id"]
    assert upload(client, bob_h, content=b"bob secret").status_code == 201
    for path in (f"/api/files/{file_id}", f"/api/files/{file_id}/download", f"/api/files/{file_id}/verify", f"/api/files/{file_id}/security-decision"):
        assert client.get(path, headers=bob_h).status_code == 404
    assert client.delete(f"/api/files/{file_id}", headers=bob_h).status_code == 404
    assert create_share(client, bob_h, file_id, alice["id"]).status_code == 404
    for path in (f"/api/shares/{share_id}", f"/api/shares/{share_id}/download", f"/api/shares/{share_id}/verify"):
        assert client.get(path, headers=charlie_h).status_code == 404
    for headers in (bob_h, charlie_h):
        assert client.post(f"/api/shares/{share_id}/revoke", headers=headers).status_code == 404
    assert client.get(f"/api/shares/{share_id}/download", headers=bob_h).content == b"owner secret"


@pytest.mark.parametrize("query", ["", "a", "  ", "x" * 101])
def test_search_broad_or_huge_query_rejected(client: TestClient, query: str) -> None:
    _, headers = register_and_login(client, "search-security@example.com")
    assert client.get("/api/users/search", params={"q": query}, headers=headers).status_code == 422


@pytest.mark.parametrize("query", ["' OR 1=1 --", '"; DROP TABLE users; --', "雪の文字列"])
def test_search_special_text_is_data(client: TestClient, query: str) -> None:
    _, headers = register_and_login(client, "search-safe@example.com")
    register_and_login(client, "another-safe@example.com")
    response = client.get("/api/users/search", params={"q": query}, headers=headers)
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.parametrize("path", ["/api/files", "/api/shares/received", "/api/shares/sent"])
@pytest.mark.parametrize("suffix", ["?limit=0", "?limit=999999", "?limit=oops", "?offset=-1"])
def test_pagination_abuse_rejected(client: TestClient, path: str, suffix: str) -> None:
    _, headers = register_and_login(client, "page-security@example.com")
    assert client.get(path + suffix, headers=headers).status_code == 422
