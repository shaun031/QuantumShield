"""Phase 15 aggregates stay owner-scoped and research exports stay read-only."""

import json
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.routes import research
from tests.test_files import register_and_login, upload
from tests.test_sharing import create_share


def test_dashboard_counts_distributions_and_activity_are_scoped(client: TestClient) -> None:
    alice, alice_headers = register_and_login(client, "dashboard-alice@example.com")
    bob, bob_headers = register_and_login(client, "dashboard-bob@example.com")
    _, outsider_headers = register_and_login(client, "dashboard-outsider@example.com")
    file_id = upload(client, alice_headers).json()["id"]
    share_id = create_share(client, alice_headers, file_id, bob["id"]).json()["id"]

    owner = client.get("/api/dashboard/summary", headers=alice_headers)
    assert owner.status_code == 200
    data = owner.json()
    assert (data["my_files"], data["shared_with_me"], data["shared_by_me"]) == (1, 0, 1)
    assert (data["active_shares"], data["revoked_shares"]) == (1, 0)
    assert data["security_levels"]["STANDARD"] == 1
    assert data["architectures"]["PQ_ONLY"] == 1
    assert data["selection_modes"]["MANUAL"] == 1
    assert all(data["key_readiness"].values())
    assert data["recent_decisions"][0]["filename"] == "report.txt"
    assert data["recent_activity"][0]["event_type"] == "SHARE_CREATED"
    assert "wrapped_file_key" not in str(data)
    assert "private_key" not in str(data)

    counts = client.get(f"/api/dashboard/file-share-counts?file_ids={file_id}", headers=alice_headers)
    assert counts.json() == {file_id: 1}
    assert client.get(f"/api/dashboard/file-share-counts?file_ids={file_id}", headers=bob_headers).json() == {}
    assert client.get("/api/dashboard/summary", headers=outsider_headers).json()["my_files"] == 0
    assert client.get("/api/dashboard/summary", headers=bob_headers).json()["shared_with_me"] == 1
    assert client.get("/api/dashboard/summary", headers=outsider_headers).json()["recent_activity"] == []

    assert client.post(f"/api/shares/{share_id}/revoke", headers=alice_headers).status_code == 200
    after = client.get("/api/dashboard/summary", headers=alice_headers).json()
    assert (after["active_shares"], after["revoked_shares"]) == (0, 1)
    assert client.get(f"/api/dashboard/file-share-counts?file_ids={file_id}", headers=alice_headers).json() == {}
    recipient = client.get("/api/dashboard/summary", headers=bob_headers).json()
    assert recipient["my_files"] == 0
    assert recipient["recent_decisions"] == []
    assert all(event["role"] == "recipient" for event in recipient["recent_activity"])
    assert alice["id"] not in str(recipient["recent_activity"])


def test_research_latest_requires_auth_and_never_fabricates(tmp_path, monkeypatch, client: TestClient) -> None:
    _, headers = register_and_login(client, "research-viewer@example.com")
    monkeypatch.setattr(research, "RESULTS", tmp_path)
    assert client.get("/api/research/benchmarks/latest").status_code == 401
    assert client.get("/api/research/adaptive/latest").status_code == 401
    assert client.get("/api/research/benchmarks/latest", headers=headers).status_code == 404
    assert client.get("/api/research/adaptive/latest", headers=headers).status_code == 404
    run = tmp_path / str(uuid4())
    run.mkdir()
    (run / "results.json").write_text(json.dumps({"benchmark_schema_version": 1, "run_id": run.name, "results": [], "note": "private operator note"}), encoding="utf-8")
    benchmark = client.get("/api/research/benchmarks/latest", headers=headers).json()
    assert benchmark["run_id"] == run.name
    assert "note" not in benchmark
    adaptive = tmp_path / "adaptive" / str(uuid4())
    adaptive.mkdir(parents=True)
    (adaptive / "adaptive_vs_fixed.json").write_text(json.dumps({"experiment_schema_version": 1, "status": "FAILED", "comparisons": []}), encoding="utf-8")
    assert client.get("/api/research/adaptive/latest", headers=headers).status_code == 404
