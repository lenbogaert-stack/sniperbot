from fastapi.testclient import TestClient

from app.main import app
from app.telegram_login import manager as tg_manager


def _build_update(chat_id: int, text: str = "/saxo_login") -> dict:
    return {
        "update_id": 1,
        "message": {
            "message_id": 99,
            "date": 1700000000,
            "chat": {"id": chat_id, "type": "private"},
            "from": {"id": 4242, "first_name": "Test", "username": "tester"},
            "text": text,
        },
    }


def test_telegram_webhook_disabled(monkeypatch):
    monkeypatch.setenv("TG_ENABLED", "false")
    monkeypatch.setenv("TG_BOT_TOKEN", "")
    tg_manager.reload()
    tg_manager._states.clear()

    with TestClient(app) as client:
        res = client.post("/telegram/webhook", json={"update_id": 1})
    assert res.status_code == 200
    assert res.json()["reason"] == "telegram_disabled"


def test_telegram_webhook_requires_secret(monkeypatch):
    monkeypatch.setenv("TG_ENABLED", "true")
    monkeypatch.setenv("TG_BOT_TOKEN", "dummy")
    monkeypatch.setenv("TG_CHAT_ID", "123")
    monkeypatch.setenv("TG_WEBHOOK_SECRET", "expected")
    monkeypatch.setenv("SAXO_APP_KEY", "abc")
    monkeypatch.setenv("SAXO_REDIRECT_URL", "https://example.com/oauth")
    tg_manager.reload()
    tg_manager._states.clear()

    update = _build_update(123)
    with TestClient(app) as client:
        res = client.post(
            "/telegram/webhook",
            json=update,
            headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"},
        )
    assert res.status_code == 401


def test_telegram_login_command(monkeypatch):
    monkeypatch.setenv("TG_ENABLED", "true")
    monkeypatch.setenv("TG_BOT_TOKEN", "dummy")
    monkeypatch.setenv("TG_CHAT_ID", "123")
    monkeypatch.setenv("TG_WEBHOOK_SECRET", "")
    monkeypatch.setenv("SAXO_APP_KEY", "abc")
    monkeypatch.setenv("SAXO_REDIRECT_URL", "https://example.com/oauth")
    monkeypatch.setenv("SAXO_AUTH_URL", "https://sim.logonvalidation.net/authorize")
    tg_manager.reload()
    tg_manager._states.clear()

    captured = []

    def fake_send(chat_id: int, text: str) -> None:
        captured.append((chat_id, text))

    monkeypatch.setattr(tg_manager, "send_message", fake_send)

    update = _build_update(123)
    with TestClient(app) as client:
        res = client.post("/telegram/webhook", json=update)

    data = res.json()
    assert res.status_code == 200
    assert data["action"] == "login_link_sent"
    state = data["state"]
    assert state in tg_manager._states
    assert captured and captured[0][0] == 123
    assert "https://sim.logonvalidation.net/authorize" in captured[0][1]
    assert state in captured[0][1]


def test_telegram_callback_success(monkeypatch):
    monkeypatch.setenv("TG_ENABLED", "true")
    monkeypatch.setenv("TG_BOT_TOKEN", "dummy")
    monkeypatch.setenv("TG_CHAT_ID", "123")
    monkeypatch.setenv("SAXO_APP_KEY", "abc")
    monkeypatch.setenv("SAXO_APP_SECRET", "secret")
    monkeypatch.setenv("SAXO_REDIRECT_URL", "https://example.com/oauth")
    tg_manager.reload()
    tg_manager._states.clear()

    pending = tg_manager.create_login_request(123, first_name="Tester")

    captured = []

    def fake_send(chat_id: int, text: str) -> None:
        captured.append((chat_id, text))

    monkeypatch.setattr(tg_manager, "send_message", fake_send)

    def fake_exchange(code: str) -> dict:
        assert code == "auth-code"
        return {"refresh_token": "REFRESH-XYZ123", "expires_in": 480}

    monkeypatch.setattr(tg_manager, "exchange_code_for_tokens", fake_exchange)

    with TestClient(app) as client:
        res = client.get(
            "/oauth/saxo/telegram/callback", params={"state": pending.state, "code": "auth-code"}
        )

    assert res.status_code == 200
    assert "Laatste 6 tekens" in res.text
    assert pending.state not in tg_manager._states
    assert any("REFRESH-XYZ123" in msg for _, msg in captured)

    from app import main as main_module

    assert main_module._stored_refresh_token == "REFRESH-XYZ123"
