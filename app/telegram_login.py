"""Telegram webhook + Saxo OAuth helper.

Dit module verzorgt de state-handling voor de Telegram-logincommandos
en de uitwisseling van de authorization code naar een (refresh) token.

Alles is bewust synchrone code zodat het zowel in tests als in FastAPI
endpoints eenvoudig aan te roepen is. Netwerkfouten worden gelogd maar
breken het proces niet – de FastAPI-routes geven in dat geval een
vriendelijke melding terug aan de gebruiker via Telegram én HTTP.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Set
from urllib.parse import urlencode

import httpx

log = logging.getLogger("telegram")


@dataclass
class PendingLogin:
    """Gegevens voor een lopende Saxo-login via Telegram."""

    state: str
    chat_id: int
    created_at: float
    expires_at: float
    first_name: str = ""
    username: Optional[str] = None


class LoginError(RuntimeError):
    """Fout bij het opzetten of afronden van de login-flow."""


def _parse_chat_ids(raw: str) -> Set[int]:
    ids: Set[int] = set()
    if not raw:
        return ids
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            log.warning("TG_ALLOWED_CHAT_IDS: '%s' is geen geldig integer id", part)
    return ids


class TelegramLoginManager:
    """Beheert Telegram-commando's en Saxo OAuth state."""

    def __init__(self) -> None:
        self._states: Dict[str, PendingLogin] = {}
        self._lock = threading.Lock()
        self.reload()

    # ------------------------------------------------------------------
    # Config laden
    # ------------------------------------------------------------------
    def reload(self) -> None:
        self.enabled = os.getenv("TG_ENABLED", "false").lower() == "true"
        self.bot_token = os.getenv("TG_BOT_TOKEN", "").strip()
        self.api_base = (
            f"https://api.telegram.org/bot{self.bot_token}" if self.bot_token else ""
        )
        self.webhook_secret = os.getenv("TG_WEBHOOK_SECRET", "").strip()
        self.allowed_chat_ids: Set[int] = _parse_chat_ids(os.getenv("TG_ALLOWED_CHAT_IDS", ""))

        fallback_chat = os.getenv("TG_CHAT_ID", "").strip()
        if fallback_chat:
            try:
                self.allowed_chat_ids.add(int(fallback_chat))
            except ValueError:
                log.warning("TG_CHAT_ID is geen integer: %s", fallback_chat)

        try:
            self.state_ttl = int(os.getenv("SAXO_LOGIN_STATE_TTL", "600"))
        except ValueError:
            self.state_ttl = 600

        self.app_key = os.getenv("SAXO_APP_KEY", "").strip()
        self.app_secret = os.getenv("SAXO_APP_SECRET", "").strip()
        self.token_url = os.getenv("SAXO_TOKEN_URL", "https://sim.logonvalidation.net/token").strip()
        self.auth_url = os.getenv("SAXO_AUTH_URL", "https://sim.logonvalidation.net/authorize").strip()
        self.redirect_url = os.getenv("SAXO_REDIRECT_URL", "").strip()
        self.scope = os.getenv("SAXO_AUTH_SCOPE", "offline_access trading").strip()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def is_enabled(self) -> bool:
        return self.enabled and bool(self.bot_token)

    def is_chat_allowed(self, chat_id: int) -> bool:
        return not self.allowed_chat_ids or chat_id in self.allowed_chat_ids

    def _cleanup_locked(self, now: Optional[float] = None) -> None:
        now = now or time.time()
        expired = [
            state
            for state, info in self._states.items()
            if info.expires_at and info.expires_at < now
        ]
        for state in expired:
            self._states.pop(state, None)

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------
    def create_login_request(
        self, chat_id: int, *, first_name: str = "", username: Optional[str] = None
    ) -> PendingLogin:
        if not self.is_enabled():
            raise LoginError("Telegram bot niet geconfigureerd (TG_ENABLED/TG_BOT_TOKEN).")
        if not self.app_key:
            raise LoginError("SAXO_APP_KEY ontbreekt.")
        if not self.redirect_url:
            raise LoginError("SAXO_REDIRECT_URL ontbreekt.")

        now = time.time()
        state = secrets.token_urlsafe(32)
        ttl = max(60, int(self.state_ttl))
        pending = PendingLogin(
            state=state,
            chat_id=int(chat_id),
            created_at=now,
            expires_at=now + ttl,
            first_name=first_name or "",
            username=username,
        )
        with self._lock:
            self._cleanup_locked(now)
            self._states[state] = pending
        return pending

    def consume_state(self, state: str) -> Optional[PendingLogin]:
        if not state:
            return None
        with self._lock:
            info = self._states.pop(state, None)
        if not info:
            return None
        if info.expires_at and info.expires_at < time.time():
            return None
        return info

    # ------------------------------------------------------------------
    # Telegram en OAuth interacties
    # ------------------------------------------------------------------
    def build_authorize_url(self, pending: PendingLogin) -> str:
        params = {
            "response_type": "code",
            "client_id": self.app_key,
            "redirect_uri": self.redirect_url,
            "state": pending.state,
        }
        if self.scope:
            params["scope"] = self.scope
        return f"{self.auth_url}?{urlencode(params)}"

    def send_message(self, chat_id: int, text: str) -> None:
        if not self.is_enabled():
            return
        url = f"{self.api_base}/sendMessage"
        payload = {
            "chat_id": int(chat_id),
            "text": text,
            "disable_web_page_preview": True,
        }
        try:
            httpx.post(url, json=payload, timeout=10.0)
        except Exception as exc:  # pragma: no cover - logging
            log.warning("Telegram sendMessage failed: %s", exc)

    def exchange_code_for_tokens(self, code: str) -> dict:
        if not self.app_key or not self.app_secret:
            raise LoginError("SAXO_APP_KEY of SAXO_APP_SECRET ontbreekt.")
        if not self.redirect_url:
            raise LoginError("SAXO_REDIRECT_URL ontbreekt.")
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_url,
            "client_id": self.app_key,
            "client_secret": self.app_secret,
        }
        try:
            resp = httpx.post(self.token_url, data=data, timeout=20.0)
        except Exception as exc:  # pragma: no cover - netwerkfout
            raise LoginError(f"Verbinding met Saxo token endpoint faalde: {exc}") from exc

        if resp.status_code not in (200, 201):
            raise LoginError(
                f"Token endpoint gaf status {resp.status_code}: {resp.text[:400]}"
            )
        try:
            return resp.json()
        except Exception as exc:  # pragma: no cover - JSON fout
            raise LoginError(f"Kon token-response niet parsen: {resp.text[:400]}") from exc


# Singleton manager voor gebruik in de FastAPI-app
manager = TelegramLoginManager()

