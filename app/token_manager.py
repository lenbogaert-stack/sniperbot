# app/token_manager.py
from __future__ import annotations
import os, json, time, asyncio, contextlib, logging
from dataclasses import dataclass, asdict
from typing import Optional
import httpx

# Set up logging
log = logging.getLogger("sniperbot.token_manager")

@dataclass
class TokenBundle:
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[float] = None  # epoch seconds
    last_refresh_ts: Optional[float] = None

    @property
    def seconds_left(self) -> Optional[int]:
        return None if self.expires_at is None else int(self.expires_at - time.time())

class SaxoTokenManager:
    def __init__(
        self,
        app_key: str,
        app_secret: str,
        refresh_token: str,
        token_url: str = "https://sim.logonvalidation.net/token",
        strategy: str = "memory",             # "memory" | "disk" | "env_only"
        storage_path: str = "/var/data/saxo_tokens.json",
        auto_refresh: bool = True,
        safety_margin_sec: int = 90,          # ververs ~1.5 min voor expiry
    ):
        self.app_key = app_key
        self.app_secret = app_secret
        self.token_url = token_url
        self.strategy = strategy
        self.storage_path = storage_path
        self.auto_refresh = auto_refresh
        self.safety_margin_sec = safety_margin_sec
        self._lock = asyncio.Lock()
        self._bundle = TokenBundle(refresh_token=refresh_token)
        self._bg_task: Optional[asyncio.Task] = None
        # load from disk if any
        if self.strategy == "disk":
            self._load_from_disk_fallback_env()

    # ---------- persistence ----------
    def _load_from_disk_fallback_env(self):
        try:
            if os.path.exists(self.storage_path):
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._bundle = TokenBundle(**data)
                log.debug("Loaded tokens from disk: %s", self.storage_path)
                # env var kan een nieuwere refresh token bevatten → voorkeursvolgorde: disk, dan env
                if not self._bundle.refresh_token:
                    self._bundle.refresh_token = os.getenv("SAXO_REFRESH_TOKEN")
                    log.debug("Using refresh token from environment (disk had none)")
            else:
                # init met env
                rt = os.getenv("SAXO_REFRESH_TOKEN")
                if rt:
                    self._bundle.refresh_token = rt
                    log.debug("Initialized with refresh token from environment (no disk file)")
        except Exception as e:
            log.warning("Failed to load tokens from disk, falling back to env: %s", e)
            # val terug op env
            self._bundle.refresh_token = os.getenv("SAXO_REFRESH_TOKEN")

    def _save_to_disk(self):
        if self.strategy != "disk":
            return
        try:
            os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
            data = asdict(self._bundle)
            # log hygiene: geen token logging
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            log.debug("Saved tokens to disk: %s", self.storage_path)
        except Exception as e:
            log.error("Failed to save tokens to disk: %s", e)

    # ---------- core ----------
    async def _call_token(self, form: dict) -> dict:
        # Variant A: Basic auth
        basic = httpx.BasicAuth(self.app_key, self.app_secret)
        log.debug("Making token request to %s", self.token_url)
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.post(self.token_url, auth=basic, data=form)
            r.raise_for_status()
            response_data = r.json()
            log.debug("Token request successful, received keys: %s", list(response_data.keys()))
            return response_data

    async def refresh_access_token(self) -> TokenBundle:
        async with self._lock:
            if not self._bundle.refresh_token:
                raise RuntimeError("Geen refresh_token geconfigureerd.")
            
            old_refresh_token = self._bundle.refresh_token
            old_expires_in = self._bundle.seconds_left
            log.info("Starting token refresh - current expires_in_s: %s", old_expires_in)
            
            form = {
                "grant_type": "refresh_token",
                "refresh_token": self._bundle.refresh_token,
            }
            
            try:
                data = await self._call_token(form)
                at = data.get("access_token")
                rt = data.get("refresh_token") or self._bundle.refresh_token  # rotation: neem nieuwe als aanwezig
                expires_in = data.get("expires_in", 600)  # fallback 10 min
                
                if not at:
                    raise RuntimeError("No access_token in token response")
                
                now = time.time()
                self._bundle.access_token = at
                self._bundle.refresh_token = rt
                self._bundle.last_refresh_ts = now
                # ververs vóór einde (safety margin)
                self._bundle.expires_at = now + max(60, int(expires_in) - self.safety_margin_sec)
                
                # Check if refresh token was rotated
                token_rotated = rt != old_refresh_token
                log.info("Token refresh completed - new expires_in_s: %s, refresh_token_rotated: %s", 
                        self._bundle.seconds_left, token_rotated)
                
                if token_rotated:
                    log.debug("Refresh token was rotated (old != new)")
                else:
                    log.debug("Refresh token unchanged")
                
                self._save_to_disk()
                return self._bundle
                
            except Exception as e:
                log.error("Token refresh failed: %s", str(e))
                raise RuntimeError(f"Token refresh failed: {str(e)}") from e

    async def get_access_token(self) -> str:
        # lazy refresh indien nodig
        needs_refresh = (
            self._bundle.access_token is None or 
            self._bundle.expires_at is None or 
            (self._bundle.seconds_left is not None and self._bundle.seconds_left < 30)
        )
        
        if needs_refresh:
            log.debug("Access token needs refresh - current expires_in_s: %s", self._bundle.seconds_left)
            await self.refresh_access_token()
        
        return self._bundle.access_token  # type: ignore

    # ---------- background loop ----------
    async def _loop(self):
        # periodiek verfrissen
        log.debug("Token manager background loop started")
        while self.auto_refresh:
            try:
                # zorg dat er een token is
                await self.get_access_token()
                # slaap tot kort voor expiry
                sleep_s = max(30, (self._bundle.seconds_left or 120) - 60)  # wake up 60s before expiry
                log.debug("Token manager sleeping for %ds (expires in %ds)", sleep_s, self._bundle.seconds_left)
                await asyncio.sleep(sleep_s)
            except Exception as e:
                log.error("Error in token manager background loop: %s", e)
                # soft backoff bij fouten
                await asyncio.sleep(30)

    def start(self):
        if self.auto_refresh and self._bg_task is None:
            self._bg_task = asyncio.create_task(self._loop())

    # ---------- debug/status ----------
    def status(self) -> dict:
        return {
            "strategy": self.strategy,
            "has_refresh_token": bool(self._bundle.refresh_token),
            "has_access_token": bool(self._bundle.access_token),
            "expires_in_s": self._bundle.seconds_left,
            "last_refresh_ts": self._bundle.last_refresh_ts,
            "storage_path": self.storage_path if self.strategy == "disk" else None,
        }
