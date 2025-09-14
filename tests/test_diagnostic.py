"""Tests for the Saxo diagnostic endpoint."""

import pytest
import json
import requests
import subprocess
import time
import signal
import os
from threading import Thread


class ServerHelper:
    """Test server context manager."""
    
    def __init__(self, port=8001):
        self.port = port
        self.process = None
        self.base_url = f"http://localhost:{port}"
    
    def __enter__(self):
        # Start uvicorn server
        env = os.environ.copy()
        env["SINGLE_API_KEY"] = "test123"
        
        self.process = subprocess.Popen([
            "uvicorn", "app.main:app", 
            "--host", "0.0.0.0", 
            "--port", str(self.port),
            "--log-level", "error"
        ], cwd="/home/runner/work/sniperbot/sniperbot", env=env)
        
        # Wait for server to start
        for _ in range(30):  # Wait up to 3 seconds
            try:
                response = requests.get(f"{self.base_url}/healthz", timeout=1)
                if response.status_code == 200:
                    break
            except:
                pass
            time.sleep(0.1)
        else:
            self.process.kill()
            raise RuntimeError("Server failed to start")
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
    
    def get(self, path, headers=None):
        return requests.get(f"{self.base_url}{path}", headers=headers, timeout=5)


def test_diagnostic_endpoint_requires_auth():
    """Test that diagnostic endpoint requires API key."""
    with ServerHelper() as server:
        response = server.get("/diag/saxo/assert")
        assert response.status_code == 200  # Should not crash
        data = response.json()
        assert data["ok"] is False
        assert "error" in data
        assert data["converged"] is False


def test_diagnostic_endpoint_with_auth():
    """Test diagnostic endpoint with valid API key."""
    with ServerHelper() as server:
        response = server.get("/diag/saxo/assert", headers={"X-API-Key": "test123"})
        assert response.status_code == 200
        data = response.json()
        
        # Basic structure validation
        assert "ok" in data
        assert "converged" in data
        assert "total_managers" in data
        assert "unique_instances" in data
        assert "active_token_managers" in data
        assert "managers" in data
        assert "convergence_details" in data
        assert "timestamp" in data
        assert "version" in data
        
        # Should always have at least saxo_auth manager
        assert data["total_managers"] >= 1
        assert isinstance(data["managers"], list)
        
        # Check manager structure
        if data["managers"]:
            mgr = data["managers"][0]
            required_fields = ["name", "type", "id", "has_token", "expires_at"]
            for field in required_fields:
                assert field in mgr


def test_diagnostic_convergence_details():
    """Test that convergence details are properly populated."""
    with ServerHelper() as server:
        response = server.get("/diag/saxo/assert", headers={"X-API-Key": "test123"})
        assert response.status_code == 200
        data = response.json()
        
        details = data["convergence_details"]
        required_flags = [
            "instance_convergence",
            "token_convergence", 
            "has_app_state_mgr",
            "has_global_tm",
            "has_saxo_auth",
            "has_accessor"
        ]
        
        for flag in required_flags:
            assert flag in details
            assert isinstance(details[flag], bool)
        
        # Should always have saxo_auth
        assert details["has_saxo_auth"] is True


def test_diagnostic_never_crashes():
    """Test that diagnostic endpoint never crashes even with errors."""
    with ServerHelper() as server:
        # Test with valid auth
        response = server.get("/diag/saxo/assert", headers={"X-API-Key": "test123"})
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        
        # Test without auth
        response = server.get("/diag/saxo/assert")
        assert response.status_code == 200  # Still returns 200, doesn't crash
        assert response.headers["content-type"].startswith("application/json")
        
        # Ensure response is valid JSON
        data = response.json()
        assert isinstance(data, dict)


def test_diagnostic_manager_identification():
    """Test that the endpoint correctly identifies different manager types."""
    with ServerHelper() as server:
        response = server.get("/diag/saxo/assert", headers={"X-API-Key": "test123"})
        assert response.status_code == 200
        data = response.json()
        
        # Should find at least saxo_auth
        manager_names = [mgr["name"] for mgr in data["managers"]]
        assert "saxo_auth" in manager_names
        
        # Check manager types
        manager_types = [mgr["type"] for mgr in data["managers"]]
        assert "SaxoAuthManager" in manager_types
        
        # Each manager should have unique ID
        manager_ids = [mgr["id"] for mgr in data["managers"]]
        assert len(manager_ids) == len(set(manager_ids))  # All IDs should be unique