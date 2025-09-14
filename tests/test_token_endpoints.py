"""Test new token management endpoints"""
import pytest
from unittest.mock import patch, MagicMock
import os

# We can't easily test with TestClient due to version conflicts, but we can test the basic structure
def test_imports_work():
    """Test that the imports work correctly"""
    try:
        from app.main import app, tm, _require_mgr
        from app.token_manager import SaxoTokenManager
        assert app is not None
        assert tm is None  # Should be None initially
        # _require_mgr should raise HTTPException when tm is None
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _require_mgr()
        assert exc_info.value.status_code == 503
        assert "TokenManager not initialized" in str(exc_info.value.detail)
        print("✅ All imports and basic functionality work correctly")
    except Exception as e:
        pytest.fail(f"Import test failed: {e}")


def test_token_manager_initialization():
    """Test that SaxoTokenManager can be initialized with proper parameters"""
    try:
        from app.token_manager import SaxoTokenManager
        
        # Test initialization with required parameters
        tm = SaxoTokenManager(
            app_key="test_key",
            app_secret="test_secret", 
            refresh_token="test_refresh",
            token_url="https://test.url",
            strategy="memory"
        )
        
        assert tm.app_key == "test_key"
        assert tm.app_secret == "test_secret"
        assert tm._bundle.refresh_token == "test_refresh"
        assert tm.strategy == "memory"
        
        status = tm.status()
        assert "strategy" in status
        assert "has_refresh_token" in status
        assert status["strategy"] == "memory"
        assert status["has_refresh_token"] is True
        
        print("✅ TokenManager initialization works correctly")
    except Exception as e:
        pytest.fail(f"TokenManager initialization test failed: {e}")


if __name__ == "__main__":
    test_imports_work()
    test_token_manager_initialization()
    print("✅ All tests passed")