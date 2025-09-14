#!/usr/bin/env python3
"""
Test script to verify the Saxo auth refactor works correctly.
Tests the new diagnostic endpoints and verifies existing functionality.
"""

import os
import sys
import asyncio
import tempfile
from pathlib import Path

# Add current directory to path
sys.path.append('.')

from app.main import app
from app.token_manager import SaxoTokenManager
from app.broker.saxo import SaxoClient

async def test_token_manager():
    """Test the TokenManager directly"""
    print("Testing TokenManager...")
    
    # Create a temporary token file
    with tempfile.TemporaryDirectory() as temp_dir:
        token_path = os.path.join(temp_dir, "test_tokens.json")
        
        # Mock credentials (these would normally come from env)
        fake_app_key = "test_app_key"
        fake_app_secret = "test_app_secret"
        fake_refresh_token = "test_refresh_token"
        
        # Create TokenManager instance
        tm = SaxoTokenManager(
            app_key=fake_app_key,
            app_secret=fake_app_secret,
            refresh_token=fake_refresh_token,
            token_url="https://sim.logonvalidation.net/token",
            strategy="disk",
            storage_path=token_path,
            auto_refresh=False,  # Don't auto-refresh in test
        )
        
        # Test status method
        status = tm.status()
        print(f"TokenManager status: {status}")
        
        assert status["strategy"] == "disk"
        assert status["has_refresh_token"] == True
        assert status["has_access_token"] == False  # No token initially
        assert status["storage_path"] == token_path
        
        print("✓ TokenManager basic functionality works")

def test_saxo_client():
    """Test SaxoClient with mock bearer provider"""
    print("Testing SaxoClient...")
    
    async def mock_bearer_provider():
        return "mock_bearer_token_12345"
    
    client = SaxoClient(get_bearer=mock_bearer_provider)
    
    # Test that the client is configured properly
    assert client.get_bearer is not None
    assert callable(client.get_bearer)
    
    # Test dry run mode (should not call bearer provider)
    assert client.enabled == False  # Default is dry run
    
    print("✓ SaxoClient basic functionality works")

async def test_app_startup():
    """Test that the app can start up without errors"""
    print("Testing app startup...")
    
    # The app uses lifespan context manager, but we can test basic structure
    assert app is not None
    assert app.title == "SNIPERBOT API"
    
    # Check that routes are registered
    routes = [route.path for route in app.routes if hasattr(route, 'path')]
    
    expected_routes = [
        "/healthz",
        "/saxo/token/status",
        "/saxo/token/refresh",
        "/oauth/saxo/status",  # legacy
        "/saxo/refresh",       # legacy
        "/decide",
        "/scan", 
        "/execute",
    ]
    
    for expected in expected_routes:
        assert expected in routes, f"Route {expected} not found in {routes}"
    
    print(f"✓ All expected routes registered: {len(expected_routes)} routes")

async def main():
    """Run all tests"""
    print("Starting Saxo auth refactor tests...\n")
    
    try:
        await test_token_manager()
        test_saxo_client()
        await test_app_startup()
        
        print("\n🎉 All tests passed!")
        return True
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)