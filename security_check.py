"""
Simple Security Testing for Students
Easy to understand security checks
"""

import subprocess
import sys
import requests
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_password_security():
    """Test password security features"""
    print("🔐 Testing Password Security...")
    
    # Test 1: Short password rejection
    short_password_user = {
        "email": "test@example.com",
        "password": "123",  # Too short
        "full_name": "Test User"
    }
    
    response = client.post("/register", json=short_password_user)
    if response.status_code == 400:
        print("   ✅ Short passwords are rejected")
    else:
        print("   ❌ Short passwords are accepted (security risk!)")
    
    # Test 2: Password hashing (passwords are not stored in plain text)
    valid_user = {
        "email": "secure@example.com",
        "password": "securepassword123",
        "full_name": "Secure User"
    }
    
    client.post("/register", json=valid_user)
    
    # Check if password is hashed in storage
    from main import users_db
    if valid_user["email"] in users_db:
        stored_password = users_db[valid_user["email"]]["password_hash"]
        if stored_password != valid_user["password"]:
            print("   ✅ Passwords are hashed (not stored in plain text)")
        else:
            print("   ❌ Passwords are stored in plain text (security risk!)")

def test_authentication_security():
    """Test JWT authentication security"""
    print("\n🔑 Testing Authentication Security...")
    
    # Test 1: Access protected endpoint without token
    response = client.get("/profile")
    if response.status_code == 403:
        print("   ✅ Protected endpoints require authentication")
    else:
        print("   ❌ Protected endpoints accessible without authentication")
    
    # Test 2: Invalid token rejection
    headers = {"Authorization": "Bearer fake_invalid_token"}
    response = client.get("/profile", headers=headers)
    if response.status_code == 401:
        print("   ✅ Invalid tokens are rejected")
    else:
        print("   ❌ Invalid tokens are accepted (security risk!)")
    
    # Test 3: Valid token works
    # Register and login user
    test_user = {
        "email": "auth_test@example.com",
        "password": "password123",
        "full_name": "Auth Test"
    }
    
    client.post("/register", json=test_user)
    login_response = client.post("/login", json={
        "email": test_user["email"],
        "password": test_user["password"]
    })
    
    if login_response.status_code == 200:
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("/profile", headers=headers)
        
        if response.status_code == 200:
            print("   ✅ Valid tokens work correctly")
        else:
            print("   ❌ Valid tokens don't work")

def test_input_validation():
    """Test input validation security"""
    print("\n✅ Testing Input Validation...")
    
    # Test 1: Invalid email format
    invalid_email_user = {
        "email": "not_an_email",
        "password": "password123",
        "full_name": "Test User"
    }
    
    response = client.post("/register", json=invalid_email_user)
    if response.status_code == 422:  # Validation error
        print("   ✅ Invalid email formats are rejected")
    else:
        print("   ❌ Invalid email formats are accepted")
    
    # Test 2: Rating validation
    # First register and login a user
    test_user = {
        "email": "rating_test@example.com",
        "password": "password123",
        "full_name": "Rating Test"
    }
    
    client.post("/register", json=test_user)
    login_response = client.post("/login", json={
        "email": test_user["email"],
        "password": test_user["password"]
    })
    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test invalid rating (too high)
    response = client.post("/movies/1/rate", json={"rating": 10}, headers=headers)
    if response.status_code == 400:
        print("   ✅ Invalid rating values are rejected")
    else:
        print("   ❌ Invalid rating values are accepted")

def run_bandit_scan():
    """Run bandit security scan if available"""
    print("\n🔍 Running Bandit Security Scan...")
    
    try:
        result = subprocess.run(
            ["bandit", "-r", ".", "-f", "txt"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("   ✅ No security issues found by Bandit")
        else:
            print("   ⚠️ Bandit found potential security issues:")
            print(result.stdout)
            
    except FileNotFoundError:
        print("   ℹ️ Bandit not installed. Install with: pip install bandit")
    except subprocess.TimeoutExpired:
        print("   ⚠️ Bandit scan timed out")
    except Exception as e:
        print(f"   ❌ Error running Bandit: {e}")

def run_safety_scan():
    """Run safety vulnerability scan if available"""
    print("\n🛡️ Running Safety Vulnerability Scan...")
    
    try:
        result = subprocess.run(
            ["safety", "check"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            print("   ✅ No known vulnerabilities found in dependencies")
        else:
            print("   ⚠️ Safety found vulnerabilities:")
            print(result.stdout)
            
    except FileNotFoundError:
        print("   ℹ️ Safety not installed. Install with: pip install safety")
    except subprocess.TimeoutExpired:
        print("   ⚠️ Safety scan timed out")
    except Exception as e:
        print(f"   ❌ Error running Safety: {e}")

def main():
    """Run all security tests"""
    print("🔒 Simple Security Testing for Movie Rating API")
    print("=" * 50)
    
    # Run custom security tests
    test_password_security()
    test_authentication_security()
    test_input_validation()
    
    # Run external security tools
    run_bandit_scan()
    run_safety_scan()
    
    print("\n" + "=" * 50)
    print("🎓 Security Testing Complete!")
    print("\nWhat we tested:")
    print("• Password security (hashing, length requirements)")
    print("• Authentication (JWT tokens, protected endpoints)")
    print("• Input validation (email format, rating values)")
    print("• Static code analysis (Bandit)")
    print("• Dependency vulnerabilities (Safety)")
    
    print("\n💡 Security Best Practices Demonstrated:")
    print("• Never store passwords in plain text")
    print("• Always validate user input")
    print("• Protect sensitive endpoints with authentication")
    print("• Use strong, unique secret keys in production")
    print("• Regularly scan for vulnerabilities")

if __name__ == "__main__":
    main()