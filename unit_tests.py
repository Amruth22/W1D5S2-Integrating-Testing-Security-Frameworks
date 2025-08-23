"""
Simple Unit Tests for Movie Rating API
Tests API endpoints through HTTP requests to live server - perfect for students to learn API testing
"""

import pytest
import requests
import time
import json
from datetime import datetime, timedelta
from jose import jwt

# Configuration for live server testing
BASE_URL = "http://localhost:8000"
TIMEOUT = 30  # seconds

def check_server_running():
    """Check if the server is running"""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        return response.status_code == 200
    except:
        return False

def get_unique_email(prefix="test"):
    """Generate unique email for testing"""
    timestamp = int(time.time() * 1000)  # milliseconds for uniqueness
    return f"{prefix}_{timestamp}@example.com"

class TestPasswordFunctions:
    """Test password security through API endpoints"""
    
    def test_password_length_validation(self):
        """Test password length validation through registration"""
        # Test short password rejection
        short_password_user = {
            "email": get_unique_email("shortpass"),
            "password": "123",  # Too short
            "full_name": "Short Pass User"
        }
        
        response = requests.post(f"{BASE_URL}/register", json=short_password_user, timeout=TIMEOUT)
        assert response.status_code == 400
        assert "at least 6 characters" in response.json()["detail"]
        
        # Test passed - tracked by run_test function
    

    
    def test_password_verification(self):
        """Test password verification through login"""
        # Register user
        test_user = {
            "email": get_unique_email("verify"),
            "password": "correctpassword",
            "full_name": "Verify User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        
        # Test correct password
        correct_login = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": "correctpassword"
        }, timeout=TIMEOUT)
        assert correct_login.status_code == 200
        
        # Test incorrect password
        wrong_login = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": "wrongpassword"
        }, timeout=TIMEOUT)
        assert wrong_login.status_code == 401
        assert "Invalid email or password" in wrong_login.json()["detail"]
        
        # Test passed - tracked by run_test function
    


class TestJWTFunctions:
    """Test JWT token functionality through API endpoints"""
    
    def test_token_creation_via_login(self):
        """Test JWT token creation through login endpoint"""
        # Register user first
        test_user = {
            "email": get_unique_email("tokentest"),
            "password": "password123",
            "full_name": "Token Test User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        
        # Login to get token
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        
        assert login_response.status_code == 200
        token_data = login_response.json()
        
        # Check token structure
        assert "access_token" in token_data
        assert "token_type" in token_data
        assert token_data["token_type"] == "bearer"
        
        token = token_data["access_token"]
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT has 3 parts
        
        # Test passed - tracked by run_test function
    
    def test_token_authentication(self):
        """Test token authentication on protected endpoints"""
        # Register and login user
        test_user = {
            "email": get_unique_email("authtest"),
            "password": "password123",
            "full_name": "Auth Test User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test protected endpoint with valid token
        profile_response = requests.get(f"{BASE_URL}/profile", headers=headers, timeout=TIMEOUT)
        assert profile_response.status_code == 200
        
        profile_data = profile_response.json()
        assert profile_data["user"]["email"] == test_user["email"]
        
        # Test passed - tracked by run_test function
    
    def test_invalid_token_rejection(self):
        """Test that invalid tokens are rejected"""
        # Test with completely invalid token
        invalid_headers = {"Authorization": "Bearer invalid_token_here"}
        response = requests.get(f"{BASE_URL}/profile", headers=invalid_headers, timeout=TIMEOUT)
        
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]
        
        # Test passed - tracked by run_test function
    


class TestDataValidation:
    """Test data validation through API endpoints"""
    
    def test_rating_validation_valid(self):
        """Test valid rating values through API"""
        # Register and login user
        test_user = {
            "email": get_unique_email("validrating"),
            "password": "password123",
            "full_name": "Valid Rating User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test valid ratings (1-5)
        valid_ratings = [1, 2, 3, 4, 5]
        
        for rating in valid_ratings:
            response = requests.post(f"{BASE_URL}/movies/1/rate", 
                                   json={"rating": rating}, 
                                   headers=headers, 
                                   timeout=TIMEOUT)
            assert response.status_code == 200
            assert response.json()["rating"] == rating
        
        # Test passed - tracked by run_test function
    
    def test_rating_validation_invalid(self):
        """Test invalid rating values through API"""
        # Register and login user
        test_user = {
            "email": get_unique_email("invalidrating"),
            "password": "password123",
            "full_name": "Invalid Rating User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test invalid ratings
        invalid_ratings = [0, 6, -1, 10, 100]
        
        for rating in invalid_ratings:
            response = requests.post(f"{BASE_URL}/movies/1/rate", 
                                   json={"rating": rating}, 
                                   headers=headers, 
                                   timeout=TIMEOUT)
            assert response.status_code == 400
            assert "between 1 and 5" in response.json()["detail"]
        
        # Test passed - tracked by run_test function
    

    


class TestBusinessLogic:
    """Test business logic through API endpoints"""
    
    def test_user_rating_history(self):
        """Test user rating history through profile"""
        # Register user
        test_user = {
            "email": get_unique_email("history"),
            "password": "password123",
            "full_name": "History User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Rate multiple movies
        movie_ratings = [(1, 5), (2, 4), (3, 3)]
        
        for movie_id, rating in movie_ratings:
            requests.post(f"{BASE_URL}/movies/{movie_id}/rate", 
                         json={"rating": rating}, 
                         headers=headers, 
                         timeout=TIMEOUT)
        
        # Check profile shows all ratings
        profile_response = requests.get(f"{BASE_URL}/profile", headers=headers, timeout=TIMEOUT)
        profile_data = profile_response.json()
        
        assert profile_data["total_ratings"] == len(movie_ratings)
        assert len(profile_data["ratings"]) == len(movie_ratings)
        
        # Verify specific ratings
        user_ratings = {r["movie_id"]: r["rating"] for r in profile_data["ratings"]}
        for movie_id, expected_rating in movie_ratings:
            assert user_ratings[movie_id] == expected_rating
        
        # Test passed - tracked by run_test function
    
    def test_movie_without_ratings(self):
        """Test movie display when no ratings exist"""
        # Get a movie that likely has no ratings (or create scenario)
        movie_response = requests.get(f"{BASE_URL}/movies/3", timeout=TIMEOUT)
        movie_data = movie_response.json()
        
        # Movie should exist but might have no ratings
        assert "average_rating" in movie_data
        assert "total_ratings" in movie_data
        
        # If no ratings, average should be None and total should be 0 or more
        if movie_data["total_ratings"] == 0:
            assert movie_data["average_rating"] is None
        
        # Test passed - tracked by run_test function

class TestAPIResponseStructures:
    """Test API response structures"""
    
    def test_user_registration_response(self):
        """Test user registration response structure"""
        test_user = {
            "email": get_unique_email("structure"),
            "password": "password123",
            "full_name": "Structure Test User"
        }
        
        response = requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        assert response.status_code == 200
        
        response_data = response.json()
        assert "message" in response_data
        assert "email" in response_data
        assert response_data["email"] == test_user["email"]
        
        # Test passed - tracked by run_test function
    
    def test_movie_response_structure(self):
        """Test movie response structure"""
        response = requests.get(f"{BASE_URL}/movies/1", timeout=TIMEOUT)
        assert response.status_code == 200
        
        movie_data = response.json()
        required_fields = ["id", "title", "genre", "year", "average_rating", "total_ratings"]
        
        for field in required_fields:
            assert field in movie_data
        
        assert isinstance(movie_data["id"], int)
        assert isinstance(movie_data["year"], int)
        assert isinstance(movie_data["total_ratings"], int)
        
        # Test passed - tracked by run_test function
    
    def test_profile_response_structure(self):
        """Test profile response structure"""
        # Register and login user
        test_user = {
            "email": get_unique_email("profile"),
            "password": "password123",
            "full_name": "Profile User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get profile
        profile_response = requests.get(f"{BASE_URL}/profile", headers=headers, timeout=TIMEOUT)
        assert profile_response.status_code == 200
        
        profile_data = profile_response.json()
        assert "user" in profile_data
        assert "ratings" in profile_data
        assert "total_ratings" in profile_data
        
        # Check user structure
        user_data = profile_data["user"]
        assert "id" in user_data
        assert "email" in user_data
        assert "full_name" in user_data
        
        # Test passed - tracked by run_test function

class TestAPIIntegration:
    """Test API integration scenarios"""
    
    def test_complete_user_workflow(self):
        """Test complete user workflow from registration to rating"""
        # Step 1: Register user
        test_user = {
            "email": get_unique_email("workflow"),
            "password": "password123",
            "full_name": "Workflow User"
        }
        
        register_response = requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        assert register_response.status_code == 200
        
        # Step 2: Login user
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        assert login_response.status_code == 200
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Step 3: Rate a movie
        rating_response = requests.post(f"{BASE_URL}/movies/1/rate", 
                                      json={"rating": 5}, 
                                      headers=headers, 
                                      timeout=TIMEOUT)
        assert rating_response.status_code == 200
        
        # Step 4: Check profile shows rating
        profile_response = requests.get(f"{BASE_URL}/profile", headers=headers, timeout=TIMEOUT)
        assert profile_response.status_code == 200
        
        profile_data = profile_response.json()
        assert profile_data["total_ratings"] >= 1
        
        # Test passed - tracked by run_test function
    
    def test_concurrent_ratings(self):
        """Test multiple users rating the same movie"""
        movie_id = 2
        users_and_ratings = []
        
        # Create multiple users and have them rate the same movie
        for i in range(3):
            user = {
                "email": get_unique_email(f"concurrent{i}"),
                "password": "password123",
                "full_name": f"Concurrent User {i}"
            }
            
            # Register and login
            requests.post(f"{BASE_URL}/register", json=user, timeout=TIMEOUT)
            login_response = requests.post(f"{BASE_URL}/login", json={
                "email": user["email"],
                "password": user["password"]
            }, timeout=TIMEOUT)
            
            token = login_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            
            # Rate movie
            rating = i + 3  # Ratings: 3, 4, 5
            rating_response = requests.post(f"{BASE_URL}/movies/{movie_id}/rate", 
                                          json={"rating": rating}, 
                                          headers=headers, 
                                          timeout=TIMEOUT)
            assert rating_response.status_code == 200
            
            users_and_ratings.append((user, rating))
        
        # Check that movie now has multiple ratings
        movie_response = requests.get(f"{BASE_URL}/movies/{movie_id}", timeout=TIMEOUT)
        movie_data = movie_response.json()
        
        assert movie_data["total_ratings"] >= 3
        assert movie_data["average_rating"] is not None
        
        # Test passed - tracked by run_test function

class TestErrorHandling:
    """Test error handling through API endpoints"""
    
    def test_invalid_endpoints(self):
        """Test invalid API endpoints return proper errors"""
        # Test non-existent endpoint
        response = requests.get(f"{BASE_URL}/nonexistent", timeout=TIMEOUT)
        assert response.status_code == 404
        
        # Test passed - tracked by run_test function
    
    def test_malformed_requests(self):
        """Test malformed request handling"""
        # Test registration with missing fields
        incomplete_user = {
            "email": get_unique_email("incomplete"),
            # Missing password and full_name
        }
        
        response = requests.post(f"{BASE_URL}/register", json=incomplete_user, timeout=TIMEOUT)
        assert response.status_code == 422  # Validation error
        
        # Test passed - tracked by run_test function
    
    def test_unauthorized_access_patterns(self):
        """Test various unauthorized access patterns"""
        # Test accessing protected endpoint with malformed token
        malformed_headers = {"Authorization": "Bearer malformed_token"}
        response = requests.get(f"{BASE_URL}/profile", headers=malformed_headers, timeout=TIMEOUT)
        assert response.status_code == 401
        
        # Test with wrong authorization format
        wrong_format_headers = {"Authorization": "Basic wrong_format"}
        response = requests.get(f"{BASE_URL}/profile", headers=wrong_format_headers, timeout=TIMEOUT)
        assert response.status_code == 403
        
        # Test passed - tracked by run_test function
    
    def test_edge_case_inputs(self):
        """Test edge case inputs through API"""
        # Register user for testing
        test_user = {
            "email": get_unique_email("edgecase"),
            "password": "password123",
            "full_name": "Edge Case User"
        }
        
        requests.post(f"{BASE_URL}/register", json=test_user, timeout=TIMEOUT)
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": test_user["email"],
            "password": test_user["password"]
        }, timeout=TIMEOUT)
        
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test rating with string instead of integer
        response = requests.post(f"{BASE_URL}/movies/1/rate", 
                               json={"rating": "five"}, 
                               headers=headers, 
                               timeout=TIMEOUT)
        assert response.status_code == 422  # Validation error
        
        # Test passed - tracked by run_test function

# Test result tracking
test_results = {"passed": 0, "failed": 0, "total": 0}

def run_test(test_func, test_name):
    """Run a single test and track results"""
    global test_results
    test_results["total"] += 1
    
    try:
        test_func()
        test_results["passed"] += 1
        print(f"  ✅ {test_name} - PASSED")
        return True
    except Exception as e:
        test_results["failed"] += 1
        print(f"  ❌ {test_name} - FAILED: {str(e)}")
        return False

# Simple test runner for API tests
def run_api_tests():
    """Run API tests against live server"""
    global test_results
    test_results = {"passed": 0, "failed": 0, "total": 0}
    
    print("🧪 Running API Tests (Live Server)")
    print("=" * 50)
    
    # Check if server is running
    if not check_server_running():
        print("❌ ERROR: Server is not running!")
        print("")
        print("Please start the server first:")
        print("  1. Open a terminal and run: python main.py")
        print("  2. Wait for the server to start")
        print("  3. Then run these tests in another terminal")
        print("")
        return False
    
    print(f"✅ Server is running at {BASE_URL}")
    print("")
    
    # Core 10 Essential Tests
    print("\n🎯 Running Core 10 Essential API Tests:")
    
    # 1. Password Security
    test_pwd = TestPasswordFunctions()
    run_test(test_pwd.test_password_length_validation, "1. Password Length Validation")
    run_test(test_pwd.test_password_verification, "2. Password Verification")
    
    # 2. JWT Authentication
    test_jwt = TestJWTFunctions()
    run_test(test_jwt.test_token_creation_via_login, "3. JWT Token Creation")
    run_test(test_jwt.test_token_authentication, "4. JWT Token Authentication")
    run_test(test_jwt.test_invalid_token_rejection, "5. Invalid Token Rejection")
    
    # 3. Data Validation
    test_validation = TestDataValidation()
    run_test(test_validation.test_rating_validation_valid, "6. Valid Rating Validation")
    run_test(test_validation.test_rating_validation_invalid, "7. Invalid Rating Validation")
    
    # 4. Core Business Logic
    test_logic = TestBusinessLogic()
    run_test(test_logic.test_user_rating_history, "8. User Rating History")
    
    # 5. Integration & Error Handling
    test_integration = TestAPIIntegration()
    run_test(test_integration.test_complete_user_workflow, "9. Complete User Workflow")
    
    test_errors = TestErrorHandling()
    run_test(test_errors.test_unauthorized_access_patterns, "10. Unauthorized Access Protection")
    
    print("\n" + "=" * 50)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 50)
    print(f"🎯 Total Tests: {test_results['total']}")
    print(f"✅ Passed: {test_results['passed']}")
    print(f"❌ Failed: {test_results['failed']}")
    
    if test_results['failed'] == 0:
        print(f"\n🎉 ALL TESTS PASSED! ({test_results['passed']}/{test_results['total']})")
        success_rate = 100.0
    else:
        success_rate = (test_results['passed'] / test_results['total']) * 100
        print(f"\n⚠️  SOME TESTS FAILED ({test_results['passed']}/{test_results['total']})")
    
    print(f"📊 Success Rate: {success_rate:.1f}%")
    
    print("\n" + "=" * 50)
    print("📚 What We Tested via Live API:")
    print("• Password security through registration/login")
    print("• JWT token creation and validation")
    print("• Data validation through API endpoints")
    print("• Business logic through API responses")
    print("• API response structures")
    print("• Complete user workflows")
    print("• Error handling and edge cases")
    
    print("\n💡 Why These 10 Tests Matter:")
    print("• Cover all critical security features")
    print("• Test authentication and authorization")
    print("• Validate core business logic")
    print("• Test complete user workflows")
    print("• Fast execution with comprehensive coverage")
    
    return test_results['failed'] == 0

if __name__ == "__main__":
    # Run API tests against live server
    success = run_api_tests()
    
    print("\n" + "=" * 50)
    if success:
        print("🎆 ALL TESTS SUCCESSFUL!")
        print("🔄 You can also run with pytest: pytest unit_tests.py -v")
    else:
        print("⚠️  SOME TESTS FAILED!")
        print("🔧 Check the error messages above for details")
        print("🔄 You can also run with pytest for more details: pytest unit_tests.py -v")
    print("=" * 50)
    
    exit(0 if success else 1)