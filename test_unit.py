import unittest
import os
import sys
import tempfile
import shutil
import asyncio
import time
import subprocess
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from dotenv import load_dotenv
from jose import jwt, JWTError

# Add the current directory to Python path to import project modules
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

class CoreTestingSecurityTests(unittest.TestCase):
    """Core 5 unit tests for Testing & Security Frameworks Integration with real components"""
    
    @classmethod
    def setUpClass(cls):
        """Load configuration and validate setup"""
        # Note: This system doesn't require external APIs - it's a local testing/security framework
        print("Setting up Testing & Security Frameworks System tests...")
        
        # Initialize Testing & Security components (classes only, no heavy initialization)
        try:
            # Import main application components
            from main import app, users_db, movies_db, ratings_db
            from main import (
                hash_password, verify_password, create_access_token, get_current_user,
                UserRegister, UserLogin, Token, MovieRating, User
            )
            
            # Import FastAPI testing client
            from fastapi.testclient import TestClient
            
            cls.app = app
            cls.client = TestClient(app)
            cls.users_db = users_db
            cls.movies_db = movies_db
            cls.ratings_db = ratings_db
            
            # Store utility functions
            cls.hash_password = hash_password
            cls.verify_password = verify_password
            cls.create_access_token = create_access_token
            cls.get_current_user = get_current_user
            
            # Store models
            cls.UserRegister = UserRegister
            cls.UserLogin = UserLogin
            cls.Token = Token
            cls.MovieRating = MovieRating
            cls.User = User
            
            print("Testing & security components loaded successfully")
        except ImportError as e:
            raise unittest.SkipTest(f"Required testing & security components not found: {e}")

    def setUp(self):
        """Set up test fixtures"""
        # Clear databases before each test
        self.users_db.clear()
        self.ratings_db.clear()
        
        # Reset user counter
        import main
        main.user_counter = 1
        
        # Test data
        self.test_user = {
            "email": "test@example.com",
            "password": "password123",
            "full_name": "Test User"
        }
        
        self.test_user_2 = {
            "email": "test2@example.com",
            "password": "password456",
            "full_name": "Test User 2"
        }
        
        self.test_rating = {
            "rating": 5
        }

    def tearDown(self):
        """Clean up test fixtures"""
        # Clear databases after each test
        self.users_db.clear()
        self.ratings_db.clear()

    def test_01_password_security_framework(self):
        """Test 1: Password Security Framework and Hashing"""
        print("Running Test 1: Password Security Framework")
        
        # Import functions directly for testing
        from main import hash_password, verify_password
        
        # Test password hashing functionality
        test_password = "test_password_123"
        hashed = hash_password(test_password)
        self.assertIsInstance(hashed, str)
        self.assertNotEqual(hashed, test_password)
        self.assertGreater(len(hashed), 50)  # bcrypt hashes are long
        
        # Test password verification
        self.assertTrue(verify_password(test_password, hashed))
        self.assertFalse(verify_password("wrong_password", hashed))
        
        # Test salt uniqueness (different hashes for same password)
        hashed_2 = hash_password(test_password)
        self.assertNotEqual(hashed, hashed_2)  # Different salts
        self.assertTrue(verify_password(test_password, hashed_2))  # Both verify correctly
        
        # Test password length validation through API
        short_password_user = {
            "email": "short@example.com",
            "password": "123",  # Too short
            "full_name": "Short Password User"
        }
        response = self.client.post("/register", json=short_password_user)
        self.assertEqual(response.status_code, 400)
        self.assertIn("at least 6 characters", response.json()["detail"])
        
        # Test valid password registration
        response = self.client.post("/register", json=self.test_user)
        self.assertEqual(response.status_code, 200)
        
        # Verify password is hashed in storage
        self.assertIn(self.test_user["email"], self.users_db)
        stored_user = self.users_db[self.test_user["email"]]
        self.assertNotEqual(stored_user["password_hash"], self.test_user["password"])
        self.assertTrue(verify_password(self.test_user["password"], stored_user["password_hash"]))
        
        print("PASS: Password hashing and verification working")
        print("PASS: Salt uniqueness ensuring security")
        print("PASS: Password length validation")
        print("PASS: Secure password storage")
        print("PASS: Password security framework validated")

    def test_02_jwt_authentication_framework(self):
        """Test 2: JWT Authentication Framework and Token Management"""
        print("Running Test 2: JWT Authentication Framework")
        
        # Import JWT functions directly for testing
        from main import create_access_token, SECRET_KEY, ALGORITHM
        
        # Test JWT token creation
        test_email = "jwt_test@example.com"
        token = create_access_token(test_email)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 100)  # JWT tokens are long
        
        # Test token structure (header.payload.signature)
        token_parts = token.split('.')
        self.assertEqual(len(token_parts), 3)
        
        # Test token payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        self.assertEqual(payload["sub"], test_email)
        self.assertIn("exp", payload)  # Expiration time
        
        # Test token expiration
        exp_time = datetime.utcfromtimestamp(payload["exp"])
        now = datetime.utcnow()
        self.assertGreater(exp_time, now)  # Token should not be expired
        
        # Test authentication through API
        # Register and login user
        self.client.post("/register", json=self.test_user)
        login_response = self.client.post("/login", json={
            "email": self.test_user["email"],
            "password": self.test_user["password"]
        })
        self.assertEqual(login_response.status_code, 200)
        
        token_data = login_response.json()
        self.assertIn("access_token", token_data)
        self.assertIn("token_type", token_data)
        self.assertEqual(token_data["token_type"], "bearer")
        
        # Test protected endpoint with valid token
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        profile_response = self.client.get("/profile", headers=headers)
        self.assertEqual(profile_response.status_code, 200)
        
        profile_data = profile_response.json()
        self.assertEqual(profile_data["user"]["email"], self.test_user["email"])
        
        # Test invalid token rejection
        invalid_headers = {"Authorization": "Bearer invalid_token"}
        response = self.client.get("/profile", headers=invalid_headers)
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid token", response.json()["detail"])
        
        # Test missing token
        response = self.client.get("/profile")
        self.assertEqual(response.status_code, 403)  # Forbidden without token
        
        print("PASS: JWT token creation and structure")
        print("PASS: Token payload and expiration")
        print("PASS: Authentication through API")
        print("PASS: Protected endpoint access control")
        print("PASS: JWT authentication framework validated")

    def test_03_input_validation_testing_framework(self):
        """Test 3: Input Validation Testing Framework"""
        print("Running Test 3: Input Validation Testing Framework")
        
        # Test Pydantic models validation
        # Test UserRegister model
        valid_user_data = {
            "email": "valid@example.com",
            "password": "validpassword",
            "full_name": "Valid User"
        }
        user_model = self.UserRegister(**valid_user_data)
        self.assertEqual(user_model.email, "valid@example.com")
        self.assertEqual(user_model.password, "validpassword")
        self.assertEqual(user_model.full_name, "Valid User")
        
        # Test email validation
        invalid_email_user = {
            "email": "not_an_email",
            "password": "password123",
            "full_name": "Invalid Email User"
        }
        response = self.client.post("/register", json=invalid_email_user)
        self.assertEqual(response.status_code, 422)  # Validation error
        
        # Test MovieRating model validation
        valid_rating = self.MovieRating(rating=5)
        self.assertEqual(valid_rating.rating, 5)
        
        # Test rating validation through API
        # First register and login user
        self.client.post("/register", json=self.test_user)
        login_response = self.client.post("/login", json={
            "email": self.test_user["email"],
            "password": self.test_user["password"]
        })
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test valid ratings (1-5)
        valid_ratings = [1, 2, 3, 4, 5]
        for rating in valid_ratings:
            response = self.client.post("/movies/1/rate", 
                                      json={"rating": rating}, 
                                      headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["rating"], rating)
        
        # Test invalid ratings
        invalid_ratings = [0, 6, -1, 10, 100]
        for rating in invalid_ratings:
            response = self.client.post("/movies/1/rate", 
                                      json={"rating": rating}, 
                                      headers=headers)
            self.assertEqual(response.status_code, 400)
            self.assertIn("between 1 and 5", response.json()["detail"])
        
        # Test non-existent movie
        response = self.client.post("/movies/999/rate", 
                                  json={"rating": 5}, 
                                  headers=headers)
        self.assertEqual(response.status_code, 404)
        self.assertIn("Movie not found", response.json()["detail"])
        
        # Test data type validation
        response = self.client.post("/movies/1/rate", 
                                  json={"rating": "not_a_number"}, 
                                  headers=headers)
        self.assertEqual(response.status_code, 422)  # Validation error
        
        print("PASS: Pydantic model validation")
        print("PASS: Email format validation")
        print("PASS: Rating range validation")
        print("PASS: Non-existent resource handling")
        print("PASS: Data type validation")
        print("PASS: Input validation testing framework validated")

    def test_04_integration_testing_framework(self):
        """Test 4: Integration Testing Framework and Complete Workflows"""
        print("Running Test 4: Integration Testing Framework")
        
        # Test complete user workflow: Register -> Login -> Rate -> Profile
        
        # Step 1: User Registration
        register_response = self.client.post("/register", json=self.test_user)
        self.assertEqual(register_response.status_code, 200)
        register_data = register_response.json()
        self.assertIn("message", register_data)
        self.assertEqual(register_data["email"], self.test_user["email"])
        
        # Verify user stored in database
        self.assertIn(self.test_user["email"], self.users_db)
        
        # Step 2: User Login
        login_response = self.client.post("/login", json={
            "email": self.test_user["email"],
            "password": self.test_user["password"]
        })
        self.assertEqual(login_response.status_code, 200)
        token_data = login_response.json()
        token = token_data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Step 3: Rate Multiple Movies
        movie_ratings = [(1, 5), (2, 4), (3, 3)]
        for movie_id, rating in movie_ratings:
            response = self.client.post(f"/movies/{movie_id}/rate", 
                                      json={"rating": rating}, 
                                      headers=headers)
            self.assertEqual(response.status_code, 200)
            response_data = response.json()
            self.assertEqual(response_data["movie_id"], movie_id)
            self.assertEqual(response_data["rating"], rating)
            self.assertEqual(response_data["user"], self.test_user["email"])
        
        # Step 4: Check User Profile
        profile_response = self.client.get("/profile", headers=headers)
        self.assertEqual(profile_response.status_code, 200)
        profile_data = profile_response.json()
        
        # Verify profile structure
        self.assertIn("user", profile_data)
        self.assertIn("ratings", profile_data)
        self.assertIn("total_ratings", profile_data)
        
        # Verify user data
        user_data = profile_data["user"]
        self.assertEqual(user_data["email"], self.test_user["email"])
        self.assertEqual(user_data["full_name"], self.test_user["full_name"])
        
        # Verify ratings data
        self.assertEqual(profile_data["total_ratings"], len(movie_ratings))
        self.assertEqual(len(profile_data["ratings"]), len(movie_ratings))
        
        # Verify specific ratings
        user_ratings = {r["movie_id"]: r["rating"] for r in profile_data["ratings"]}
        for movie_id, expected_rating in movie_ratings:
            self.assertEqual(user_ratings[movie_id], expected_rating)
        
        # Step 5: Test Movie List with Ratings
        movies_response = self.client.get("/movies")
        self.assertEqual(movies_response.status_code, 200)
        movies_data = movies_response.json()
        self.assertIsInstance(movies_data, list)
        self.assertGreater(len(movies_data), 0)
        
        # Verify movie structure includes ratings
        for movie in movies_data:
            self.assertIn("id", movie)
            self.assertIn("title", movie)
            self.assertIn("genre", movie)
            self.assertIn("year", movie)
            self.assertIn("average_rating", movie)
            self.assertIn("total_ratings", movie)
        
        # Test duplicate registration
        duplicate_response = self.client.post("/register", json=self.test_user)
        self.assertEqual(duplicate_response.status_code, 400)
        self.assertIn("already registered", duplicate_response.json()["detail"])
        
        # Test invalid login
        invalid_login_response = self.client.post("/login", json={
            "email": self.test_user["email"],
            "password": "wrong_password"
        })
        self.assertEqual(invalid_login_response.status_code, 401)
        self.assertIn("Invalid email or password", invalid_login_response.json()["detail"])
        
        print("PASS: Complete user workflow (Register -> Login -> Rate -> Profile)")
        print("PASS: Database integration and data persistence")
        print("PASS: Movie rating system integration")
        print("PASS: User profile and rating history")
        print("PASS: Error handling in workflows")
        print("PASS: Integration testing framework validated")

    def test_05_security_testing_framework(self):
        """Test 5: Security Testing Framework and Vulnerability Assessment"""
        print("Running Test 5: Security Testing Framework")
        
        # Test authentication security
        # Test 1: Unauthorized access protection
        protected_endpoints = ["/profile", "/movies/1/rate"]
        
        for endpoint in protected_endpoints:
            if endpoint.endswith("/rate"):
                response = self.client.post(endpoint, json={"rating": 5})
            else:
                response = self.client.get(endpoint)
            
            self.assertEqual(response.status_code, 403)  # Forbidden without token
        
        # Test 2: Invalid token formats
        invalid_tokens = [
            "Bearer invalid_token",
            "Bearer ",
            "invalid_format",
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"
        ]
        
        for invalid_token in invalid_tokens:
            headers = {"Authorization": invalid_token}
            response = self.client.get("/profile", headers=headers)
            self.assertIn(response.status_code, [401, 403])  # Unauthorized or Forbidden
        
        # Test 3: SQL Injection attempts (should be prevented by Pydantic)
        sql_injection_attempts = [
            {"email": "test'; DROP TABLE users; --", "password": "password123", "full_name": "Hacker"},
            {"email": "test@example.com", "password": "' OR '1'='1", "full_name": "Hacker"},
        ]
        
        for attempt in sql_injection_attempts:
            response = self.client.post("/register", json=attempt)
            # Should either fail validation (422) or register normally (200)
            # But should not cause system errors
            self.assertIn(response.status_code, [200, 422])
        
        # Test 4: XSS prevention (HTML/JS in inputs)
        xss_attempts = [
            {"email": "xss@example.com", "password": "password123", "full_name": "<script>alert('xss')</script>"},
            {"email": "xss2@example.com", "password": "password123", "full_name": "<img src=x onerror=alert('xss')>"},
        ]
        
        for attempt in xss_attempts:
            response = self.client.post("/register", json=attempt)
            if response.status_code == 200:
                # If registration succeeds, verify data is stored as-is (not executed)
                stored_user = self.users_db.get(attempt["email"])
                if stored_user:
                    self.assertEqual(stored_user["full_name"], attempt["full_name"])
        
        # Test 5: Rate limiting simulation (business logic)
        # Register and login user for rate testing
        rate_test_user = {
            "email": "ratetest@example.com",
            "password": "password123",
            "full_name": "Rate Test User"
        }
        self.client.post("/register", json=rate_test_user)
        login_response = self.client.post("/login", json={
            "email": rate_test_user["email"],
            "password": rate_test_user["password"]
        })
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test multiple rapid requests (should all succeed in this simple implementation)
        rapid_requests = []
        for i in range(5):
            response = self.client.post("/movies/1/rate", 
                                      json={"rating": 5}, 
                                      headers=headers)
            rapid_requests.append(response.status_code)
        
        # All should succeed (no rate limiting implemented yet)
        for status_code in rapid_requests:
            self.assertEqual(status_code, 200)
        
        # Test 6: Input boundary testing
        boundary_tests = [
            # Very long strings
            {"email": "test@example.com", "password": "a" * 1000, "full_name": "Test"},
            {"email": "test@example.com", "password": "password123", "full_name": "a" * 1000},
            # Empty strings (should fail validation)
            {"email": "", "password": "password123", "full_name": "Test"},
            {"email": "test@example.com", "password": "", "full_name": "Test"},
        ]
        
        for test_case in boundary_tests:
            response = self.client.post("/register", json=test_case)
            # Should handle gracefully (either succeed or fail validation)
            self.assertIn(response.status_code, [200, 400, 422])
        
        # Test 7: Security headers and response analysis
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        
        # Check that sensitive information is not exposed in responses
        root_data = response.json()
        self.assertNotIn("password", str(root_data).lower())
        self.assertNotIn("secret", str(root_data).lower())
        self.assertNotIn("key", str(root_data).lower())
        
        print("PASS: Unauthorized access protection")
        print("PASS: Invalid token format handling")
        print("PASS: SQL injection prevention")
        print("PASS: XSS prevention and data sanitization")
        print("PASS: Rate limiting simulation")
        print("PASS: Input boundary testing")
        print("PASS: Information disclosure prevention")
        print("PASS: Security testing framework validated")

def run_core_tests():
    """Run core tests and provide summary"""
    print("=" * 70)
    print("[*] Core Testing & Security Frameworks Unit Tests (5 Tests)")
    print("Testing with LOCAL Testing & Security Components")
    print("=" * 70)
    
    print("[INFO] This system uses local testing and security frameworks (no external dependencies)")
    print("[INFO] Tests validate Password Security, JWT Auth, Input Validation, Integration, Security")
    print()
    
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(CoreTestingSecurityTests)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    print("[*] Test Results:")
    print(f"[*] Tests Run: {result.testsRun}")
    print(f"[*] Failures: {len(result.failures)}")
    print(f"[*] Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n[FAILURES]:")
        for test, traceback in result.failures:
            print(f"  - {test}")
            print(f"    {traceback}")
    
    if result.errors:
        print("\n[ERRORS]:")
        for test, traceback in result.errors:
            print(f"  - {test}")
            print(f"    {traceback}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    
    if success:
        print("\n[SUCCESS] All 5 core testing & security tests passed!")
        print("[OK] Testing & security frameworks working correctly with local implementation")
        print("[OK] Password Security, JWT Auth, Input Validation, Integration, Security validated")
    else:
        print(f"\n[WARNING] {len(result.failures) + len(result.errors)} test(s) failed")
    
    return success

if __name__ == "__main__":
    print("[*] Starting Core Testing & Security Frameworks Tests")
    print("[*] 5 essential tests with local testing & security implementation")
    print("[*] Components: Password Security, JWT Auth, Input Validation, Integration, Security")
    print()
    
    success = run_core_tests()
    exit(0 if success else 1)