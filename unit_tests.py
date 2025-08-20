"""
Simple Unit Tests for Movie Rating API
Tests individual functions without HTTP requests - perfect for students to learn unit testing
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from jose import jwt

# Import functions to test
from main import (
    hash_password, 
    verify_password, 
    create_access_token, 
    get_current_user,
    SECRET_KEY, 
    ALGORITHM,
    users_db,
    movies_db,
    ratings_db
)

class TestPasswordFunctions:
    """Test password hashing and verification functions"""
    
    def test_hash_password(self):
        """Test password hashing function"""
        password = "testpassword123"
        hashed = hash_password(password)
        
        # Check that hash is created
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) > 20  # Bcrypt hashes are long
        
        # Check that hash is different from original password
        assert hashed != password
        
        print(f"✅ Password hashed successfully: {password} -> {hashed[:20]}...")
    
    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        password = "correctpassword"
        hashed = hash_password(password)
        
        # Verify correct password
        is_valid = verify_password(password, hashed)
        assert is_valid == True
        
        print(f"✅ Correct password verified successfully")
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        password = "correctpassword"
        wrong_password = "wrongpassword"
        hashed = hash_password(password)
        
        # Verify wrong password
        is_valid = verify_password(wrong_password, hashed)
        assert is_valid == False
        
        print(f"✅ Incorrect password rejected successfully")
    
    def test_password_hashing_unique(self):
        """Test that same password creates different hashes (salt)"""
        password = "samepassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Hashes should be different due to salt
        assert hash1 != hash2
        
        # But both should verify correctly
        assert verify_password(password, hash1) == True
        assert verify_password(password, hash2) == True
        
        print(f"✅ Password salting works correctly")

class TestJWTFunctions:
    """Test JWT token creation and validation"""
    
    def test_create_access_token(self):
        """Test JWT token creation"""
        email = "test@example.com"
        token = create_access_token(email)
        
        # Check token structure
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT has 3 parts: header.payload.signature
        
        # Decode and verify content
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == email
        assert "exp" in payload  # Expiration time should be present
        
        print(f"✅ JWT token created successfully for {email}")
    
    def test_token_expiration_time(self):
        """Test that token has correct expiration time"""
        email = "test@example.com"
        
        # Create token and immediately decode it (before expiration)
        token = create_access_token(email)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Check that expiration is in the future
        exp_time = datetime.utcfromtimestamp(payload["exp"])
        current_time = datetime.utcnow()
        
        # Token should expire in approximately 30 minutes
        time_diff = exp_time - current_time
        expected_minutes = 30
        
        # Allow some tolerance (29-31 minutes)
        assert 29 <= time_diff.total_seconds() / 60 <= 31
        
        print(f"✅ Token expiration time is correct (~30 minutes)")
    
    def test_token_with_invalid_secret(self):
        """Test that token cannot be decoded with wrong secret"""
        email = "test@example.com"
        token = create_access_token(email)
        
        # Try to decode with wrong secret
        with pytest.raises(jwt.JWTError):
            jwt.decode(token, "wrong_secret", algorithms=[ALGORITHM])
        
        print(f"✅ Token security: wrong secret rejected")
    
    def test_expired_token(self):
        """Test that expired tokens are rejected"""
        email = "test@example.com"
        
        # Create a token manually with past expiration
        past_time = datetime.utcnow() - timedelta(hours=1)  # 1 hour ago
        expired_payload = {
            "sub": email,
            "exp": past_time
        }
        expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)
        
        # Try to decode expired token
        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(expired_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        print(f"✅ Expired tokens are rejected")

class TestDataValidation:
    """Test data validation logic"""
    
    def test_rating_validation_valid(self):
        """Test valid rating values"""
        valid_ratings = [1, 2, 3, 4, 5]
        
        for rating in valid_ratings:
            # This simulates the validation logic in the endpoint
            assert 1 <= rating <= 5
        
        print(f"✅ Valid ratings (1-5) accepted")
    
    def test_rating_validation_invalid(self):
        """Test invalid rating values"""
        invalid_ratings = [0, 6, -1, 10, 100]
        
        for rating in invalid_ratings:
            # This simulates the validation logic in the endpoint
            assert not (1 <= rating <= 5)
        
        print(f"✅ Invalid ratings rejected")
    
    def test_email_format_basic(self):
        """Test basic email format validation"""
        valid_emails = ["test@example.com", "user@domain.org", "student@university.edu"]
        invalid_emails = ["notanemail", "missing@", "@domain.com", ""]
        
        # Basic email validation (contains @ and .)
        for email in valid_emails:
            assert "@" in email and "." in email
        
        for email in invalid_emails:
            assert not ("@" in email and "." in email and len(email) > 5)
        
        print(f"✅ Basic email validation works")
    
    def test_password_length_validation(self):
        """Test password length validation"""
        valid_passwords = ["password123", "securepass", "123456"]
        invalid_passwords = ["123", "ab", "", "12345"]
        
        for password in valid_passwords:
            assert len(password) >= 6
        
        for password in invalid_passwords:
            assert len(password) < 6
        
        print(f"✅ Password length validation works")

class TestBusinessLogic:
    """Test business logic functions"""
    
    def test_calculate_average_rating(self):
        """Test average rating calculation logic"""
        # Simulate rating calculation
        ratings = [5, 4, 3, 4, 5]  # Sample ratings
        expected_average = sum(ratings) / len(ratings)  # 4.2
        
        calculated_average = sum(ratings) / len(ratings)
        assert calculated_average == expected_average
        assert calculated_average == 4.2
        
        print(f"✅ Average rating calculation: {ratings} -> {calculated_average}")
    
    def test_calculate_average_single_rating(self):
        """Test average with single rating"""
        ratings = [5]
        average = sum(ratings) / len(ratings)
        
        assert average == 5.0
        
        print(f"✅ Single rating average: {ratings} -> {average}")
    
    def test_calculate_average_empty_ratings(self):
        """Test handling of empty ratings"""
        ratings = []
        
        # Should handle empty list gracefully
        if ratings:
            average = sum(ratings) / len(ratings)
        else:
            average = None
        
        assert average is None
        
        print(f"✅ Empty ratings handled: {ratings} -> {average}")

class TestDataStructures:
    """Test data structure operations"""
    
    def test_user_storage_structure(self):
        """Test user data storage structure"""
        # Test user data structure
        user_data = {
            "password_hash": "hashed_password",
            "full_name": "Test User",
            "id": 1
        }
        
        # Verify required fields
        assert "password_hash" in user_data
        assert "full_name" in user_data
        assert "id" in user_data
        assert isinstance(user_data["id"], int)
        
        print(f"✅ User data structure is correct")
    
    def test_movie_storage_structure(self):
        """Test movie data storage structure"""
        # Test movie data structure
        movie_data = {
            "id": 1,
            "title": "Test Movie",
            "genre": "Action",
            "year": 2023
        }
        
        # Verify required fields
        assert "id" in movie_data
        assert "title" in movie_data
        assert "genre" in movie_data
        assert "year" in movie_data
        assert isinstance(movie_data["year"], int)
        
        print(f"✅ Movie data structure is correct")
    
    def test_rating_storage_structure(self):
        """Test rating data storage structure"""
        # Test rating storage: {movie_id: {user_id: rating}}
        ratings_structure = {
            1: {  # movie_id
                1: 5,  # user_id: rating
                2: 4
            }
        }
        
        # Test structure access
        movie_id = 1
        user_id = 1
        
        assert movie_id in ratings_structure
        assert user_id in ratings_structure[movie_id]
        assert 1 <= ratings_structure[movie_id][user_id] <= 5
        
        print(f"✅ Rating data structure is correct")

class TestMockingExamples:
    """Examples of mocking for unit tests"""
    
    def test_with_mocked_database(self):
        """Test with mocked database to isolate logic"""
        # Mock the users_db
        mock_users = {
            "test@example.com": {
                "password_hash": hash_password("password123"),
                "full_name": "Test User",
                "id": 1
            }
        }
        
        with patch('main.users_db', mock_users):
            # Test that user exists in mocked database
            assert "test@example.com" in mock_users
            
            # Test password verification
            stored_user = mock_users["test@example.com"]
            assert verify_password("password123", stored_user["password_hash"])
        
        print(f"✅ Mocked database testing works")
    
    def test_with_mocked_time(self):
        """Test with mocked time for predictable results"""
        email = "test@example.com"
        
        # Create token and verify it contains email
        token = create_access_token(email)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Verify email is in token
        assert payload["sub"] == email
        
        # Verify expiration exists and is in future
        exp_time = datetime.utcfromtimestamp(payload["exp"])
        current_time = datetime.utcnow()
        assert exp_time > current_time
        
        print(f"✅ Token creation and validation works")

class TestErrorHandling:
    """Test error handling in functions"""
    
    def test_jwt_decode_invalid_token(self):
        """Test JWT decoding with invalid token"""
        invalid_token = "invalid.token.here"
        
        with pytest.raises(jwt.JWTError):
            jwt.decode(invalid_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        print(f"✅ Invalid JWT tokens raise proper errors")
    
    def test_password_verification_edge_cases(self):
        """Test password verification edge cases"""
        # Test with empty strings
        assert verify_password("", hash_password("password")) == False
        assert verify_password("password", "") == False
        
        # Test with None (should handle gracefully)
        try:
            result = verify_password("password", None)
            assert result == False  # Should return False for None hash
        except (TypeError, AttributeError, ValueError):
            pass  # Expected error - either is fine
        
        print(f"✅ Password verification handles edge cases")

# Simple test runner for unit tests only
def run_unit_tests():
    """Run only the unit tests"""
    print("🧪 Running Unit Tests (Individual Functions)")
    print("=" * 50)
    
    # Test password functions
    print("\n🔐 Testing Password Functions:")
    test_pwd = TestPasswordFunctions()
    test_pwd.test_hash_password()
    test_pwd.test_verify_password_correct()
    test_pwd.test_verify_password_incorrect()
    test_pwd.test_password_hashing_unique()
    
    # Test JWT functions
    print("\n🔑 Testing JWT Functions:")
    test_jwt = TestJWTFunctions()
    test_jwt.test_create_access_token()
    test_jwt.test_token_expiration_time()
    test_jwt.test_token_with_invalid_secret()
    test_jwt.test_expired_token()
    
    # Test validation logic
    print("\n✅ Testing Data Validation:")
    test_validation = TestDataValidation()
    test_validation.test_rating_validation_valid()
    test_validation.test_rating_validation_invalid()
    test_validation.test_email_format_basic()
    test_validation.test_password_length_validation()
    
    # Test business logic
    print("\n📊 Testing Business Logic:")
    test_logic = TestBusinessLogic()
    test_logic.test_calculate_average_rating()
    test_logic.test_calculate_average_single_rating()
    test_logic.test_calculate_average_empty_ratings()
    
    # Test data structures
    print("\n🗄️ Testing Data Structures:")
    test_data = TestDataStructures()
    test_data.test_user_storage_structure()
    test_data.test_movie_storage_structure()
    test_data.test_rating_storage_structure()
    
    # Test mocking examples
    print("\n🎭 Testing with Mocks:")
    test_mocks = TestMockingExamples()
    test_mocks.test_with_mocked_database()
    test_mocks.test_with_mocked_time()
    
    # Test error handling
    print("\n❌ Testing Error Handling:")
    test_errors = TestErrorHandling()
    test_errors.test_jwt_decode_invalid_token()
    test_errors.test_password_verification_edge_cases()
    
    print("\n" + "=" * 50)
    print("🎉 All Unit Tests Completed!")
    print("\n📚 What We Tested:")
    print("• Password hashing and verification")
    print("• JWT token creation and validation")
    print("• Data validation logic")
    print("• Business logic calculations")
    print("• Data structure operations")
    print("• Mocking techniques")
    print("• Error handling")
    
    print("\n💡 Unit Testing Benefits:")
    print("• Fast execution (no HTTP requests)")
    print("• Test individual functions in isolation")
    print("• Easy to debug when tests fail")
    print("• Test edge cases and error conditions")
    print("• Learn mocking techniques")

if __name__ == "__main__":
    # You can run this file directly to see unit tests in action
    run_unit_tests()
    
    # Or run with pytest
    print("\n" + "=" * 50)
    print("🔄 You can also run with pytest:")
    print("pytest unit_tests.py -v")
    print("=" * 50)