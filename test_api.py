"""
Simple Test Cases for Movie Rating API
Easy to understand for students learning testing frameworks
"""

import pytest
from fastapi.testclient import TestClient
from main import app

# Create test client
client = TestClient(app)

# Test data
test_user = {
    "email": "student@example.com",
    "password": "password123",
    "full_name": "Test Student"
}

class TestBasicEndpoints:
    """Test basic API endpoints"""
    
    def test_root_endpoint(self):
        """Test the root endpoint works"""
        response = client.get("/")
        assert response.status_code == 200
        assert "message" in response.json()
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_get_movies_public(self):
        """Test getting movies (no authentication needed)"""
        response = client.get("/movies")
        assert response.status_code == 200
        movies = response.json()
        assert len(movies) == 3  # We have 3 sample movies
        assert movies[0]["title"] == "The Matrix"

class TestAuthentication:
    """Test user registration and login"""
    
    def test_user_registration(self):
        """Test user can register successfully"""
        response = client.post("/register", json=test_user)
        assert response.status_code == 200
        assert "User registered successfully" in response.json()["message"]
    
    def test_duplicate_registration(self):
        """Test duplicate email registration fails"""
        # Register first time
        client.post("/register", json=test_user)
        
        # Try to register again
        response = client.post("/register", json=test_user)
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]
    
    def test_short_password(self):
        """Test short password is rejected"""
        short_password_user = test_user.copy()
        short_password_user["password"] = "123"  # Too short
        
        response = client.post("/register", json=short_password_user)
        assert response.status_code == 400
        assert "at least 6 characters" in response.json()["detail"]
    
    def test_user_login(self):
        """Test user can login and get token"""
        # Register user first
        client.post("/register", json=test_user)
        
        # Login
        login_data = {"email": test_user["email"], "password": test_user["password"]}
        response = client.post("/login", json=login_data)
        
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
    
    def test_wrong_password(self):
        """Test login with wrong password fails"""
        # Register user first
        client.post("/register", json=test_user)
        
        # Try login with wrong password
        wrong_login = {"email": test_user["email"], "password": "wrongpassword"}
        response = client.post("/login", json=wrong_login)
        
        assert response.status_code == 401
        assert "Invalid email or password" in response.json()["detail"]

class TestMovieRating:
    """Test movie rating functionality"""
    
    def get_auth_token(self):
        """Helper function to get authentication token"""
        # Register and login user
        client.post("/register", json=test_user)
        login_response = client.post("/login", json={
            "email": test_user["email"], 
            "password": test_user["password"]
        })
        return login_response.json()["access_token"]
    
    def test_rate_movie_success(self):
        """Test user can rate a movie"""
        token = self.get_auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Rate movie with ID 1
        rating_data = {"rating": 5}
        response = client.post("/movies/1/rate", json=rating_data, headers=headers)
        
        assert response.status_code == 200
        assert response.json()["rating"] == 5
        assert "rated successfully" in response.json()["message"]
    
    def test_rate_movie_without_auth(self):
        """Test rating movie without authentication fails"""
        rating_data = {"rating": 4}
        response = client.post("/movies/1/rate", json=rating_data)
        
        assert response.status_code == 403  # No authorization header
    
    def test_rate_nonexistent_movie(self):
        """Test rating non-existent movie fails"""
        token = self.get_auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        rating_data = {"rating": 3}
        response = client.post("/movies/999/rate", json=rating_data, headers=headers)
        
        assert response.status_code == 404
        assert "Movie not found" in response.json()["detail"]
    
    def test_invalid_rating(self):
        """Test invalid rating values are rejected"""
        token = self.get_auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test rating too high
        response = client.post("/movies/1/rate", json={"rating": 6}, headers=headers)
        assert response.status_code == 400
        
        # Test rating too low
        response = client.post("/movies/1/rate", json={"rating": 0}, headers=headers)
        assert response.status_code == 400

class TestUserProfile:
    """Test user profile functionality"""
    
    def get_auth_token(self):
        """Helper function to get authentication token"""
        client.post("/register", json=test_user)
        login_response = client.post("/login", json={
            "email": test_user["email"], 
            "password": test_user["password"]
        })
        return login_response.json()["access_token"]
    
    def test_get_profile(self):
        """Test user can get their profile"""
        token = self.get_auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        response = client.get("/profile", headers=headers)
        
        assert response.status_code == 200
        profile = response.json()
        assert profile["user"]["email"] == test_user["email"]
        assert "ratings" in profile
        assert "total_ratings" in profile
    
    def test_get_profile_without_auth(self):
        """Test getting profile without authentication fails"""
        response = client.get("/profile")
        assert response.status_code == 403
    
    def test_profile_with_ratings(self):
        """Test profile shows user's ratings"""
        token = self.get_auth_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Rate a movie first
        client.post("/movies/1/rate", json={"rating": 5}, headers=headers)
        
        # Get profile
        response = client.get("/profile", headers=headers)
        profile = response.json()
        
        assert profile["total_ratings"] == 1
        assert len(profile["ratings"]) == 1
        assert profile["ratings"][0]["rating"] == 5

class TestSecurity:
    """Test security features"""
    
    def test_invalid_token(self):
        """Test invalid JWT token is rejected"""
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/profile", headers=headers)
        
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"]
    
    def test_no_token(self):
        """Test accessing protected endpoint without token fails"""
        response = client.get("/profile")
        assert response.status_code == 403

class TestMovieData:
    """Test movie data and ratings"""
    
    def test_movie_with_ratings(self):
        """Test movie shows average rating after being rated"""
        # Register user and get token
        client.post("/register", json=test_user)
        login_response = client.post("/login", json={
            "email": test_user["email"], 
            "password": test_user["password"]
        })
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # Rate movie
        client.post("/movies/1/rate", json={"rating": 4}, headers=headers)
        
        # Check movie now has rating
        response = client.get("/movies/1")
        movie = response.json()
        
        assert movie["average_rating"] == 4.0
        assert movie["total_ratings"] == 1
    
    def test_get_specific_movie(self):
        """Test getting a specific movie by ID"""
        response = client.get("/movies/1")
        
        assert response.status_code == 200
        movie = response.json()
        assert movie["title"] == "The Matrix"
        assert movie["genre"] == "Sci-Fi"
        assert movie["year"] == 1999

# Simple test runner
if __name__ == "__main__":
    pytest.main([__file__, "-v"])