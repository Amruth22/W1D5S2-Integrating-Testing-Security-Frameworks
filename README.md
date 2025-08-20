# Simple Movie Rating API - Testing & Security for Students

A beginner-friendly FastAPI project to learn testing frameworks and security practices.

## 🎯 What You'll Learn

- **FastAPI Basics**: Building REST APIs
- **Authentication**: JWT tokens and password hashing
- **Testing**: Writing and running tests with pytest
- **Security**: Basic security practices and vulnerability scanning

## 🚀 Quick Start

### 1. Setup
```bash
# Clone the repository
git clone https://github.com/Amruth22/W1D5S2-Integrating-Testing-Security-Frameworks.git
cd W1D5S2-Integrating-Testing-Security-Frameworks

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the API
```bash
python main.py
```

Visit: http://localhost:8000/docs to see the interactive API documentation!

### 3. Run Tests
```bash
python test_api.py
```

### 4. Run Security Checks
```bash
python security_check.py
```

## 📚 API Overview

### **Movies (Public)**
- `GET /movies` - Get all movies
- `GET /movies/{id}` - Get specific movie

### **Authentication**
- `POST /register` - Register new user
- `POST /login` - Login and get JWT token

### **Rating (Requires Login)**
- `POST /movies/{id}/rate` - Rate a movie (1-5 stars)
- `GET /profile` - Get your profile and ratings

## 🧪 Testing Examples

### Basic Test
```python
def test_get_movies():
    response = client.get("/movies")
    assert response.status_code == 200
    assert len(response.json()) == 3
```

### Authentication Test
```python
def test_user_login():
    # Register user
    client.post("/register", json=test_user)
    
    # Login
    response = client.post("/login", json={
        "email": test_user["email"], 
        "password": test_user["password"]
    })
    
    assert response.status_code == 200
    assert "access_token" in response.json()
```

### Security Test
```python
def test_protected_endpoint():
    # Try without token
    response = client.get("/profile")
    assert response.status_code == 403  # Forbidden
```

## 🔒 Security Features

### 1. **Password Security**
- Passwords are hashed with bcrypt
- Minimum 6 characters required
- Never stored in plain text

### 2. **JWT Authentication**
- Secure token-based authentication
- 30-minute token expiration
- Protected endpoints require valid tokens

### 3. **Input Validation**
- Email format validation
- Rating range validation (1-5)
- Automatic data type checking

## 📖 Learning Path

### Step 1: Understand the API
1. Run the API: `python main.py`
2. Visit http://localhost:8000/docs
3. Try the endpoints in the browser

### Step 2: Run Tests
1. Look at `test_api.py` to understand test structure
2. Run tests: `python test_api.py`
3. See which tests pass/fail

### Step 3: Security Testing
1. Run security checks: `python security_check.py`
2. Understand what each security test does
3. Learn about common vulnerabilities

### Step 4: Experiment
1. Add new endpoints
2. Write new tests
3. Try breaking the security (safely!)

## 🛠️ Code Structure

```
├── main.py           # Main FastAPI application
├── test_api.py       # Test cases
├── security_check.py # Security testing
├── requirements.txt  # Dependencies
└── README.md        # This file
```

## 🎓 Key Concepts

### **Testing**
- **Unit Tests**: Test individual functions
- **Integration Tests**: Test complete workflows
- **Test Client**: Simulate HTTP requests
- **Assertions**: Check if results are correct

### **Security**
- **Authentication**: Who are you?
- **Authorization**: What can you do?
- **Password Hashing**: Never store plain passwords
- **JWT Tokens**: Secure way to maintain login state

### **FastAPI Features**
- **Automatic Documentation**: Swagger UI
- **Data Validation**: Pydantic models
- **Dependency Injection**: Reusable components
- **Type Hints**: Better code clarity

## 🧪 Test Categories

### 1. **Basic Endpoints** (`TestBasicEndpoints`)
- Root endpoint
- Health check
- Public movie list

### 2. **Authentication** (`TestAuthentication`)
- User registration
- User login
- Password validation
- Duplicate email handling

### 3. **Movie Rating** (`TestMovieRating`)
- Rating movies
- Authentication required
- Invalid ratings
- Non-existent movies

### 4. **User Profile** (`TestUserProfile`)
- Getting user profile
- Showing user ratings
- Authentication required

### 5. **Security** (`TestSecurity`)
- Invalid tokens
- Missing tokens
- Protected endpoints

## 🔍 Security Checks

### 1. **Password Security**
- ✅ Short passwords rejected
- ✅ Passwords are hashed
- ✅ Plain text passwords never stored

### 2. **Authentication Security**
- ✅ Protected endpoints require tokens
- ✅ Invalid tokens rejected
- ✅ Valid tokens work correctly

### 3. **Input Validation**
- ✅ Invalid email formats rejected
- ✅ Invalid rating values rejected
- ✅ Data type validation

### 4. **External Tools**
- **Bandit**: Static code analysis
- **Safety**: Dependency vulnerability scanning

## 💡 Common Issues & Solutions

### Issue: Tests fail with "connection error"
**Solution**: Make sure the API is NOT running when you run tests

### Issue: "Module not found" error
**Solution**: Install requirements: `pip install -r requirements.txt`

### Issue: Security tools not found
**Solution**: Install them: `pip install bandit safety`

## 🎯 Exercises for Students

### Beginner
1. Add a new test for getting a specific movie
2. Test what happens with invalid movie IDs
3. Add a test for the health check endpoint

### Intermediate
1. Add a new endpoint to get movies by genre
2. Write tests for the new endpoint
3. Add input validation for the new endpoint

### Advanced
1. Add rate limiting (max 10 requests per minute)
2. Add tests for rate limiting
3. Add security tests for rate limiting

## 📚 Additional Resources

- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **Pytest Documentation**: https://docs.pytest.org/
- **JWT Introduction**: https://jwt.io/introduction/
- **OWASP Security**: https://owasp.org/www-project-top-ten/

## 🤝 Contributing

This is a learning project! Feel free to:
- Add more test cases
- Improve security features
- Add new endpoints
- Fix bugs
- Improve documentation

## 📄 License

This project is for educational purposes. Use it to learn and experiment!

---

**Happy Learning! 🎓**