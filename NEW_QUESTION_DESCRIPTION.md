# W1D5S2 - Integrating Testing & Security Frameworks

## 🎯 **Learning Objective**
Build a comprehensive Movie Rating API that demonstrates **Testing Frameworks Integration** and **Security Best Practices** using FastAPI, JWT authentication, and multiple testing methodologies.

## 📋 **Project Requirements**

### **Core Functionality**
1. **Movie Rating System**
   - User registration and authentication
   - JWT token-based authorization
   - Movie rating (1-5 stars) with user authentication
   - User profile with rating history

2. **Security Implementation**
   - Password hashing with bcrypt and salt
   - JWT token authentication with expiration
   - Protected endpoints requiring authentication
   - Input validation and sanitization

3. **Testing Framework Integration**
   - Unit tests for individual functions
   - Integration tests for complete workflows
   - Security tests for vulnerability assessment
   - API endpoint testing with FastAPI TestClient

## 🏗️ **Technical Architecture**

### **Authentication & Security Layer**
```python
# Password Security
- bcrypt hashing with automatic salt generation
- Minimum 6-character password requirement
- Secure password storage (never plain text)

# JWT Authentication
- 30-minute token expiration
- HS256 algorithm with secret key
- Protected endpoint authorization
- Token validation and error handling
```

### **API Endpoints Structure**
```python
# Public Endpoints
GET  /                    # API information
GET  /movies             # List all movies with ratings
GET  /movies/{id}        # Get specific movie details
GET  /health            # Health check

# Authentication Endpoints
POST /register          # User registration
POST /login            # User login (returns JWT token)

# Protected Endpoints (Require JWT)
POST /movies/{id}/rate  # Rate a movie (1-5 stars)
GET  /profile          # Get user profile and rating history
```

### **Data Models**
```python
# User Models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    id: int
    email: str
    full_name: str

# Movie Models
class MovieRating(BaseModel):
    rating: int  # 1-5 stars

class Token(BaseModel):
    access_token: str
    token_type: str
```

## 🧪 **Testing Framework Requirements**

### **1. Unit Tests (Individual Functions)**
```python
# Password Security Tests
def test_password_hashing():
    - Test bcrypt hashing functionality
    - Verify salt uniqueness
    - Test password verification

# JWT Token Tests
def test_jwt_creation():
    - Test token creation and structure
    - Verify token payload and expiration
    - Test token validation

# Input Validation Tests
def test_data_validation():
    - Test email format validation
    - Test rating range validation (1-5)
    - Test data type enforcement
```

### **2. Integration Tests (Complete Workflows)**
```python
# Complete User Workflow
def test_user_workflow():
    1. Register user
    2. Login and get JWT token
    3. Rate multiple movies
    4. Check profile shows ratings
    5. Verify data persistence

# Authentication Flow
def test_auth_flow():
    - Test registration → login → protected access
    - Verify token-based authorization
    - Test unauthorized access prevention
```

### **3. Security Tests (Vulnerability Assessment)**
```python
# Security Validation
def test_security_features():
    - Test unauthorized access protection
    - Test invalid token rejection
    - Test SQL injection prevention
    - Test XSS prevention
    - Test input boundary conditions
```

## 🔒 **Security Requirements**

### **1. Password Security**
- ✅ Use bcrypt for password hashing
- ✅ Automatic salt generation for each password
- ✅ Minimum password length validation (6 characters)
- ✅ Never store passwords in plain text
- ✅ Secure password verification

### **2. JWT Authentication**
- ✅ Create JWT tokens with expiration (30 minutes)
- ✅ Use HS256 algorithm with secret key
- ✅ Validate tokens on protected endpoints
- ✅ Handle invalid/expired tokens gracefully
- ✅ Implement proper authorization headers

### **3. Input Validation & Sanitization**
- ✅ Email format validation using Pydantic EmailStr
- ✅ Rating range validation (1-5 stars only)
- ✅ Data type validation for all inputs
- ✅ Prevent SQL injection through proper validation
- ✅ Handle XSS attempts safely

### **4. API Security**
- ✅ Protect sensitive endpoints with authentication
- ✅ Return appropriate HTTP status codes
- ✅ Don't expose sensitive information in responses
- ✅ Handle unauthorized access attempts
- ✅ Implement proper error messages

## 📊 **Expected Deliverables**

### **1. Core Application Files**
```
├── main.py                 # FastAPI application with all endpoints
├── requirements.txt        # Dependencies including testing/security tools
├── security_check.py      # Security testing and vulnerability scanning
└── README.md              # Comprehensive documentation
```

### **2. Testing Implementation**
```
├── test_unit.py           # W1D4S2-style comprehensive unit tests
├── unit_test.py          # Original API integration tests
└── pytest configuration   # Support for pytest framework
```

### **3. Security Tools Integration**
```
├── bandit integration     # Static code analysis
├── safety integration     # Dependency vulnerability scanning
└── Custom security tests  # Application-specific security validation
```

## 🎯 **Core Testing Scenarios**

### **Scenario 1: Password Security Testing**
```python
# Test password hashing
password = "test123"
hashed = hash_password(password)
assert hashed != password  # Not plain text
assert verify_password(password, hashed)  # Verification works

# Test salt uniqueness
hash1 = hash_password("same_password")
hash2 = hash_password("same_password")
assert hash1 != hash2  # Different salts

# Test password length validation
response = client.post("/register", json={
    "email": "test@example.com",
    "password": "123",  # Too short
    "full_name": "Test User"
})
assert response.status_code == 400
```

### **Scenario 2: JWT Authentication Testing**
```python
# Test token creation
token = create_access_token("test@example.com")
payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
assert payload["sub"] == "test@example.com"

# Test protected endpoint access
headers = {"Authorization": f"Bearer {token}"}
response = client.get("/profile", headers=headers)
assert response.status_code == 200

# Test invalid token rejection
invalid_headers = {"Authorization": "Bearer invalid_token"}
response = client.get("/profile", headers=invalid_headers)
assert response.status_code == 401
```

### **Scenario 3: Integration Testing**
```python
# Complete user workflow
def test_complete_workflow():
    # 1. Register user
    register_response = client.post("/register", json=user_data)
    assert register_response.status_code == 200
    
    # 2. Login user
    login_response = client.post("/login", json=login_data)
    token = login_response.json()["access_token"]
    
    # 3. Rate movies
    headers = {"Authorization": f"Bearer {token}"}
    rating_response = client.post("/movies/1/rate", 
                                json={"rating": 5}, 
                                headers=headers)
    assert rating_response.status_code == 200
    
    # 4. Check profile
    profile_response = client.get("/profile", headers=headers)
    assert profile_response.status_code == 200
    assert profile_response.json()["total_ratings"] >= 1
```

## 🛡️ **Security Testing Requirements**

### **1. Authentication Security**
- Test unauthorized access to protected endpoints
- Validate JWT token format and signature
- Test token expiration handling
- Verify proper HTTP status codes for auth failures

### **2. Input Security**
- Test SQL injection prevention
- Test XSS prevention in user inputs
- Validate input boundary conditions
- Test malformed request handling

### **3. Business Logic Security**
- Test rating validation (1-5 range only)
- Test movie existence validation
- Test user ownership of ratings
- Test duplicate registration prevention

## 📈 **Performance & Quality Metrics**

### **Testing Metrics**
- **Test Coverage**: 100% of critical security functions
- **Test Types**: Unit, Integration, Security, API
- **Response Time**: < 100ms for most endpoints
- **Security Score**: Pass all security validations

### **Security Metrics**
- **Password Strength**: bcrypt with salt
- **Token Security**: Proper JWT implementation
- **Input Validation**: 100% validation coverage
- **Vulnerability Score**: Zero critical vulnerabilities

## 🎓 **Learning Outcomes**

Upon completion, students will understand:

### **Testing Concepts**
1. **Unit Testing**: Testing individual functions in isolation
2. **Integration Testing**: Testing complete workflows and interactions
3. **API Testing**: Testing HTTP endpoints and responses
4. **Security Testing**: Testing for vulnerabilities and security flaws
5. **Test Framework Integration**: Using pytest, unittest, and FastAPI TestClient

### **Security Concepts**
1. **Authentication vs Authorization**: Who you are vs what you can do
2. **Password Security**: Hashing, salting, and secure storage
3. **JWT Tokens**: Stateless authentication and token validation
4. **Input Validation**: Preventing injection attacks and data corruption
5. **Vulnerability Assessment**: Identifying and preventing security flaws

### **Framework Integration**
1. **FastAPI Security**: Built-in security features and best practices
2. **Pydantic Validation**: Data validation and serialization
3. **Testing Tools**: pytest, unittest, TestClient integration
4. **Security Tools**: bandit, safety, and custom security testing

## 🔧 **Implementation Guidelines**

### **Security Implementation**
1. Use bcrypt for password hashing with automatic salt
2. Implement JWT tokens with proper expiration
3. Validate all user inputs with Pydantic models
4. Protect sensitive endpoints with authentication
5. Handle security errors gracefully

### **Testing Implementation**
1. Write unit tests for all security functions
2. Create integration tests for complete workflows
3. Implement security tests for vulnerability assessment
4. Use FastAPI TestClient for API testing
5. Integrate external security tools (bandit, safety)

### **Code Quality**
1. Follow FastAPI best practices
2. Use type hints for better code clarity
3. Implement proper error handling
4. Add comprehensive logging
5. Document security considerations

## 🎯 **Success Criteria**

### **Functional Requirements**
- ✅ All API endpoints working correctly
- ✅ User registration and login functional
- ✅ Movie rating system operational
- ✅ User profile showing rating history

### **Security Requirements**
- ✅ Passwords properly hashed and secured
- ✅ JWT authentication working correctly
- ✅ Protected endpoints requiring authentication
- ✅ Input validation preventing malicious inputs

### **Testing Requirements**
- ✅ All unit tests passing
- ✅ Integration tests covering complete workflows
- ✅ Security tests validating vulnerability prevention
- ✅ API tests covering all endpoints

### **Framework Integration**
- ✅ Testing frameworks properly integrated
- ✅ Security tools successfully integrated
- ✅ External tools (bandit, safety) functional
- ✅ Comprehensive test coverage achieved

## 💡 **Bonus Challenges**

### **Advanced Testing**
1. Add performance testing for API endpoints
2. Implement load testing for concurrent users
3. Add database testing with mock data
4. Create automated test reporting

### **Enhanced Security**
1. Add rate limiting for login attempts
2. Implement password complexity requirements
3. Add session management and logout
4. Implement role-based access control

### **Framework Extensions**
1. Add continuous integration (CI) setup
2. Implement automated security scanning
3. Add code coverage reporting
4. Create security compliance reporting

---

## 📚 **Resources for Learning**

### **Testing Resources**
- [pytest Documentation](https://docs.pytest.org/)
- [FastAPI Testing Guide](https://fastapi.tiangolo.com/tutorial/testing/)
- [Python unittest Documentation](https://docs.python.org/3/library/unittest.html)

### **Security Resources**
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT.io Introduction](https://jwt.io/introduction/)
- [FastAPI Security Guide](https://fastapi.tiangolo.com/tutorial/security/)

### **Tools Documentation**
- [Bandit Security Linter](https://bandit.readthedocs.io/)
- [Safety Vulnerability Scanner](https://pyup.io/safety/)
- [bcrypt Password Hashing](https://pypi.org/project/bcrypt/)

---

**🎓 Master Testing & Security Frameworks Integration with this comprehensive educational project!**