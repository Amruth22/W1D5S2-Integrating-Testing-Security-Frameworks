"""
Simple Movie Rating API for Students
Demonstrates testing and security frameworks integration
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
import uvicorn

# Simple FastAPI app
app = FastAPI(title="Movie Rating API", description="Simple API for learning testing and security")

# Security setup
SECRET_KEY = "student-secret-key-for-learning"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# In-memory storage (simple for students)
users_db = {}  # {email: {password_hash, full_name, id}}
movies_db = {
    1: {"id": 1, "title": "The Matrix", "genre": "Sci-Fi", "year": 1999},
    2: {"id": 2, "title": "Inception", "genre": "Thriller", "year": 2010},
    3: {"id": 3, "title": "Interstellar", "genre": "Sci-Fi", "year": 2014}
}
ratings_db = {}  # {movie_id: {user_id: rating}}
user_counter = 1

# Simple models
class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class MovieRating(BaseModel):
    rating: int  # 1-5 stars

class User(BaseModel):
    id: int
    email: str
    full_name: str

# Helper functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(email: str):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": email, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        
        if email is None or email not in users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user_data = users_db[email]
        return User(id=user_data["id"], email=email, full_name=user_data["full_name"])
    
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# API Endpoints
@app.get("/")
def root():
    return {
        "message": "Simple Movie Rating API for Students",
        "endpoints": {
            "auth": ["/register", "/login"],
            "movies": ["/movies", "/movies/{id}/rate"],
            "user": ["/profile"]
        }
    }

@app.post("/register")
def register_user(user: UserRegister):
    global user_counter
    
    # Check if user exists
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Validate password length
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    # Store user
    users_db[user.email] = {
        "password_hash": hash_password(user.password),
        "full_name": user.full_name,
        "id": user_counter
    }
    user_counter += 1
    
    return {"message": "User registered successfully", "email": user.email}

@app.post("/login", response_model=Token)
def login_user(user: UserLogin):
    # Check if user exists
    if user.email not in users_db:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Verify password
    stored_user = users_db[user.email]
    if not verify_password(user.password, stored_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Create token
    access_token = create_access_token(user.email)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/movies")
def get_movies():
    """Get all movies (public endpoint)"""
    movies = list(movies_db.values())
    
    # Add average ratings
    for movie in movies:
        movie_ratings = ratings_db.get(movie["id"], {})
        if movie_ratings:
            avg_rating = sum(movie_ratings.values()) / len(movie_ratings)
            movie["average_rating"] = round(avg_rating, 1)
            movie["total_ratings"] = len(movie_ratings)
        else:
            movie["average_rating"] = None
            movie["total_ratings"] = 0
    
    return movies

@app.get("/movies/{movie_id}")
def get_movie(movie_id: int):
    """Get specific movie"""
    if movie_id not in movies_db:
        raise HTTPException(status_code=404, detail="Movie not found")
    
    movie = movies_db[movie_id].copy()
    movie_ratings = ratings_db.get(movie_id, {})
    
    if movie_ratings:
        avg_rating = sum(movie_ratings.values()) / len(movie_ratings)
        movie["average_rating"] = round(avg_rating, 1)
        movie["total_ratings"] = len(movie_ratings)
    else:
        movie["average_rating"] = None
        movie["total_ratings"] = 0
    
    return movie

@app.post("/movies/{movie_id}/rate")
def rate_movie(movie_id: int, rating: MovieRating, current_user: User = Depends(get_current_user)):
    """Rate a movie (requires authentication)"""
    
    # Check if movie exists
    if movie_id not in movies_db:
        raise HTTPException(status_code=404, detail="Movie not found")
    
    # Validate rating
    if rating.rating < 1 or rating.rating > 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")
    
    # Store rating
    if movie_id not in ratings_db:
        ratings_db[movie_id] = {}
    
    ratings_db[movie_id][current_user.id] = rating.rating
    
    return {
        "message": "Movie rated successfully",
        "movie_id": movie_id,
        "rating": rating.rating,
        "user": current_user.email
    }

@app.get("/profile")
def get_profile(current_user: User = Depends(get_current_user)):
    """Get user profile (requires authentication)"""
    
    # Get user's ratings
    user_ratings = []
    for movie_id, movie_ratings in ratings_db.items():
        if current_user.id in movie_ratings:
            movie = movies_db[movie_id]
            user_ratings.append({
                "movie_id": movie_id,
                "movie_title": movie["title"],
                "rating": movie_ratings[current_user.id]
            })
    
    return {
        "user": current_user,
        "ratings": user_ratings,
        "total_ratings": len(user_ratings)
    }

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
