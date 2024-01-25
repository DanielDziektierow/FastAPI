#Inicia el serve con uvicorn jwt_auth_users:app --reload
#pip install "python-jose[cryptography]"
#pip install "passlib[bcrypt]"

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

ALGORITH = "HS256"
ACCESS_TOKEN_DURATION = 1
SECRET = "0ba84dd9273d1f182bd630ee012ce3f5e351d6dc691c98de040d2ac44147ef3e"

crypt = CryptContext(schemes=["bcrypt"])

router = APIRouter()

oauth2 = OAuth2PasswordBearer(tokenUrl= "login")

class User(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: bool

class UserDB(User):
    password : str

users_db = {
    "danidev": {
        "username" : "DaniDz",
        "full_name" : "Daniel Dziektierow",
        "email" : "dz09dz@hotmail.com",
        "disabled" : False,
        "password" : "$2a$12$k/u6zpI.P1qYDORQineaOuCiJqSlkZ79QjNnk1o6doJ3KPQPUJRka",
    },
    "charodev": {
        "username" : "CharoGom",
        "full_name" : "Rosario Gomez",
        "email" : "charo.f.gomez@gmail.com",
        "disabled" : True,
        "password" : "$2a$12$zYhbupgwLQNEXdpJ9O39.OBMN/OgTdvRoWzn67pD6Ulvqe3xoFgK6",
    },
}

def search_user_db(username : str):
    if username in users_db:
        return UserDB(**users_db[username])
    
def search_user(username : str):
    if username in users_db:
        return User(**users_db[username])

async def auth_user(token: str = Depends(oauth2)):
    exception =  HTTPException(
                status_code= status.HTTP_401_UNAUTHORIZED, 
                detail= "Credenciales de autenticacion invalidas", 
                    headers= {"WWW-Authenticate" : "Bearer"})

    try:    
        username = jwt.decode(token, SECRET, algorithms=[ALGORITH]).get("sub")
        if username is None :  
            raise exception
        

    except JWTError:
        raise exception
    
    return search_user(username)
           

async def current_user(user: User = Depends(auth_user)):
    if user.disabled:
        raise HTTPException(
            status_code= status.HTTP_400_BAD_REQUEST, 
            detail= "Usuario inactivo")
    return user
    

@router.post("/loginjwt/")
async def login(form : OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form.username)
    if not users_db:
        raise HTTPException(
            status_code= status.HTTP_400_BAD_REQUEST, detail= "El usuario no es correcto")
    
    user = search_user_db(form.username)

    if not crypt.verify(form.password, user.password):
        raise HTTPException(
            status_code= status.HTTP_400_BAD_REQUEST,
             detail= "La contraseña no es correcta")
    

    access_token = {"sub" : user.username, 
                    "exp" : datetime.utcnow() + timedelta(minutes= ACCESS_TOKEN_DURATION)}

    return {"access_token" : jwt.encode(access_token, SECRET,algorithm=ALGORITH), "token_type" : "bearer"}

@router.get("/usersjwt/me")
async def me(user: User= Depends(current_user)):
    return user