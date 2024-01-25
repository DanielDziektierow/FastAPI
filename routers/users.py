from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

#Inicia el serve con uvicorn users:app --reload

router = APIRouter()

#Entidad user

class User(BaseModel):
    id: int
    name: str 
    surname: str
    url: str
    age: int

users_list = [User(id=1, name="Dani", surname="Dziektierow", url="www'google.com", age=27)]

@router.get("/usersjson")
async def usersjson():
    return [{"name" : "Dani", "surname" : "Dziektierow", "url" : "www'google.com", "age" : "27" }]

@router.get("/users")
async def usersjson():
    return users_list

@router.get("/user/{id}")
async def user(id: int):
    users = filter(lambda user : user.id == id, users_list)
    try:
        return list(users)[0]
    except:
        return {"error":"No existe"}


@router.post("/user/", response_model= User,status_code=201)
async def user(user: User):
    if type(search_user(user.id)) == User:
        raise HTTPException(status_code=204, detail="El usuario ya existe")

    else:
        users_list.append(user)
        return user

@router.put("/user/")
async def user(user:User):
    found= False

    for index, saved_user in enumerate(users_list):
        if saved_user.id == user.id:
            users_list[index]= user
            found= True
    
    if not found:
        return {"error":"No se ha actualizado el usuario"} 
    else:
        return user 


@router.delete("/user/{id}/")
async def user(id:int):
    found= False

    for index, saved_user in enumerate(users_list):
        if saved_user.id == id:
            del users_list[index]
            found= True
   
    if not found:
            return {"error":"No se ha eliminado el usuario"} 
    else:
        return user 

def search_user(id: int):
    users = filter(lambda user : user.id == id, users_list)
    try:
        return list(users)[0]
    except:
        return {"error":"No existe"}