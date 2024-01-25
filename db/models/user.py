from pydantic import BaseModel
from typing import Optional

class User(BaseModel):
#    id: Optional[str]
    id: str
    username: str
    email: str