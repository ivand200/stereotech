from typing import List, Optional

from pydantic import BaseModel, validator


class UserBase(BaseModel):
    username: Optional[str]


class UserCreate(UserBase):
    password: str

    @validator("password")
    def valid_password(cls, value):
        if len(value) < 8:
            raise ValueError("Password should be at least 8 chars")
        if not any(i.isdigit() for i in value):
            raise ValueError("Password should contains at least one number")
        if not any(i.isupper() for i in value):
            raise ValueError("Password should contains at least one capital letter")
        return value

    class Config:
        orm_mode = True


class UserPublic(UserBase):
    id: Optional[int]

    class Config:
        orm_mode = True
