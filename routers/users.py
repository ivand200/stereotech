import time
import logging
import sys
from typing import Dict, Optional

from fastapi import APIRouter, Body, status, Depends, HTTPException, Header, Body
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from passlib.context import CryptContext
import jwt

from decouple import config
from db import get_db
from schemas.users import UserCreate, UserPublic
from models.users import User
from .auth import signJWT, decodeJWT, logoutJWT


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler =logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

router = APIRouter()


def get_user_or_404(id: int, db: Session = Depends(get_db)) -> UserPublic:
    select_user = db.query(User).filter(User.id == id).first()
    if not select_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

    return UserPublic(username=select_user.username, id=select_user.id)


def check_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Check user in db
    """
    try:
        user_db = db.query(User).filter(User.username == user.username).first()
        varify_password = pwd_context.verify(user.password, user_db.password)
        if user_db and varify_password:
            return True
        return False
    except:
        False


@router.get("/test/{id}")
def test(id: int, db: Session = Depends(get_db)):
    x = get_user_or_404(id, db)
    return x


@router.post("/registration", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def user_create(user: UserCreate, db: Session = Depends(get_db)):
    """
    New user registration
    """
    # logger
    user_db = db.query(User).filter(User.username == user.username).first()
    if user_db:
        raise HTTPException(status_code=400, detail="login already exist.")
    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@router.post("/login", status_code=status.HTTP_200_OK)
async def user_login(user: UserCreate, db: Session = Depends(get_db)):
    """
    Login existing user
    """
    # logging
    if check_user(user, db):
        return signJWT(user.username)
    raise HTTPException(status_code=403, detail="Unauthorized")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def exit_user(
    Authorization: Optional[str] = Header(...)
):
    """
    Exit user
    """
    result = logoutJWT(Authorization)
    return result


@router.post("/refresh_jwt", status_code=status.HTTP_201_CREATED)
async def refresh_token(
    Authorization: Optional[str] = Header(...),
    db: Session = Depends(get_db),
):
    """
    Refresh user token
    """
    token = decodeJWT(Authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Acces denied")
    return signJWT(token["user_id"])




@router.get("/user", response_model=UserPublic, status_code=status.HTTP_200_OK)
async def get_user(
    Authorization: Optional[str] = Header(...),
    db: Session = Depends(get_db)
):
    """
    Get user information
    """
    token = decodeJWT(Authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Acces denied")
    user = db.query(User).filter(User.username == token["user_id"]).first()
    return user
