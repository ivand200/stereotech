import time
import logging
import sys
from typing import Dict, Optional

from fastapi import APIRouter, Body, status, Depends, HTTPException, Header, Body
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from passlib.context import CryptContext
import jwt

from decouple import config
from db import get_db
from schemas.users import UserCreate, UserPublic
from models.users import User, Blacklist
from .auth import signJWT, decodeJWT


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

router = APIRouter()

api_key_header = APIKeyHeader(name="Token")


def blacklist_check(token: str, db: Session = Depends(get_db)):
    """
    Check token in blacklist
    """
    check = db.query(Blacklist).filter(Blacklist.token == token).first()
    if check:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


# def get_user_or_404(id: int, db: Session = Depends(get_db)) -> UserPublic:
#     select_user = db.query(User).filter(User.id == id).first()
#     if not select_user:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
#
#     return UserPublic(username=select_user.username, id=select_user.id)


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


@router.post("/registration", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def user_create(user: UserCreate, db: Session = Depends(get_db)):
    """
    New user registration
    """
    logger.info(f"Create user: {user.username}")
    user_db = db.query(User).filter(User.username == user.username).first()
    if user_db:
        raise HTTPException(status_code=400, detail="Username already exist.")
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
    logger.info(f"User login: {user.username}")
    if check_user(user, db):
        return signJWT(user.username)
    raise HTTPException(status_code=403, detail="Unauthorized")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def exit_user(
    db: Session = Depends(get_db),
    token: str = Depends(api_key_header),
):
    """
    Exit user
    """
    token_jwt = decodeJWT(token)
    if not token_jwt:
        raise HTTPException(status_code=401, detail="Acces denied")
    token_blacklist = Blacklist(token=token)
    logger.info(f"User logout: {token_jwt}")
    db.add(token_blacklist)
    db.commit()
    return True


@router.post("/refresh_jwt", status_code=status.HTTP_201_CREATED)
async def refresh_token(
    token: str = Depends(api_key_header),
    db: Session = Depends(get_db),
):
    """
    Refresh user token
    """
    token_jwt = decodeJWT(token)
    if not token_jwt:
        raise HTTPException(status_code=401, detail="Acces denied")
    logger.info(f"User token refresh: {token_jwt}")
    return signJWT(token["user_id"])


@router.get("/user", response_model=UserPublic, status_code=status.HTTP_200_OK)
async def get_user(
    token: str = Depends(api_key_header),
    db: Session = Depends(get_db),
):
    """
    Get user information
    """
    blacklist = blacklist_check(token, db)
    token_jwt = decodeJWT(token)
    if not token_jwt:
        raise HTTPException(status_code=401, detail="Acces denied")
    user = db.query(User).filter(User.username == token_jwt["user_id"]).first()
    logger.info(f"Get user info: {user.id, user.username}")
    return user


@router.delete("/user/{id}", status_code=status.HTTP_204_NO_CONTENT)
async def user_delete(
    id: int, token: str = Depends(api_key_header), db: Session = Depends(get_db)
):
    """
    Delete user by id
    """
    blacklist = blacklist_check(token, db)
    token_jwt = decodeJWT(token)
    if not token_jwt:
        raise HTTPException(status_code=401, detail="Acces denied")
    user_to_delete = (
        db.query(User)
        .filter(User.username == token_jwt["user_id"], User.id == id)
        .first()
    )
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="Id not found")
    logging.info(f"User delete : {user_to_delete.id, user_to_delete.username}")
    db.delete(user_to_delete)
    db.commit()
    return "ok"
