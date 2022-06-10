import time
import logging
import sys
from typing import Dict

from fastapi import APIRouter, Body, status, Depends, HTTPException, Header, Body
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import jwt
from typing import Optional

import jwt
from decouple import config

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


@router.get("/test")
def test():
    return "Hey you!"


@router.post("/registration")
async def user_registration():
    """
    New user registration
    """


@router.post("/login")
async def user_login():
    """
    Login existing user
    """


@router.post("/logout")
async def exit_user():
    """
    Exit user
    """


@router.post("/refresh_jwt")
async def refresh_token():
    """
    Refresh use token
    """


@router.get("/user")
async def get_user():
    """
    Get user information
    """
