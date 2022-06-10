import time
from typing import Dict

import jwt
from decouple import config

JWT_SECRET = config("secret")
JWT_ALGORITHM = config("algorithm")


def check_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Check user in db
    """
    try:
        user_db = db.query(User).filter(User.login == user.login).first()
        varify_password = pwd_context.verify(user.password, user_db.password)
        if user_db and varify_password:
            return True
        return False
    except:
        False


def token_response(token: str):
    return {"access_token": token}


def signJWT(user_id: str) -> Dict[str, str]:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token_response(token)


def decodeJWT(token: str):
    try:
        decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else False
    except:
        return False


def transferJWT(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "expires": time.time() + 300
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token
