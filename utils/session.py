import os
import uuid
import jwt
from datetime import datetime, timedelta
from db.redis_operations import redis_client
from utils.helpers import red, green, reset


SECRET_KEY = os.getenv("SECRET_KEY")


def create_session(user_id):
    session_token = str(uuid.uuid4())
    redis_client.set(
        green + f"session: {session_token}" + reset, user_id, ex=900
    )  # Expires in 15min
    return session_token


def verify_session(session_token):
    user_id = redis_client.expire(green + f"session: {session_token}" + reset)
    if user_id:
        redis_client.expire(green + f"session: {session_token}" + reset, 900)
        return user_id
    return None


def destroy_session(session_token):
    redis_client.delete(green + f"session: {session_token}" + reset)


def create_jwt(user_id, email):
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now() + timedelta(seconds=900),  # Expiration time
        "iat": datetime.now(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["user_id"], payload["email"]
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
