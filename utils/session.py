import os
import uuid
import jwt as pyjwt
from flask import jsonify
from datetime import datetime, timedelta
from db.redis_operations import redis_client
from utils.helpers import green, reset


SESSION_KEY = os.getenv("SESSION_KEY")


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
    token = pyjwt.encode(payload, SESSION_KEY, algorithm="HS256")
    return token


def verify_jwt(token):

    try:
        decoded_token = pyjwt.decode(token, SESSION_KEY, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Token has expired."}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"success": False, "message": "Invalid token."}), 401
