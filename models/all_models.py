# Models for checking data input
from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class RegisterModel(BaseModel):
    name: str = Field(..., min_length=3)
    email: EmailStr
    password: str = Field(..., min_length=4)
    sec_password: str = Field(..., min_length=4)
