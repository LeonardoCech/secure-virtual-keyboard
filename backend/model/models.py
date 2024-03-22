import re
from pydantic import SecretStr, EmailStr
from fastapi import Form
from typing_extensions import Annotated

from model.constants import *


class UserFirebase:
    uid: str
    email: str

class SigninPostRequestForm:
    def __init__(
        self,
        *,
        username: Annotated[EmailStr, Form()],
        password: Annotated[SecretStr, Form()]
    ):
        """
        Initializes a new instance of the class.

        Args:
            username (EmailStr): The email for the instance.
            password (SecretStr): The password for the instance.

        Returns:
            None
        """

        self.username = username
        self.password = password
