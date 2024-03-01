import re
from pydantic import BaseModel, SecretStr, EmailStr, field_serializer
from fastapi import Form
from enum import Enum
from typing_extensions import Annotated, Optional

from model.constants import *


class Services(Enum):
    users_service = 'https://users.we-bronx.io'
    smart_trade = 'https://app.we-bronx.io'


class MfaTypes(Enum):
    totp = 'TOTP'
    hotp = 'HOTP'


class Roles(Enum):
    admin = 'ADMIN'
    free_trial = 'Free Trial'


class UserFirebase:
    uid: str
    email: str


class UserModel(BaseModel):

    fullname: str = Form(...)
    email: EmailStr = Form(...)
    password: SecretStr = Form(...)
    role: Roles = Form(default=Roles.free_trial)
    oauthmfa: bool = Form(default=USER_MODEL_OAUTHMFA_DEFAULT)

    @field_serializer('password', when_used='json')
    def dump_secret(v):
        """
        Decorator that serializes the 'password' field when used in JSON format.

        :param v: The value of the 'password' field.
        :type v: Any

        :return: The secret value of the 'password' field.
        :rtype: Any
        """
        return v.get_secret_value()

    def validate(self):
        """
        Validates the model instance.
        """
        self.validate_fullname()
        self.validate_password()

    def validate_fullname(self):
        """
        Validates the 'fullname' field.
        """

        if not isinstance(self.fullname, str):
            return False, f'Fullname must be a <class \'str\'> instance. Got {type(self.fullname)}'

        v = self.fullname

        if len(v) < USER_MODEL_FULLNAME_LENGTH_MIN:
            return False, f'Fullname must be at least {USER_MODEL_FULLNAME_LENGTH_MIN} characters long. Got {len(v)} characters.'

        if len(v) > USER_MODEL_FULLNAME_LENGTH_MAX:
            return False, f'Fullname must be at most {USER_MODEL_FULLNAME_LENGTH_MAX} characters long. Got {len(v)} characters.'

        return True, 'Valid fullname.'

    def validate_password(self):
        """
        Validates the 'password' field.
        """

        if not isinstance(self.password, SecretStr):
            return False, f'Password must be a <class \'SecretStr\'> instance. Got {type(self.password)}'

        v = self.password.get_secret_value()

        if len(v) < USER_MODEL_PASSWORD_LENGTH_MIN:
            return False, f'Password must be at least {USER_MODEL_PASSWORD_LENGTH_MIN} characters long. Got {len(v)} characters.'

        if len(v) > USER_MODEL_PASSWORD_LENGTH_MAX:
            return False, f'Password must be at most {USER_MODEL_PASSWORD_LENGTH_MAX} characters long. Got {len(v)} characters.'

        if not re.match(USER_MODEL_PASSWORD_REGEX, v):
            return False, 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.'

        return True, 'Valid password.'

    def validate_email(self):
        """
        Validates the 'email' field.
        """

        if not isinstance(self.email, str):
            return False, f'Email must be a <class \'str\'> instance. Got {type(self.email)}'

        v = self.email

        if not re.match(USER_MODEL_EMAIL_REGEX, v):
            return False, 'Email must be a valid email address.'

        return True, 'Valid email.'


class UserSettingsModel(BaseModel):

    fullname: Optional[str] = None
    role: Optional[Roles] = None
    mfa_auth_app: Optional[bool] = None
    wallet: Optional[dict] = None


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


class SigninPatchRequestForm:
    def __init__(
        self,
        *,
        password: Annotated[SecretStr, Form()]
    ):
        """
        Initializes a new instance of the class.

        Args:
            password (SecretStr): The password for the instance.

        Returns:
            None
        """

        self.password = password


class SignupPostRequestForm:
    def __init__(
        self,
        *,
        username: Annotated[EmailStr, Form()],
        password: Annotated[SecretStr, Form()],
        fullname: Annotated[str, Form()],
        mfa_auth_app: Annotated[bool, Form()] = USER_MODEL_OAUTHMFA_DEFAULT
    ):
        """
        Initializes a new instance of the class.

        Args:
            username (EmailStr): The email for the instance.
            password (SecretStr): The password for the instance.
            fullname (str): The fullname for the instance.
            oauthmfa (bool): The oauthmfa for the instance.

        Returns:
            None
        """

        self.username = username
        self.password = password
        self.fullname = fullname
        self.mfa_auth_app = mfa_auth_app


class MFACheckRequestForm:
    def __init__(
        self,
        *,
        oauthmfa: Annotated[str, Form()] = ''
    ):
        """
        Initializes a new instance of the class.

        Args:
            oauthmfa (str): The user's 2FA token for the instance.

        Returns:
            None
        """
        self.oauthmfa = oauthmfa


class NewsQueryPeriods(Enum):
    today = 'today'
    week = 'week'
    month = 'month'
    year = 'year'
    all = 'all'
    query = 'query'
