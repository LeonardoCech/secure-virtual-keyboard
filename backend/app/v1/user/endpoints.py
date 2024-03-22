import json
from typing_extensions import Annotated

# FastAPI Packages
from fastapi.security import OAuth2PasswordBearer
from fastapi import APIRouter, Depends, Response, HTTPException, status
from fastapi.responses import JSONResponse

# Firebase Packages
from firebase_admin.exceptions import FirebaseError, NotFoundError, UnavailableError

# Own packages
from controller.firebase import sign_in_with_password
from model.constants import *
from model.models import *

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='api/v1/user/sign/in')

@router.post('/sign/in')
def post_users_sign_in_v1(form_data: Annotated[SigninPostRequestForm, Depends()], response: Response):
    '''
    Generates a valid JWT Token for a user.
    Updates the user metadata to set the last login date.

    TODO(Developer): Add possibilities to signin with other priveders (Apple, Google etc.)
    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger

    #### Tests:
    ./tests/app/v1/user/sign/in/test_api_post_user_sign_in.py

    #### Args:
    - **form_data (SigninPostRequestForm)**: The user credentials to be validated.
    '''

    try:
        # Get user data from Firebase Authentication
        firebase_user = sign_in_with_password(form_data.username, form_data.password.get_secret_value(), FIREBASE_API_KEY)

        if firebase_user is None:
            response.status_code = status.HTTP_400_BAD_REQUEST
            return HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    'message': 'Invalid email or password',
                    'type': 'InvalidCredentials'
                }
            )

        user = UserFirebase()
        user.uid = firebase_user['localId']
        user.email = firebase_user['email']

        return JSONResponse(
            content = user.__dict__,
            status_code = status.HTTP_200_OK
        )

    except FirebaseError as error:

        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        # If the user doesn't exist
        if isinstance(error, NotFoundError):
            status_code = status.HTTP_404_NOT_FOUND

        # If the Firebase service is unavailable
        if isinstance(error, UnavailableError):
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE

        response.status_code = status_code
        return HTTPException(
            status_code=status_code,
            detail={
                'message': str(error),
                'type': type(error).__name__
            }
        )
    except ValueError as error:

        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        response.status_code = status_code
        return HTTPException(
            status_code=status_code,
            detail={
                'message': str(error),
                'type': type(error).__name__
            }
        )
