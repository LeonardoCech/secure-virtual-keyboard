import json
from io import BytesIO
from typing_extensions import Annotated
from pydantic import EmailStr

# FastAPI Packages
from fastapi.security import OAuth2PasswordBearer
from fastapi import APIRouter, Depends, Header, Response, HTTPException, status
from fastapi.responses import JSONResponse

# Firebase Packages
from firebase_admin import auth, exceptions, firestore
from firebase_admin.exceptions import FirebaseError, NotFoundError, UnavailableError

# Own packages
from model.constants import *
from model.models import *

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='api/v1/user/sign/in')


@router.get('/me')
def get_user_me_v1(token: Annotated[str, Depends(oauth2_scheme)], response: Response):
    '''
    Get the own user metadata by the JWT.

    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger
    TODO(Developer): Add Pytests to test this endpoint

    #### Tests:
    ./tests/app/v1/user/me/test_api_get_user_me.py

    #### Args:
    - **token (str)**: The JWT token, it's taken from the 'Authorization' header.
    '''
    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:
        _, decoded_token = decode_token(token)

        db = firestore.client()

        email = decoded_token['sub']
        user = auth.get_user_by_email(email)

        user_data = db.collection('metadata').document(
            user.uid).get().to_dict()
        user_data['uid'] = user.uid

        del user_data['uid'],
        del user_data['email_verified'],
        del user_data['last_login'],
        del user_data['last_token_refresh'],
        del user_data['updated_at']

        user_wallet = db.collection('wallet').document(user.uid).get().to_dict()

        user_data['wallet'] = user_wallet

        user_oauth = db.collection('oauth').document(
            user.email).get().to_dict()

        user_data['mfa_auth_app'] = user_oauth['mfa_auth_app']

        return user_data
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.patch('/me')
def patch_user_me_v1(token: Annotated[str, Depends(oauth2_scheme)], doc_metadata: UserSettingsModel, response: Response):
    '''
    Updates the own user document in the 'metadata' collection, in Firebase Firestore.

    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger
    TODO(Developer): Add Pytests to test this endpoint

    #### Tests:
    ./tests/app/v1/user/me/test_api_patch_user_me.py

    #### Args:
    - **user (UserSettingsModel)**: The user object to be created.
    '''
    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:

        _, decoded_token = decode_token(token)

        user = auth.get_user_by_email(decoded_token['sub'])

        db = firestore.client()

        user_metadata = db.collection('metadata').document(user.uid)
        user_wallet = db.collection('wallet').document(user.uid)
        user_oauth = db.collection('oauth').document(user.email)

        doc_metadata = {key: value for key, value in doc_metadata.__dict__.items()
                        if value is not None}
        doc_wallet = dict()
        doc_oauth = dict()

        if ('wallet' in doc_metadata):
            doc_wallet = doc_metadata['wallet']
            del doc_metadata['wallet']

        if ('mfa_auth_app' in doc_metadata):
            doc_oauth['mfa_auth_app'] = doc_metadata['mfa_auth_app']
            del doc_metadata['mfa_auth_app']

        if len(doc_metadata) == 0:
            response.status_code = status.HTTP_400_BAD_REQUEST
            return HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    'message': 'Nothing to update, body is empty',
                    'type': 'BadRequest'
                }
            )

        if 'role' in doc_metadata:
            doc_metadata['role'] = doc_metadata['role'].value

            user_current_role = user_metadata.get().to_dict()['role']

            if user_current_role != 'ADMIN' and doc_metadata['role'] == 'ADMIN':
                response.status_code = status.HTTP_403_FORBIDDEN
                return HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        'message': 'User cannot set his own role to \'ADMIN\'.',
                        'type': 'Forbidden'
                    }
                )

        doc_metadata['updated_at'] = get_token_iat()

        user_metadata.update(doc_metadata)

        if len(doc_wallet) > 0:
            user_wallet.update(doc_wallet)

        if len(doc_oauth) > 0:
            user_oauth.update(doc_oauth)

        return user_metadata.get().to_dict()
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.get('/me/validate/mfa', status_code=status.HTTP_308_PERMANENT_REDIRECT)
async def get_user_me_validate_mfa_v1(token: Annotated[str, Depends(oauth2_scheme)],
                                      response: Response, oauthmfa: Annotated[str | None, Header()] = None, mfa_type: MfaTypes = MfaTypes.totp):
    '''
    Validate the MFA secret for the authenticated user.

    Parameters:
    - token: The authentication token for the user. (str)
    - form_data: The form data containing the MFA check request. (MFACheckRequestForm)
    - response: The HTTP response object. (Response)

    Returns:
    - An HTTP redirect response with the appropriate status code, or
    - An HTTP exception with the appropriate status code and detail message.

    Raises:
    - FirebaseError: If there is an error with the Firebase API.

    Note:
    - This function assumes that the user is authenticated.
    - The MFA secret is retrieved from the Firestore database.
    - The MFA code is verified using the user's MFA secret.
    - If the MFA code is invalid, an HTTP exception is raised.
    - If the token is invalid or expired, an HTTP exception is raised.
    - If there is an error with the Firebase API, an HTTP exception is raised.
    '''

    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:

        if mfa_type == MfaTypes.totp and not validate_totp(oauthmfa):
            status_code = status.HTTP_401_UNAUTHORIZED
            response.status_code = status_code
            return HTTPException(
                status_code=status_code,
                detail={
                    'message': f'Invalid MFA code format. Expected 6 digits string. Got: \'{oauthmfa}\'',
                    'type': 'InvalidMFAFormat'
                }
            )
        elif mfa_type == MfaTypes.hotp and not validate_hotp(oauthmfa):
            status_code = status.HTTP_401_UNAUTHORIZED
            response.status_code = status_code
            return HTTPException(
                status_code=status_code,
                detail={
                    'message': f'Invalid MFA code format. Expected 6 digits string. Got: \'{oauthmfa}\'',
                    'type': 'InvalidMFAFormat'
                }
            )

        try:
            _, decoded_token = decode_token(token)

            db = firestore.client()

            # Get user data from Firebase Authentication
            user = auth.get_user_by_email(decoded_token['sub'])

            user_oauth_doc = db.collection('oauth').document(user.email)

            user_oauth = user_oauth_doc.get().to_dict()

            if mfa_type == MfaTypes.totp and user_oauth and 'totp_secret' in user_oauth:
                if not verify_totp(oauthmfa, user_oauth['totp_secret']):
                    status_code = status.HTTP_401_UNAUTHORIZED
                    response.status_code = status_code
                    return HTTPException(
                        status_code=status_code,
                        detail={
                            'message': 'Invalid MFA code.',
                            'type': 'InvalidMFA'
                        }
                    )
            elif mfa_type == MfaTypes.hotp and user_oauth and 'hotp_secret' in user_oauth:
                verify_hotp_success = verify_hotp(oauthmfa, user_oauth['hotp_secret'], user_oauth['hotp_counter'])
                if not verify_hotp_success:
                    status_code = status.HTTP_401_UNAUTHORIZED
                    response.status_code = status_code
                    return HTTPException(
                        status_code=status_code,
                        detail={
                            'message': 'Invalid MFA code.',
                            'type': 'InvalidMFA'
                        }
                    )
            if (mfa_type == MfaTypes.hotp):
                user_metadata = db.collection('metadata').document(user.uid)
                user_metadata.update({
                    'email_verified': True
                })
            if stts_code == status.HTTP_200_OK:
                return JSONResponse(content={
                    'success': True,
                    'code': oauthmfa
                })
            else:
                response.status_code = stts_code
                return HTTPException(
                    status_code=stts_code,
                    detail={
                        'message': msg,
                        'type': e_type
                    }
                )
        except exceptions.FirebaseError as error:
            stts_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.status_code = stts_code
            return HTTPException(
                status_code=stts_code,
                detail={
                    'message': str(error),
                    'type': type(error).__name__
                }
            )
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.get('/me/validate/token')
def get_user_me_validate_token_v1(token: Annotated[str, Depends(oauth2_scheme)], response: Response):
    '''
    Check if user has a valid token. If token is valid, refreshes it and return a new token.
    Check if user has validated their email. If they have, update the 'metadata' collection and Token data.

    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger

    #### Tests:
    ./tests/app/v1/user/token/test_api_get_user_me_validate_token.py

    #### Args:
    - **token (str)**: The JWT token, it's taken from the 'Authorization' header.
    '''

    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:
        # There is no need to validate decode success if validate_token already returned success
        _, decoded_token = decode_token(token)

        if 'uid' not in decoded_token:
            return JSONResponse(
                content={
                    'access_token': token,
                    'temp_token': True,
                    'token_type': 'Bearer',
                    'valid': True
                }
            )

        user = auth.get_user(decoded_token['uid'])

        db = firestore.client()
        user_metadata = db.collection('metadata').document(user.uid)
        user_oauth = db.collection('oauth').document(user.email)

        if user.email_verified:
            user_metadata.update({
                'last_token_refresh': get_token_iat()
            })

        user_metadata_dict = user_metadata.get().to_dict()
        user_oauth_dict = user_oauth.get().to_dict()

        user_data = {
            'fullname': user_metadata_dict['fullname'],
            'role': user_metadata_dict['role'],
            'mfa_auth_app': user_oauth_dict['mfa_auth_app']
        }

        refresh_success, e_type, token = refresh_access_token(
            token, data=user_data)

        if refresh_success:
            return JSONResponse(
                content={
                    'access_token': token,
                    'token_type': 'Bearer',
                    'valid': refresh_success
                }
            )
        else:
            stts_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.status_code = stts_code
            return HTTPException(
                status_code=stts_code,
                detail={
                    'message': f'JWT Refresh Exception: {str(token)}',
                    'type': e_type
                }
            )
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.get('/{email}')
def get_user_v1(token: Annotated[str, Depends(oauth2_scheme)], email: EmailStr, response: Response):
    '''
    Get a specific user metadata by the JWT. Requester must have the 'admin' role.

    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger
    TODO(Developer): Add Pytests to test this endpoint

    #### Tests:
    ./tests/app/v1/user/test_api_get_user.py

    #### Args:
    - **token (str)**: The JWT token, it's taken from the 'Authorization' header.
    '''
    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:

        _, decoded_token = decode_token(token)

        db = firestore.client()

        user = auth.get_user_by_email(email)
        requester = auth.get_user_by_email(decoded_token['sub'])

        requester_current_role = db.collection('metadata').document(
            requester.uid).get().to_dict()['role']

        if requester_current_role != 'ADMIN':
            response.status_code = status.HTTP_403_FORBIDDEN
            return HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    'message': 'User must have the \'admin\' role to perform this action.',
                    'type': 'Forbidden'
                }
            )

        user_data = db.collection('metadata').document(
            user.uid).get().to_dict()
        user_data['uid'] = user.uid

        user_wallet = db.collection('wallet').document(user.uid).get().to_dict()
        user_data['wallet'] = user_wallet

        return user_data
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.patch('/{email}')
def patch_user_v1(token: Annotated[str, Depends(oauth2_scheme)], email: EmailStr, doc_metadata: UserSettingsModel, response: Response):
    '''
    Updates a specific user document in the 'metadata' collection, in Firebase Firestore. Requester must have the 'admin' role.

    TODO(Developer): Finish API to update user
    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger
    TODO(Developer): Add Pytests to test this endpoint

    #### Tests:
    ./tests/app/v1/user/test_api_patch_user.py

    #### Args:
    - **email (str)**: The email address of the user.
    - **user (UserSettingsModel)**: The user object to be created.
    '''
    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:

        _, decoded_token = decode_token(token)

        db = firestore.client()

        user = auth.get_user_by_email(email)

        user = auth.get_user_by_email(email)
        requester = auth.get_user_by_email(decoded_token['sub'])

        requester_current_role = db.collection('metadata').document(
            requester.uid).get().to_dict()['role']

        if requester_current_role != 'ADMIN':
            response.status_code = status.HTTP_403_FORBIDDEN
            return HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    'message': 'User must have the \'admin\' role to perform this action.',
                    'type': 'Forbidden'
                }
            )

        doc_metadata = {key: value for key, value in doc_metadata.__dict__.items()
                        if value is not None}
        doc_wallet = dict()
        doc_oauth = dict()

        if 'role' in doc_metadata:
            doc_metadata['role'] = doc_metadata['role'].value

        user_metadata = db.collection('metadata').document(user.uid)
        user_wallet = db.collection('wallet').document(user.uid)
        user_oauth = db.collection('oauth').document(user.email)

        if ('mfa_auth_app' in doc_metadata):
            doc_oauth['mfa_auth_app'] = doc_metadata['mfa_auth_app']
            del doc_metadata['mfa_auth_app']

        user_metadata.update(doc_metadata)

        if len(doc_wallet) > 0:
            user_wallet.update(doc_wallet)

        if len(doc_oauth) > 0:
            user_oauth.update(doc_oauth)

        return user_metadata.get().to_dict()
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.get('/{email}/mfa/qr-code')
async def get_user_mfa_qr_code_v1(email: EmailStr, response: Response):
    '''
        Generate a QR code for the user's MFA configuration.

        :param email: The email of the user.
        :type email: EmailStr
        :param response: The response object to return the QR code image.
        :type response: Response
        :return: The response object with the QR code image.
        :rtype: Response
        '''
    # Generate TOPT and HOTP
    totp_secret = generate_totp()
    hotp_secret = generate_hotp()

    otp_type = 'totp'
    issuer = 'Smart Trade'
    config_uri = f'otpauth://{otp_type}/{issuer}:{email}?secret={totp_secret}&issuer={issuer}'

    # Generate QR code
    img = qrcode.make(config_uri)

    # Save the image to a BytesIO buffer
    buffer = BytesIO()
    img.save(buffer)

    # Get the bytes from the buffer
    image_bytes = buffer.getvalue()

    # Close the buffer
    buffer.close()

    db = firestore.client()

    user_oauth = db.collection('oauth').document(email).get().to_dict()

    if user_oauth is None:
        db.collection('oauth').document(email).set({
            'hotp_counter': get_current_timestamp(),
            'hotp_secret': hotp_secret,
            'totp_secret': totp_secret,
            'totp_uri': config_uri,
            'mfa_auth_app': False
        })

    # Return the image bytes as a response
    response = Response(content=image_bytes, media_type='image/png')
    return response


@router.get('/{email}/send/email')
def get_user_send_email_v1(email: EmailStr, response: Response, lang: str = 'en-US'):
    '''
    Send and email with a MFA code to verify the user's email address and his integrity.

    TODO(Developer): Finish API to send email to verify user email address.
    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger
    TODO(Developer): Add Pytests to test this endpoint

    #### Tests:
    ./tests/app/v1/user/send/email/test_api_get_user_send_email.py

    #### Args:
    - **email (str)**: The email address of the user.
    - **lang (str, optional): The language of the email. Defaults to 'en-US'.
    '''
    try:
        # auth.get_user_by_email(email)  # If the user doesn't exist, raises NotFoundError

        db = firestore.client()

        user_oauth_doc = db.collection('oauth').document(email)
        user_oauth = user_oauth_doc.get().to_dict()

        if user_oauth is not None:

            user_hotp_secret = user_oauth.get('hotp_secret')
            user_hotp_code, user_hotp_counter = get_hotp_code(user_hotp_secret, user_oauth['hotp_counter'])

            user_oauth_doc.update({
                'hotp_counter': user_hotp_counter
            })

            send_email(
                api_key=SENDGRID_API_KEY,
                lang=lang,
                subject='[Smart Trade] Your verification Code',
                to_emails=email,
                hotp_code=user_hotp_code
            )

        return JSONResponse(content={
            'message': 'If the user exists, a verification code has been sent to his email'
        })
    except FirebaseError as error:

        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        # If the user doesn't exist
        if isinstance(error, NotFoundError):
            return JSONResponse(content={
                'message': 'If the user doesn\'t exist, a verification code has been sent to his email'
            })

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


@router.get('/{email}/send/phone', status_code=status.HTTP_501_NOT_IMPLEMENTED)
def get_user_send_phone_v1(token: Annotated[str, Depends(oauth2_scheme)], email: EmailStr, response: Response):
    '''
    Creates a new user in the Firebase Auth.
    Creates a new document in the 'metadata' collection, in Firebase Firestore.

    TODO(Developer): API to verify phone number
    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger
    TODO(Developer): Add Pytests to test this endpoint

    #### Tests:
    ./tests/app/v1/user/send/phone/test_api_get_user_send_phone.py

    #### Args:
    - **email (str)**: The email address of the user.
    '''

    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:
        return JSONResponse(content={
            'message': 'User must check phone to verify your account'
        })
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.get('/{email}/sign/temp-token')
def post_user_sign_temp_token_v1(email: EmailStr, response: Response):

    now = get_token_iat()

    token_data = {
        'iss': Services.users_service.value,
        'sub': email,
        'iat': now,
        'exp': get_token_exp(now),
        'secure_hash': generate_token_hash(email)
    }

    create_token_success, token = create_access_token(data=token_data, algorithm=TEMP_TOKEN_ALGORITHM)

    if create_token_success:
        return JSONResponse(content={
            'access_token': token,
            'token_type': 'Bearer'
        })
    else:
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        response.status_code = status_code
        return HTTPException(
            status_code=status_code,
            detail={
                'message': str(token),
                'type': type(token).__name__
            }
        )


@router.patch('/sign/in')
def patch_users_sign_in_v1(token: Annotated[str, Depends(oauth2_scheme)], form_data: Annotated[SigninPatchRequestForm, Depends()], response: Response):
    '''
    Update the user password on Firebase Authentication.
    Updates the user metadata to set the last login date.

    TODO(Developer): Add possibilities to signin with other priveders (Apple, Google etc.)
    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger

    #### Tests:
    ./tests/app/v1/user/sign/in/test_api_patch_user_sign_in.py

    #### Args:
    - **form_data (SigninPatchRequestForm)**: The user credentials to be validated.
    '''

    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:

        _, decoded_token = decode_token(token)

        db = firestore.client()

        try:
            # Get user data from Firebase Authentication
            user = auth.get_user_by_email(decoded_token['sub'])

            user_data = db.collection('metadata').document(
                user.uid).get().to_dict()

            if user_data is None:
                response.status_code = status.HTTP_404_NOT_FOUND
                return HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        'message': 'User not found.',
                        'type': 'UserNotFoundError'
                    }
                )

            auth.update_user(
                user.uid,
                password=form_data.password.get_secret_value()
            )

            now = get_token_iat()

            db.collection('metadata').document(user.uid).update({
                'updated_at': now
            })

            return JSONResponse(content={
                'message': f'User\'s password updated',
                'type': 'OK'
            })

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
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


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

    db = firestore.client()

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

        user_data = db.collection('metadata').document(
            user.uid).get().to_dict()

        if user_data is None:
            response.status_code = status.HTTP_404_NOT_FOUND
            return HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    'message': 'User not found.',
                    'type': 'UserNotFoundError'
                }
            )

        # Get user metadata from Firebase Firestore
        user_oauth = db.collection('oauth').document(
            user.email).get().to_dict()

        user_email = form_data.username

        token_data = {
            'fullname': user_data['fullname'],
            'role': user_data['role'],
            'mfa_auth_app': user_oauth['mfa_auth_app'],
        }

        now = get_token_iat()

        token_dict = {
            'iss': Services.users_service.value,
            'sub': user_email,
            'uid': user.uid,
            'data': json.dumps(token_data),
            'iat': now,
            'exp': get_token_exp(now),
            'secure_hash': generate_token_hash(user.uid)
        }

        create_token_success, token = create_access_token(data=token_dict)

        if create_token_success:
            try:
                db.collection('metadata').document(user.uid).update({
                    'last_login': now,
                    'last_token_refresh': now
                })
                return JSONResponse(content={
                    'access_token': token,
                    'token_type': 'Bearer',
                    'first_login': 'last_login' not in user_data
                })
            except Exception as error:

                print(f'Failed to save user data: {str(error)}')

                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
                response.status_code = status_code
                return HTTPException(
                    status_code=status_code,
                    detail={
                        'message': str(error),
                        'type': type(error).__name__
                    }
                )
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.status_code = status_code
            return HTTPException(
                status_code=status_code,
                detail={
                    'message': str(token),
                    'type': type(token).__name__
                }
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


@router.post('/sign/out')
def post_user_sign_out_v1(token: Annotated[str, Depends(oauth2_scheme)], response: Response):
    '''
        Handles the POST request to /user/sign/out endpoint.
    Invalidates the JWT.

    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger

    #### Tests:
    ./tests/app/v1/user/sign/out/test_api_post_user_sign_out.py

    #### Args:
    - **token (str)**: The JWT token, it's taken from the 'Authorization' header.
        '''
    stts_code, e_type, msg = validate_token(token)

    if stts_code == status.HTTP_200_OK:
        refresh_success, e_type, token = refresh_access_token(
            token, invalidate=True)

        if refresh_success:
            return JSONResponse(content={
                'access_token': token,
                'message': 'Successfully signed out',
                'token_type': 'Bearer'
            })
        else:
            stts_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.status_code = stts_code
            return HTTPException(
                status_code=stts_code,
                detail={
                    'message': 'Failed to sign out',
                    'type': e_type
                }
            )
    else:
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': msg,
                'type': e_type
            }
        )


@router.post('/sign/up', status_code=status.HTTP_201_CREATED)
def post_user_sign_up_v1(form_data: Annotated[SignupPostRequestForm, Depends()], response: Response):
    '''
    Creates a new user in the Firebase Auth.
    Creates a new document in the 'metadata' collection, in Firebase Firestore.

    TODO(Developer): Add possibilities to signup with other priveders (Apple, Google etc.)
    TODO(Developer): Add validation to don't validate users that are enabled
    TODO(Developer): Add validation to don't validate users that have email address verified
    TODO(Developer): Add erros examples on Swagger

    #### Tests:
    ./tests/app/v1/user/sign/up/test_api_post_user_sign_up.py

    #### Args:
    - **form_data (SignupPostRequestForm)**: The user credentials to be validated.
    '''
    form_data.password = UserModel.dump_secret(form_data.password)

    def save_user_data(form_data, result):

        try:
            db = firestore.client()

            now = get_token_iat()

            user_data = {
                'username': form_data.username,
                'fullname': form_data.fullname,
                'disabled': USER_MODEL_DISABLED_DEFAULT,
                'email_verified': USER_MODEL_EMAIL_VERIFIED_DEFAULT,
                'role': Roles.free_trial.value,
                'created_at': now,
                'updated_at': now
            }
            db.collection('metadata').document(
                result.uid).set(user_data)

            user_wallet = {'items': [{'symbol': 'BTC', 'name': 'Bitcoin', 'inWallet': True, 'type': 'crypto'}]}

            db.collection('wallet').document(
                result.uid).set(user_wallet)

            # Check if not exists a document in the 'oauth' collection
            if not db.collection('oauth').document(form_data.username).get().exists:
                db.collection('oauth').document(
                    form_data.username).set({
                        'hotp_counter': get_current_timestamp(),
                        'hotp_secret': generate_hotp(),
                        'mfa_auth_app': form_data.mfa_auth_app
                    })
            else:
                db.collection('oauth').document(
                    form_data.username).update({
                        'mfa_auth_app': form_data.mfa_auth_app
                    })

            return True, 'Success'

        except Exception as error:

            print(f'Failed to save user data: {str(error)}')

            return False, error

    try:
        result = auth.create_user(
            email=form_data.username, password=form_data.password)

        db_success, db_result = save_user_data(form_data, result)

        if not db_success:
            stts_code = status.HTTP_500_INTERNAL_SERVER_ERROR
            response.status_code = stts_code
            return HTTPException(
                status_code=stts_code,
                detail={
                    'type': str(db_result),
                    'message': 'User could not be created'
                }
            )

        response.status_code = status.HTTP_201_CREATED
        return JSONResponse(content={
            'message': f'Successfully created user {result.uid}'},
        )
    except exceptions.AlreadyExistsError as error:
        stts_code = status.HTTP_409_CONFLICT
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': str(error),
                'type': type(error).__name__
            }
        )
    except exceptions.FirebaseError as error:
        stts_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        response.status_code = stts_code
        return HTTPException(
            status_code=stts_code,
            detail={
                'message': str(error),
                'type': type(error).__name__
            }
        )
