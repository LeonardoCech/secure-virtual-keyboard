import hmac
import hashlib
import base64
import json
import pytz
from datetime import datetime, timedelta
from jose import JWTError, jwt
from model.constants import *

from fastapi import status


def get_token_iat():
    local_time = datetime.now()  # Get the current local time
    utc_timezone = pytz.utc  # Create a UTC timezone object
    iat = local_time.astimezone(utc_timezone)  # Convert the local time to UTC time

    return iat


def get_token_exp(iat=get_token_iat()):

    exp = iat + timedelta(seconds=TOKEN_EXPIRATION_TIME)

    return exp


def validate_token_hash(token_hash, uid):

    generated_hash = generate_token_hash(uid)

    return token_hash == generated_hash


def validate_token(token):

    try:
        decoded_success, decoded_token = decode_token(token)

        if decoded_success:

            if 'uid' not in decoded_token:
                return status.HTTP_200_OK, 'Success', 'Valid Temporary Token.'

            is_hash_valid = validate_token_hash(decoded_token['secure_hash'], decoded_token['uid'])

            is_ttl_valid = (decoded_token['exp'] - decoded_token['iat']) <= TOKEN_EXPIRATION_TIME

            if is_hash_valid and is_ttl_valid:
                return status.HTTP_200_OK, 'Success', 'Valid Token.'
            else:
                return status.HTTP_401_UNAUTHORIZED, 'Success', 'Invalid Token.'
        else:
            e_type = type(decoded_token).__name__

            if (e_type == 'ExpiredSignatureError'):
                return status.HTTP_401_UNAUTHORIZED, e_type, 'Expired Token.'

            return status.HTTP_500_INTERNAL_SERVER_ERROR, e_type, 'Failed to decode token.'

    except JWTError as e:
        e_type = type(e).__name__
        return status.HTTP_500_INTERNAL_SERVER_ERROR, e_type, f'JWT Error: {str(e)}'

    except ValueError as error:
        e_type = type(error).__name__
        return status.HTTP_500_INTERNAL_SERVER_ERROR, e_type, {'message': f'API Exception: {str(error)}'}


def generate_token_hash(uid):

    digest = hmac.new(TOKEN_HASH_SECRET, msg=uid.encode('utf-8'), digestmod=hashlib.sha256).digest()

    final_hash = base64.b64encode(digest).decode()

    return final_hash


def create_access_token(data: dict, algorithm=TOKEN_ALGORITHM):

    try:
        to_encode = data.copy()
        encoded_jwt = jwt.encode(to_encode, TOKEN_SECRET_KEY, algorithm=algorithm)

        return True, encoded_jwt

    except JWTError as e:
        return False, e


def decode_token(token: str):

    try:
        # Decode the JWT
        payload = jwt.decode(token, TOKEN_SECRET_KEY, algorithms=[TOKEN_ALGORITHM, TEMP_TOKEN_ALGORITHM])

        # The payload will contain the claims from the JWT
        return True, payload

    except JWTError as error:
        return False, error


def refresh_access_token(token, data=None, invalidate=False):

    try:
        success, decoded_token = decode_token(token)

        if success:
            new_token = decoded_token.copy()
            new_token['iat'] = get_token_iat()
            new_token['exp'] = get_token_exp(new_token['iat'])

            if data is not None:
                # Merge the new data with the existing token
                new_token['data'] = json.loads(new_token['data'])
                new_token['data'].update(data)
                new_token['data'] = json.dumps(new_token['data'])

            if invalidate:
                new_token['secure_hash'] = 'invalidated'

            success, token = create_access_token(data=new_token)
        else:
            token = decoded_token

        return success, 'Success', token

    except JWTError as error:
        e_type = type(error).__name__
        return False, e_type, error
