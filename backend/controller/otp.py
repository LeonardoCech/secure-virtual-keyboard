import pyotp
import re
from datetime import datetime
from model.constants import HOTP_TTL


def get_current_timestamp():
    return int(datetime.now().timestamp())


def validate_6_digit_code(code):
    # Define the regex pattern for a 6-digit numeric code
    pattern = re.compile(r'^\d{6}$')
    # Use the pattern to match the provided code
    match = pattern.match(code)
    # Return True if the code matches the pattern, otherwise False
    return bool(match)


def generate_totp():
    """
    Generate a Time-based One-Time Password (TOTP) using a random base32 string.

    Returns:
        str: The generated TOTP as a random base32 string.
    """
    return pyotp.random_base32()


def verify_totp(informed_token: str, user_totp_secret: str):
    """
    Verifies a Time-Based One-Time Password (TOTP) using the provided informed token and user MFA secret.

    Args:
        informed_token (str): The informed TOTP code.
        user_totp_secret (str): The user's secret key for multi-factor authentication.

    Returns:
        bool: True if the code matches the pattern, otherwise False.
    """
    totp = pyotp.TOTP(user_totp_secret)

    # print(totp.now(), informed_token)

    return totp.verify(informed_token)


def validate_totp(code):
    """
    Validates a Time-Based One-Time Password (TOTP) code.

    Args:
        code (str): The TOTP code to validate.

    Returns:
        bool: True if the code matches the pattern, otherwise False.
    """
    return validate_6_digit_code(code)


def generate_hotp():
    """
    Generate a HMAC-based One-Time Password (HOTP) using a random base32 string.

    Returns:
        str: The generated HOTP as a random base32 string.
    """
    return pyotp.random_base32()


def get_hotp_code(user_hotp_secret: str, counter: int = get_current_timestamp(), return_new_counter: bool = True):
    """
    Generate a HMAC-based One-Time Password (HOTP) using a random base32 string.

    Args:
        user_hotp_secret (str): The user's secret key for multi-factor authentication.

    Returns:
        str: The generated HOTP as a random base32 string.
        int: The due timestamp in seconds.
    """
    hotp = pyotp.HOTP(user_hotp_secret)

    if return_new_counter:
        new_counter = get_current_timestamp()
        return hotp.at(count=new_counter), new_counter
    else:
        return hotp.at(count=counter)


def verify_hotp(informed_token: str, user_hotp_secret: str, user_hotp_counter: int = 0):
    """
    Verifies a HMAC-Based One-Time Password (HOTP) using the provided informed token and user MFA secret.

    Args:
        informed_token (str): The token entered by the user.
        user_hotp_secret (str): The user's secret key for multi-factor authentication.

    Returns:
        bool: True if the informed token is valid, False otherwise.
    """
    if (get_current_timestamp() - user_hotp_counter) >= HOTP_TTL:
        return False

    hotp = pyotp.HOTP(user_hotp_secret)
    return hotp.verify(informed_token, counter=user_hotp_counter)


def validate_hotp(code):
    """
    Validates a HMAC-Based One-Time Password (HOTP) code.

    Args:
        code (str): The HOTP code to validate.

    Returns:
        bool: True if the code matches the pattern, otherwise False.
    """
    return validate_6_digit_code(code)
