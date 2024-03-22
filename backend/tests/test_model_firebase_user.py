from pydantic import SecretStr
from model.models import UserModel
from model.constants import *
import unittest
import sys
import os
import pytest

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)


@pytest.mark.order(1)
class TestModelUserModel(unittest.TestCase):

    user = UserModel(
        fullname='',
        email='leonardo.cech@catolicasc.edu.br',
        password=SecretStr(''),
        oauthmfa=False
    )

    def test_validate_password_not_secretstr(self):
        '''
        Testing a not str password
        '''
        test_class = 'Model UserModel'
        test_name = 'Validate Password Not SecretStr'

        self.user.password = '314123'
        result, msg = self.user.validate_password()

        self.assertFalse(result)

    def test_validate_password_empty(self):
        '''
        Testing an empty password
        '''
        test_class = 'Model UserModel'
        test_name = 'Validate Password Empty'

        self.user.password = SecretStr('')
        result, msg = self.user.validate_password()

        self.assertFalse(result)

    def test_validate_password_not_set(self):
        '''
        Testing a not set password
        '''
        test_class = 'Model UserModel'
        test_name = 'Validate Password Not Set'

        self.user.password = None
        result, msg = self.user.validate_password()

        self.assertFalse(result)

    def test_validate_email_correct(self):
        '''
        Testing a valid email
        '''

        self.user.email = 'leonardo.cech@catolicasc.edu.br'
        result, msg = self.user.validate_email()

        self.assertTrue(result)

    def test_validate_email_invalid(self):
        '''
        Testing an invalid email
        '''
        test_class = 'Model UserModel'
        test_name = 'Validate Email Invalid'

        self.user.email = 'leonardo.cech'
        result, msg = self.user.validate_email()

        self.assertFalse(result)

    def test_validate_email_none(self):
        '''
        Testing an email that is None
        '''
        test_class = 'Model UserModel'
        test_name = 'Validate Email None'

        self.user.email = None
        result, msg = self.user.validate_email()

        self.assertFalse(result)

    def test_validate_email_not_str(self):
        '''
        Testing an email that is not a string
        '''
        test_class = 'Model UserModel'
        test_name = 'Validate Email Not String'

        self.user.email = 123
        result, msg = self.user.validate_email()

        self.assertFalse(result)
