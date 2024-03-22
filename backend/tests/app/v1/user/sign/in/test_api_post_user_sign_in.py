from __init__ import app
import sys
import os
from fastapi import status
from fastapi.testclient import TestClient

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)


client = TestClient(app)

# TODO: Add more tests (for each error case)

def test_api_v1_post_user_sign_in_200_1(api_v1_user_sign_in):
    """
        Test the POST /user/sign/in endpoint with a valid request and expect a 200 OK response.

        USED TO AUTHENTICATING BASE USER

        :param api_v1_user_sign_in: The fixture for the API client and the necessary data for the request.
        :return: None
        """
    endpoint = api_v1_user_sign_in.copy()

    response = client.post(
        endpoint['route'],
        headers=endpoint['headers']['post'],
        data=endpoint['data']['post']
    )
    assert response.status_code == status.HTTP_200_OK