
from __init__ import app
import sys
import os
import pytest
from fastapi import status
from fastapi.testclient import TestClient

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root_dir)


client = TestClient(app)


@pytest.mark.order(1)
def test_server_constants_200_0(api_default_cors):

    response = client.options(
        api_default_cors['route'],
        headers=api_default_cors['headers'])
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}
