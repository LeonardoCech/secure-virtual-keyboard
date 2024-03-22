# Copyright (c) 2023 Bronx Co. | we-bronx.io
# This script is protected by copyright laws and cannot be reproduced, distributed,
# or used without written permission of the copyright owner.

# Contribuitors:
# - Cech <leonardo.cech@we-bronx.io> | Full Stack Developer
# - Braian <braian.zapelini@we-bronx.io> | Full Stack Developer

# System Packages
from fastapi.middleware.cors import CORSMiddleware

# FastAPI Packages
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
import requests
from app.v1.user.endpoints import router as api_v1_user_router

# Firebase Packages
import firebase_admin
from firebase_admin import credentials

# Own packages
from model.constants import *

# Constants
cred = credentials.Certificate(FIREBASE_CERTIFICATE_PATH)

default_app = firebase_admin.initialize_app(cred)

print(f'Firebase App: {default_app.project_id}')

app = FastAPI(
    openapi_url='/openapi-schema.json',
    swagger_ui_parameters={
        'defaultModelsExpandDepth': -1,
        'syntaxHighlight.theme': 'tomorrow-night'
    }
)

app.include_router(api_v1_user_router, prefix='/api/v1/user', tags=['User'])

# origins = json.loads(os.environ.get("ORIGINS_IP"))
origins = ["http://localhost", "http://localhost:4000", "http://127.0.0.1"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=['*'],
    allow_headers=['*']
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title='Secure Virtual Keyboard API',
        version='1.0.0',
        summary='Secure Virtual Keyboard API',
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@app.options('/')
async def cors_options():
    """
    A function that handles the CORS options request for the specified endpoint.

    #### Tests:
    ./tests/app/default/cors/test_api_default_cors.py

    #### Args:
    - None

    Returns:
        An empty dictionary.
    """
    return {}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='localhost', port=7000)
