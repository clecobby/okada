import boto3
import os

USER_POOL_ID = os.environ.get('USER_POOL_ID')
CLIENT_ID = os.environ.get('USER_POOL_CLIENT_ID')
cognito_client = boto3.client('cognito-idp')

def sign_up_user(email, password, name, role):
    response = cognito_client.sign_up(
        ClientId=CLIENT_ID,
        Username=email,
        Password=password,
        UserAttributes=[
            {'Name': 'email', 'Value': email},
            {'Name': 'name', 'Value': name},
            {'Name': 'custom:role', 'Value': role},
        ]
    )
    return response

def authenticate_user(email, password):
    response = cognito_client.initiate_auth(
        ClientId=CLIENT_ID,
        AuthFlow='USER_PASSWORD_AUTH',
        AuthParameters={
            'USERNAME': email,
            'PASSWORD': password
        }
    )
    return response['AuthenticationResult']
