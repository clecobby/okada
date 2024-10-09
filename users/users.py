import json
import logging
from utils.cognito_utils import sign_up_user, authenticate_user

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    http_method = event['httpMethod']
    path = event['path']
    
    if http_method == 'POST' and '/signup' in path:
        return sign_up(event)
    elif http_method == 'POST' and '/login' in path:
        return login(event)
    else:
        logger.warning(f"Unhandled path: {path}")
        return {
            'statusCode': 404,
            'body': json.dumps({'message': 'Not Found'})
        }

def sign_up(event):
    body = json.loads(event['body'])
    email = body.get('email')
    password = body.get('password')
    name = body.get('name')
    role = body.get('role')
    logger.info(f"Attempting to signn up user: {email}")

    try:
        response = sign_up_user(email, password, name, role)
        logger.info(f"Sign up response for user: {response}")

        return {
            'statusCode': 201,
            'body': json.dumps({'message': 'User registered successfully'})
        }
    except Exception as e:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': str(e)})
        }

def login(event):
    body = json.loads(event['body'])
    email = body.get('email')
    password = body.get('password')
    logger.info(f"User login attempt: {email}")

    try:
        auth_result = authenticate_user(email, password)
        logger.info(f"Login results for user: {auth_result}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'access_token': auth_result['AccessToken'],
                'refresh_token': auth_result['RefreshToken'],
                'id_token': auth_result['IdToken'],
                'expires_in': auth_result['ExpiresIn'],
                'token_type': auth_result['TokenType']
            })
        }
    except Exception as e:
        logger.error(f"Login failed for user {email}: {str(e)}", exc_info=True)

        return {
            'statusCode': 401,
            'body': json.dumps({'error': str(e)})
        }
