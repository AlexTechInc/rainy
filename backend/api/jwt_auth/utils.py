import time
import jwt
from datetime import timedelta
from api.settings import JWT_ACCESS_TOKEN_TTL, JWT_REFRESH_TOKEN_TTL, SECRET_KEY
# from django.core.cache import caches 


# redis_cache = caches['default']


def jwt_payload_wrapper(data, token_type='access'):
    if not isinstance(data, dict):
        raise TypeError('data must be dict instance')
    
    if not isinstance(JWT_ACCESS_TOKEN_TTL, timedelta):
        raise TypeError('JWT_ACCESS_TOKEN_TTL must be timedelta instance')

    if not isinstance(JWT_REFRESH_TOKEN_TTL, timedelta):
        raise TypeError('JWT_REFRESH_TOKEN_TTL must be timedelta instance')
    
    if not token_type in ('access', 'refresh'):
        raise TypeError('token_type must be "access" or "refresh"')
    
    now = int(time.time())
    
    data['iat'] = now

    if token_type == 'access':
        data['exp'] = int(now + JWT_ACCESS_TOKEN_TTL.total_seconds())

    if token_type == 'refresh':
        data['exp'] = int(now + JWT_REFRESH_TOKEN_TTL.total_seconds())
        data['refresh'] = True


def jwt_encode(payload, *args, **kwargs):
    kwargs['key'] = SECRET_KEY
    
    return jwt.encode(payload, *args, **kwargs)


def jwt_decode(token, *args, **kwargs):
    kwargs['key'] = SECRET_KEY
    kwargs['algorithms'] = 'HS256'

    return jwt.decode(token, *args, **kwargs)


# def jwt_cache_token(token, expire_at, token_type='access'):
#     if not token_type in ('access', 'refresh'):
#         raise TypeError('token_type must be "access" or "refresh"')
    
#     cache_key = f'{token_type}_token:{token}'


def jwt_generate_tokens_pair(access_token_payload, refresh_token_payload):
    jwt_payload_wrapper(access_token_payload)
    jwt_payload_wrapper(refresh_token_payload, token_type='refresh')

    access_token = jwt_encode(access_token_payload)
    refresh_token = jwt_encode(refresh_token_payload)

    tokens_pair =  {
        'access_token': access_token,
        'refresh_token': refresh_token
    }

    return tokens_pair