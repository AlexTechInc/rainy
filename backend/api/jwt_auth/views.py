from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST
from hashlib import sha256
from jwt.exceptions import ExpiredSignatureError, DecodeError

from .utils import jwt_generate_tokens_pair, jwt_decode
from .models import User
from .serializers import UserSerializer


class Login(APIView):
    def post(self, request):
        data = request.data

        login = data.get('login')
        password = data.get('password')

        response = {}

        if (not login) or (not password):
            response = {
                'messages': [
                    f'login or password is incorrect'
                ]
            }

            return Response(status=HTTP_400_BAD_REQUEST)
        
        user = None

        try:
            user = User.objects.get(login=login)
        except User.DoesNotExist:
            response = {
                'messages': [
                    f'user {login} doesn\'t exist'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)
        
        if sha256(password.encode('utf-8')).hexdigest() != user.password:
            response = {
                'messages': [
                    f'login or password is incorrect'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)

        user_id = user.id;

        access_token_payload = {
            'login': login,
            'user_id': user_id
        }

        refresh_token_payload = {
            'user_id': user_id
        }

        tokens_pair = jwt_generate_tokens_pair(access_token_payload, refresh_token_payload)

        return Response(tokens_pair)
    

class Refresh(APIView):
    def post(self, request):
        data = request.data

        refresh_token = data.get('refresh_token')

        if not refresh_token:
            response = {
                'messages': [
                    'refresh token was not provided'
                ]
            }
            return Response(response, status=HTTP_400_BAD_REQUEST)
        
        refresh_token_payload = None

        try:
            refresh_token_payload = jwt_decode(refresh_token)
        except ExpiredSignatureError:
            response = {
                'messages': [
                    'refresh token is expired'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)
        except DecodeError:
            response = {
                'messages': [
                    'refresh token is invalid'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)

        is_refresh_token = refresh_token_payload.get('refresh', False)

        if not is_refresh_token:
            response = {
                'messages': [
                    'provided token is not refresh type'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)
        
        user = None
        user_id = refresh_token_payload.get('user_id')

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            response = {
                'messages': [
                    'user doesn\'t exist'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)
        
        login = user.login
        
        access_token_payload = {
            'login': login,
            'user_id': user_id
        }

        refresh_token_payload = {
            'user_id': user_id
        }

        tokens_pair = jwt_generate_tokens_pair(access_token_payload, refresh_token_payload)

        return Response(tokens_pair)


class Register(APIView):
    """
    login - 64 chars
    password - sha256 hexdigest (64 hex chars)
    """  
    
    def post(self, request):
        data = request.data

        password = data.get('password')
        password_repeat = data.get('password_repeat')

        if not password or not password_repeat:
            response = {
                'messages': [
                    'password fields cannot be empty'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)
        
        if password != password_repeat:
            response = {
                'messages': [
                    'passwords don\'t match'
                ]
            }

            return Response(response, status=HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response({'success': '32'})

        print(serializer.error_messages)

        return Response({'error': '1'})


class Logout(APIView):

    pass