from rest_framework import serializers
from .models import User
from hashlib import sha256


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('login', 'password', 'password_repeat')

    password_repeat = serializers.CharField(read_only=True)

    def validate(self, data):
        if data['password'] != self.context['password_repeat']:
            raise serializers.ValidationError('passwords don\'t match')

        return data
    
    def save(self):
        password = self.validated_data['password'] 
        self.validated_data['password'] = sha256(password).hexdigest()