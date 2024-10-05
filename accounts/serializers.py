from rest_framework import serializers
from .models import StockImageUser

class StockImageUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = StockImageUser
        fields = ('id', 'username', 'email', 'phone_number', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = StockImageUser.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            phone_number=validated_data.get('phone_number', ''),
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = StockImageUser.objects.get(email=value)
        except StockImageUser.DoesNotExist:
            raise serializers.ValidationError("Email address is not registered")
        return value
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    confirm_password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)