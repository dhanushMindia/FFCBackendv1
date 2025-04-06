from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation



User = get_user_model()  # Get the active User model (our custom one)

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[password_validation.validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    #NEW CHANGE TO ALLOW CUSTOM USERNAMES!
    username = serializers.CharField(required=True, max_length=150)

    class Meta:
        model = User
        fields = ('username','email', 'first_name', 'last_name', 'password', 'password2')
        extra_kwargs = {
            # Make first/last name required since we want them during signup
            'first_name': {'required': True},
            'last_name': {'required': True},
        }
#----username validation method ---
    def validate_username(self, value):
        """
        Check that the username is not already taken.
        """
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with that username already exists.")
        # TODO: Add more checks as necessary
        return value
    
    def validate(self, data):
        """
        Check that the two password entries match.
        """
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": ["Password fields didn't match."]}) # Return as list
        return data


    def create(self, validated_data):
        """
        Create and return a new `User` instance, using the provided username.
        """
        validated_data.pop('password2', None)
        user = User.objects.create_user(
            username=validated_data['username'],      # Use the validated username
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''), # Use .get if not strictly required by model in the future
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password'],is_active=False      # create_user handles hashing
        )
        return user
# TODO: might want to add 'username' to UserDetailSerializer.Meta.fields later
class UserLoginSerializer(serializers.Serializer):
    email = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'first_name', 'last_name')