from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer
from .serializers import UserLoginSerializer
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.permissions import IsAuthenticated
from .serializers import UserDetailSerializer
from django.contrib.auth import get_user_model




class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"success": True, "message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data) # If you're using this
        if serializer.is_valid(): # If you're using this
            email = serializer.validated_data.get("email") # If you're using this
            password = serializer.validated_data.get("password") # If you're using this
        else:
            email = request.data.get("email") # If you're not using serializer
            password = request.data.get("password") # If you're not using serializer

        user = authenticate(email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)  # Generate tokens
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return Response(
                {
                    "success": True,
                    "message": "Login successful",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"success": False, "message": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated] # Require authentication

    def get(self, request):
        user = request.user # The authenticated user
        serializer = UserDetailSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)




# class UserLoginView(APIView):
#     def post(self, request):
     



#         email = request.data.get("email")

#         password = request.data.get("password")
 



#         user = authenticate(email=email, password=password)

#         if user is not None:
#             # Authentication successful
#             # TODO: Generate and return a JWT token here
#             return Response(
#                 {"success": True, "message": "Login successful", "token": "DUMMY_TOKEN"},
#                 status=status.HTTP_200_OK,
#             )
#         else:
#             # Authentication failed
#             return Response(
#                 {"success": False, "message": "Invalid credentials"},
#                 status=status.HTTP_401_UNAUTHORIZED,
#             )



