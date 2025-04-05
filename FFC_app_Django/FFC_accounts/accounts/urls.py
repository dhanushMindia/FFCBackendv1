from django.urls import path
from .views import UserRegistrationView, UserLoginView, UserDetailView # Import your views

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='user-registration'),
    path('login/', UserLoginView.as_view(), name='user-login'),
    path('me/', UserDetailView.as_view(), name='user-detail')
]