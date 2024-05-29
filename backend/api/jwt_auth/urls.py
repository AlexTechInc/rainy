from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView
from .views import Login, Refresh, Register, Logout

urlpatterns = [
    path('login/', Login.as_view()),
    path('refresh/', Refresh.as_view()),
    path('register/', Register.as_view()),
    path('logout/', Logout.as_view())
]   