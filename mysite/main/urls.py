# main/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Main Pages
    path('', views.home, name='home'),
    # Цей маршрут працює з іменем 'settings_page'
    path('settings/', views.settings_page, name='settings_page'),
    
    # Authentication
    path('auth/', views.auth_view, name='auth_view'), 
    path('logout/', views.user_logout, name='logout'), 
    
    # API Endpoints
    path('api/encrypt/', views.api_encrypt, name='api_encrypt'),
    path('api/decrypt/', views.api_decrypt, name='api_decrypt'),
    
    # Settings API
    path('api/get-settings/', views.api_get_settings, name='api_get_settings'),
    path('api/update-settings/', views.api_update_settings, name='api_update_settings'),
    
    # History API
    path('api/get-history/', views.api_get_history, name='api_get_history'),
    path('api/clear-history/', views.api_clear_history, name='api_clear_history'),
]