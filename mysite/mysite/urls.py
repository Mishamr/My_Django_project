# mysite/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('main.urls')),
]

# ГАРАНТОВАНЕ ОБСЛУГОВУВАННЯ СТАТИЧНИХ ФАЙЛІВ
# Це змушує Django шукати файли у STATICFILES_DIRS, які ви вказали.
if settings.DEBUG:
    # Використовуємо STATICFILES_DIRS[0], де лежить ваша папка main/static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0])