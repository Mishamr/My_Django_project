# main/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import UserProfile, EncryptionHistory, UserSession # <--- Це рядок, який спричиняє помилку

# Реєстрація моделей (використовуйте тільки ті, які ви реєструєте тут)

# 1. Створення inline для UserProfile
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Профіль'

# 2. Перевизначення адмінки User
class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    # Додайте інші поля, якщо потрібно

# 3. Реєстрація власних моделей
@admin.register(EncryptionHistory)
class EncryptionHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'operation_type', 'created_at', 'key_used')
    list_filter = ('operation_type', 'created_at')
    search_fields = ('user__username', 'input_text')

@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'login_time', 'logout_time', 'ip_address')
    list_filter = ('login_time',)
    search_fields = ('user__username', 'ip_address')

# Від'єднання стандартного User і реєстрація нашого
admin.site.unregister(User)
admin.site.register(User, UserAdmin)