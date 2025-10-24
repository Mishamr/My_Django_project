# main/serializers.py
from rest_framework import serializers
from .models import EncryptionHistory

class EncryptionHistorySerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(source='created_at', format="%Y-%m-%d %H:%M:%S")
    
    # Створення прев'ю для відображення
    input_preview = serializers.SerializerMethodField()
    output_preview = serializers.SerializerMethodField()
    icon = serializers.SerializerMethodField()
    
    class Meta:
        model = EncryptionHistory
        fields = [
            'id', 'operation_type', 'input_preview', 
            'output_preview', 'timestamp', 'icon'
        ]
    
    def get_input_preview(self, obj):
        return obj.input_text[:50] + '...' if len(obj.input_text) > 50 else obj.input_text
        
    def get_output_preview(self, obj):
        return obj.output_text[:50] + '...' if len(obj.output_text) > 50 else obj.output_text

    def get_icon(self, obj):
        # Використання назви іконки FontAwesome (для фронтенду)
        return 'lock' if obj.operation_type == 'encrypt' else 'unlock'

class EncryptionRequestSerializer(serializers.Serializer):
    """Серіалізатор для запитів шифрування"""
    key = serializers.CharField(max_length=500, min_length=1)
    text = serializers.CharField(min_length=1)
    # Алгоритм буде визначатися з налаштувань профілю користувача
    # algorithm = serializers.CharField(required=False) 
    
    def validate_key(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Key must be at least 8 characters long")
        return value

class DecryptionRequestSerializer(serializers.Serializer):
    """Серіалізатор для запитів дешифрування"""
    key = serializers.CharField(max_length=500, min_length=1)
    encrypted_data = serializers.CharField(min_length=1)
    
    def validate_key(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Key must be at least 8 characters long")
        return value