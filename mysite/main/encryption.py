import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

class AES256Encryptor:
    @staticmethod
    def encrypt(text, key):
        """
        Шифрування тексту з використанням AES-256-CBC
        """
        try:
            # Генеруємо випадковий salt (16 байт)
            salt = get_random_bytes(16)
            
            # Генеруємо випадковий IV (16 байт)
            iv = get_random_bytes(16)
            
            # Створюємо ключ 256 біт з пароля та salt
            key_hash = hashlib.pbkdf2_hmac(
                'sha256', 
                key.encode('utf-8'), 
                salt, 
                100000,  # 100,000 ітерацій
                32       # 32 байти = 256 біт
            )
            
            # Створюємо AES шифр у режимі CBC
            cipher = AES.new(key_hash, AES.MODE_CBC, iv)
            
            # Додаємо padding та шифруємо текст
            padded_text = pad(text.encode('utf-8'), AES.block_size)
            encrypted_bytes = cipher.encrypt(padded_text)
            
            # Об'єднуємо salt + iv + encrypted_data
            combined = salt + iv + encrypted_bytes
            
            # Кодуємо у base64 для безпечного зберігання
            return base64.urlsafe_b64encode(combined).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Помилка шифрування: {str(e)}")

    @staticmethod
    def decrypt(encrypted_text, key):
        """
        Дешифрування тексту з використанням AES-256-CBC
        """
        try:
            # Декодуємо з base64
            combined = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
            
            # Розділяємо компоненти:
            # salt - перші 16 байт
            # iv - наступні 16 байт  
            # encrypted_data - решта
            salt = combined[:16]
            iv = combined[16:32]
            encrypted_data = combined[32:]
            
            # Відтворюємо ключ з пароля та salt
            key_hash = hashlib.pbkdf2_hmac(
                'sha256',
                key.encode('utf-8'),
                salt,
                100000,
                32
            )
            
            # Створюємо AES шифр для дешифрування
            cipher = AES.new(key_hash, AES.MODE_CBC, iv)
            
            # Дешифруємо та видаляємо padding
            decrypted_padded = cipher.decrypt(encrypted_data)
            decrypted_bytes = unpad(decrypted_padded, AES.block_size)
            
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Помилка дешифрування: {str(e)}")

def get_encryptor():
    return AES256Encryptor()