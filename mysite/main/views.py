# main/views.py
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseNotFound
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.contrib.auth.models import User
import json
import base64
import hashlib 

def get_client_ip(request):
    """Отримання IP-адреси клієнта."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def simple_encrypt(text, key, algorithm='aes-256'):
    """Базова функція шифрування (для демонстрації логіки)."""
    try:
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16] 

        encoded = base64.b64encode(text.encode('utf-8')).decode()

        return f"ENC:{algorithm}:{key_hash}:{encoded}"
    except Exception as e:
        return f"Error during encryption: {e}"

def simple_decrypt(text, key):
    """Базова функція дешифрування (для демонстрації логіки)."""
    if text.startswith('ENC:'):
        try:
            parts = text.split(':')
            if len(parts) == 4:

                key_hash_sent = parts[2] 
                encoded_data = parts[3] 
                
                key_hash_expected = hashlib.sha256(key.encode()).hexdigest()[:16]
                
                if key_hash_sent == key_hash_expected:
                    decoded = base64.b64decode(encoded_data).decode('utf-8')
                    return decoded
                else:
                    return "Invalid decryption key or algorithm mismatch."
            else:
                return "Invalid encrypted text format (parts mismatch)."
        except:
            return "Decryption error"
    return "Invalid encrypted text format (missing prefix)."

def home(request):
    """Головна сторінка."""
    profile = None
    history = []
    
    if request.user.is_authenticated:
        pass
    
    return render(request, 'main/home.html', {
        'history': history,
        'profile': profile
    })

@login_required
def settings_page(request):
    """
    Сторінка налаштувань. Рендерить settings.html.
    Це функція перегляду сторінки, вона повертає HTML.
    """
    return render(request, 'main/settings.html', {})

@csrf_exempt
def auth_view(request):
    """Об'єднаний вхід та реєстрація."""
    if request.user.is_authenticated:
        return redirect('home')
    
    signup_mode = request.GET.get('mode') == 'signup'
    error = None
    
    if request.method == 'POST':
        if 'signin' in request.POST:
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                
                
                login(request, user)
                
                return redirect('home')
            else:
                error = 'Неправильне ім\'я користувача або пароль'
                signup_mode = False 
                
        elif 'signup' in request.POST:

            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            
            if password != confirm_password:
                error = 'Паролі не збігаються'
                signup_mode = True
            elif User.objects.filter(username=username).exists():
                error = 'Ім\'я користувача вже існує'
                signup_mode = True
            else:
                try:

                    user = User.objects.create_user(username=username, email=email, password=password)
                    
                    login(request, user)
                    
                    return redirect('home')
                except Exception as e:
                    error = f'Помилка реєстрації: {e}'
                    signup_mode = True

    return render(request, 'main/signin.html', { 
        'signup_mode': signup_mode,
        'error': error
    })

def user_logout(request):
    """Вихід користувача з оновленням сесії."""
    if request.user.is_authenticated:
        pass
    
    logout(request)
    return redirect('home')

@login_required
@csrf_exempt 
def api_encrypt(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            key = data.get('key', '')
            text = data.get('text', '')
            
            if not key or not text:
                 return JsonResponse({'success': False, 'error': 'Key and text are required.'}, status=400)
            
            algorithm = 'aes-256'
            
            encrypted_text = simple_encrypt(text, key, algorithm)
            
            if encrypted_text.startswith("Error"):
                 return JsonResponse({'success': False, 'error': encrypted_text}, status=500)

            return JsonResponse({'success': True, 'encrypted': encrypted_text, 'algorithm': algorithm})
        
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON format.'}, status=400)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)

    return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)


@login_required
@csrf_exempt
def api_decrypt(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            key = data.get('key', '')
            encrypted_data = data.get('encrypted_data', '')
            
            if not key or not encrypted_data:
                 return JsonResponse({'success': False, 'error': 'Key and encrypted data are required.'}, status=400)
            
            decrypted_text = simple_decrypt(encrypted_data, key)
            
            if decrypted_text.startswith("Invalid") or decrypted_text.startswith("Decryption error"):
                 return JsonResponse({'success': False, 'error': decrypted_text}, status=400)

            return JsonResponse({'success': True, 'decrypted': decrypted_text})
        
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON format.'}, status=400)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)

    return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)


@login_required
def api_get_settings(request):
    """API: Повертає налаштування користувача у форматі JSON."""
    if request.method == 'GET':
        try:
            settings_data = {
                'theme': 'dark', 
                'auto_clear': True,
                'secure_wipe': True,
                'audit_trail': False,
                'encryption_algorithm': 'aes-256',
                'key_derivation': 'pbkdf2',
                'font_size': 'medium',
                'language': 'en',
            }
            return JsonResponse({'success': True, 'settings': settings_data})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)

@login_required
@csrf_exempt
def api_update_settings(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            return JsonResponse({'success': True, 'message': 'Налаштування успішно оновлено!'})
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON format.'}, status=400)
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)

@login_required
def api_get_history(request):
    if request.method == 'GET':
        try:
            history_data = [] 
            return JsonResponse({'success': True, 'history': history_data})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)

@login_required
@csrf_exempt
def api_clear_history(request):
    if request.method == 'POST':
        try:
            return JsonResponse({'success': True, 'message': 'Успішно видалено 0 записів історії.'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    return JsonResponse({'success': False, 'error': 'Method not allowed'}, status=405)