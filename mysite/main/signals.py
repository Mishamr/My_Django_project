# main/signals.py (Повний та виправлений код)

from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.dispatch import receiver
from .models import UserProfile
from django.db.utils import OperationalError

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Гарантує створення профілю та безпечне збереження.
    """
    try:
        if created:
            # Створення профілю при реєстрації
            UserProfile.objects.create(user=instance)
        else:
            # Спроба зберегти профіль, якщо він існує.
            # Якщо ні, Django викликає DoestNotExist, який ми ловимо.
            if hasattr(instance, 'userprofile'):
                instance.userprofile.save()
            
    except OperationalError:
        # Ігноруємо помилки, якщо таблиця ще не створена (наприклад, під час міграцій)
        pass
    except UserProfile.DoesNotExist:
        # Ігноруємо помилку для старих користувачів, профіль яких ми створимо 
        # при першому вході у views.py
        pass