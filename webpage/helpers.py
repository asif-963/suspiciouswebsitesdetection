
import random
import string
from django.core.mail import send_mail
import uuid
from django.conf import settings


def send_forget_password_mail(email, token):
    subject = 'Reset Password'
    reset_link =f'{settings.BASE_URL}/change_pass/{token}/'
    message = f"You're receiving this email because you requested a password reset for your user account at Detecting Phishing Website .\n\n"
    message += f"Please go to the following page and choose a new password:\n{reset_link}\n\n"
    message += "Thanks for using our site!\nThe Detecting Phishing Websites team"
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)
    return True
