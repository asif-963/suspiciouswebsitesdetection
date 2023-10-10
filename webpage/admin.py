from django.contrib import admin
from .models import Message

from .models import SuspiciousWebsite
admin.site.register(SuspiciousWebsite)

class MessageAdmin(admin.ModelAdmin):
    list_display = ('user_name','user_email','user_message')

admin.site.register(Message,MessageAdmin)
