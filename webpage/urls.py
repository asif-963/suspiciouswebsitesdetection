from django.contrib import admin
from django.urls import path
from .import views
from webpage.views import list_suspicious_websites
from webpage.views import list_sqlinjection_websites





urlpatterns = [
    # path('admin/', admin.site.urls,),
    path('',views.index,name='home'),
    path('login',views.user_login,name="login"),
    path('signup',views.signup,name='sign'),
    path('about',views.about,name="about"),
    path('faq',views.faq,name='faq'),
    path('admin_user',views.admin_user,name='admin_user'),
    path('detection',views.check_phishing,name='detection'),
    path('sqli_detection',views.check_sqlinjection,name='sqli_detection'),
<<<<<<< HEAD

=======
>>>>>>> 814844cc31095bc78de4281c30c89a21fa770c68
    path('admin_login',views.adminlogin,name='admin_login'),
    path('admin/', views.admin,name='admin'),
    path('blacklist',views.list_suspicious_websites,name='blacklist'),
    path('sqli_list',views.list_sqlinjection_websites,name='sqli_list'),
    path('forget',views.forget,name='forget'),
    path('change_pass/<token>/',views.change_pass,name='change_pass'),
    

]
