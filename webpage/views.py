from django.shortcuts import render, redirect,HttpResponse
from django.db import IntegrityError
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
import pandas as pd
import numpy as np
import random


# Machine Learning Packages
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics
from .models import SuspiciousWebsite

from django.views import View
from .models import Message
from django.http import HttpResponse


from django.contrib import messages
from .models import *
from .helpers import send_forget_password_mail
from .models import Profile
import uuid

from datetime import timedelta
from django.utils import timezone

# Create your views here.
def index(request):
    if request.method == 'POST':
        user_names = request.POST['name']
        user_emails = request.POST['email']
        user_messages = request.POST['message']

        if len(user_names)  < 1:
            messages.error(request,'Name and Email are required...')
            # return HttpResponse('<h1>!!!Name and Email are required</h1>' )
        else:
            new_contact = Message(user_name=user_names , user_email=user_emails, user_message=user_messages)
            new_contact.save()

    return render(request,'index.html')

def user_login(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('detection')
        else:
            messages.error(request,'Username or Password not found')
            # return HttpResponse("<h1>Username or Password not found</h1>")
            return redirect('login')
    messages.success(request,' Login now...')
    return render(request,'login.html')

def signup(request):
    if request.method == "POST":
        username = request.POST['username']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        email = request.POST['email']
        password = request.POST['password']

        if len(password)  < 6:
            messages.error(request,'Password must be more than 6 character')
            return render(request,'signup.html')
            # return HttpResponse('<h1>password must be more than 6 character</h1>' )

        # Check if the username is already taken
        if User.objects.filter(username=username).exists():
            messages.error(request,'Username already taken')
            # return HttpResponse("<h1>Username already taken</h1>")
            return render(request, 'signup.html', {'error_message': 'Username already taken'})

        try:
            myuser = User.objects.create_user(username=username, email=email, password=password)
            myuser.first_name = firstname
            myuser.last_name = lastname
            myuser.save()
            messages.success(request,'You have been successfully Registered ...')
            return redirect('login')
        except IntegrityError:
            return render(request, 'signup.html', {'error_message': 'An error occurred during signup'})
        

    messages.success(request, 'Signup Now ... ')
    return render(request, 'signup.html')


def about(request):
    return render(request,'aboutus.html')

def faq(request):
    return render(request,'faq.html')

def admin_user(request):
    # messages.success(request, 'Click the button below to be redirected....')
    return render(request,'admin_user.html')


def check_phishing(request):
    result = None
    checked_website=""
    if request.method=='POST':
        url=request.POST['url']

        data = pd.read_csv("D:/Phishing Detector/phishing.csv")
        X = data.drop(["class","Index"],axis =1)
        y = data["class"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 42)
        model= GradientBoostingClassifier(max_depth=4,learning_rate=0.7)
        model.fit(X_train,y_train)

        try:
            import ipaddress
            import re
            import urllib.request
            from bs4 import BeautifulSoup
            import socket
            import requests
            import google
            from googleapiclient.discovery import build
            import whois
            from datetime import date, datetime
            import time
            from dateutil.parser import parse as date_parse
            from urllib.parse import urlparse

            class FeatureExtraction:
                features = []
                def __init__(self,url):
                    self.features = []
                    self.url = url
                    self.domain = ""
                    self.whois_response = ""
                    self.urlparse = ""
                    self.response = ""
                    self.soup = ""

                    try:
                        self.response = requests.get(url)
                        self.soup = BeautifulSoup(response.text, 'html.parser')
                    except:
                        pass

                    try:
                        self.urlparse = urlparse(url)
                        self.domain = self.urlparse.netloc
                    except:
                        pass

                    try:
                        self.whois_response = whois.whois(self.domain)
                    except:
                        pass


                    

                    self.features.append(self.UsingIp())
                    self.features.append(self.longUrl())
                    self.features.append(self.shortUrl())
                    self.features.append(self.symbol())
                    self.features.append(self.redirecting())
                    self.features.append(self.prefixSuffix())
                    self.features.append(self.SubDomains())
                    self.features.append(self.Hppts())
                    self.features.append(self.DomainRegLen())
                    self.features.append(self.Favicon())
                    

                    self.features.append(self.NonStdPort())
                    self.features.append(self.HTTPSDomainURL())
                    self.features.append(self.RequestURL())
                    self.features.append(self.AnchorURL())
                    self.features.append(self.LinksInScriptTags())
                    self.features.append(self.ServerFormHandler())
                    self.features.append(self.InfoEmail())
                    self.features.append(self.AbnormalURL())
                    self.features.append(self.WebsiteForwarding())
                    self.features.append(self.StatusBarCust())

                    self.features.append(self.DisableRightClick())
                    self.features.append(self.UsingPopupWindow())
                    self.features.append(self.IframeRedirection())
                    self.features.append(self.AgeofDomain())
                    self.features.append(self.DNSRecording())
                    self.features.append(self.WebsiteTraffic())
                    self.features.append(self.PageRank())
                    self.features.append(self.GoogleIndex())
                    self.features.append(self.LinksPointingToPage())
                    self.features.append(self.StatsReport())


                # 1.UsingIp
                def UsingIp(self):
                    try:
                        ipaddress.ip_address(self.url)
                        return -1
                    except:
                        return 1

                # 2.longUrl
                def longUrl(self):
                    if len(self.url) < 54:
                        return 1
                    if len(self.url) >= 54 and len(self.url) <= 75:
                        return 0
                    return -1

                # 3.shortUrl
                def shortUrl(self):
                    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                                'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                                'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                                'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                                'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                                'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                                'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
                    if match:
                        return -1
                    return 1

                # 4.Symbol@
                def symbol(self):
                    if re.findall("@",self.url):
                        return -1
                    return 1
                
                # 5.Redirecting//
                def redirecting(self):
                    if self.url.rfind('//')>6:
                        return -1
                    return 1
                
                # 6.prefixSuffix
                def prefixSuffix(self):
                    try:
                        match = re.findall('\-', self.domain)
                        if match:
                            return -1
                        return 1
                    except:
                        return -1
                
                # 7.SubDomains
                def SubDomains(self):
                    dot_count = len(re.findall("\.", self.url))
                    if dot_count == 1:
                        return 1
                    elif dot_count == 2:
                        return 0
                    return -1

                # 8.HTTPS
                def Hppts(self):
                    try:
                        https = self.urlparse.scheme
                        if 'https' in https:
                            return 1
                        return -1
                    except:
                        return 1

                # 9.DomainRegLen
                def DomainRegLen(self):
                    try:
                        expiration_date = self.whois_response.expiration_date
                        creation_date = self.whois_response.creation_date
                        try:
                            if(len(expiration_date)):
                                expiration_date = expiration_date[0]
                        except:
                            pass
                        try:
                            if(len(creation_date)):
                                creation_date = creation_date[0]
                        except:
                            pass

                        age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
                        if age >=12:
                            return 1
                        return -1
                    except:
                        return -1

                # 10. Favicon
                def Favicon(self):
                    try:
                        for head in self.soup.find_all('head'):
                            for head.link in self.soup.find_all('link', href=True):
                                dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                                if self.url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                                    return 1
                        return -1
                    except:
                        return -1

                # 11. NonStdPort
                def NonStdPort(self):
                    try:
                        port = self.domain.split(":")
                        if len(port)>1:
                            return -1
                        return 1
                    except:
                        return -1

                # 12. HTTPSDomainURL
                def HTTPSDomainURL(self):
                    try:
                        if 'https' in self.domain:
                            return -1
                        return 1
                    except:
                        return -1
                
                # 13. RequestURL
                def RequestURL(self):
                    try:
                        for img in self.soup.find_all('img', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                            if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for audio in self.soup.find_all('audio', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                            if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for embed in self.soup.find_all('embed', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                            if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for iframe in self.soup.find_all('iframe', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                            if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        try:
                            percentage = success/float(i) * 100
                            if percentage < 22.0:
                                return 1
                            elif((percentage >= 22.0) and (percentage < 61.0)):
                                return 0
                            else:
                                return -1
                        except:
                            return 0
                    except:
                        return -1
                
                # 14. AnchorURL
                def AnchorURL(self):
                    try:
                        i,unsafe = 0,0
                        for a in self.soup.find_all('a', href=True):
                            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or self.domain in a['href']):
                                unsafe = unsafe + 1
                            i = i + 1

                        try:
                            percentage = unsafe / float(i) * 100
                            if percentage < 31.0:
                                return 1
                            elif ((percentage >= 31.0) and (percentage < 67.0)):
                                return 0
                            else:
                                return -1
                        except:
                            return -1

                    except:
                        return -1

                # 15. LinksInScriptTags
                def LinksInScriptTags(self):
                    try:
                        i,success = 0,0
                    
                        for link in self.soup.find_all('link', href=True):
                            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                            if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for script in self.soup.find_all('script', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                            if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        try:
                            percentage = success / float(i) * 100
                            if percentage < 17.0:
                                return 1
                            elif((percentage >= 17.0) and (percentage < 81.0)):
                                return 0
                            else:
                                return -1
                        except:
                            return 0
                    except:
                        return -1

                # 16. ServerFormHandler
                def ServerFormHandler(self):
                    try:
                        if len(self.soup.find_all('form', action=True))==0:
                            return 1
                        else :
                            for form in self.soup.find_all('form', action=True):
                                if form['action'] == "" or form['action'] == "about:blank":
                                    return -1
                                elif self.url not in form['action'] and self.domain not in form['action']:
                                    return 0
                                else:
                                    return 1
                    except:
                        return -1

                # 17. InfoEmail
                def InfoEmail(self):
                    try:
                        if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                            return -1
                        else:
                            return 1
                    except:
                        return -1

                # 18. AbnormalURL
                def AbnormalURL(self):
                    try:
                        if self.response.text == self.whois_response:
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 19. WebsiteForwarding
                def WebsiteForwarding(self):
                    try:
                        if len(self.response.history) <= 1:
                            return 1
                        elif len(self.response.history) <= 4:
                            return 0
                        else:
                            return -1
                    except:
                        return -1

                # 20. StatusBarCust
                def StatusBarCust(self):
                    try:
                        if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 21. DisableRightClick
                def DisableRightClick(self):
                    try:
                        if re.findall(r"event.button ?== ?2", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 22. UsingPopupWindow
                def UsingPopupWindow(self):
                    try:
                        if re.findall(r"alert\(", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 23. IframeRedirection
                def IframeRedirection(self):
                    try:
                        if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 24. AgeofDomain
                def AgeofDomain(self):
                    try:
                        creation_date = self.whois_response.creation_date
                        try:
                            if(len(creation_date)):
                                creation_date = creation_date[0]
                        except:
                            pass

                        today  = date.today()
                        age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
                        if age >=6:
                            return 1
                        return -1
                    except:
                        return -1

                # 25. DNSRecording    
                def DNSRecording(self):
                    try:
                        creation_date = self.whois_response.creation_date
                        try:
                            if(len(creation_date)):
                                creation_date = creation_date[0]
                        except:
                            pass

                        today  = date.today()
                        age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
                        if age >=6:
                            return 1
                        return -1
                    except:
                        return -1

                # 26. WebsiteTraffic   
                def WebsiteTraffic(self):
                    try:
                        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
                        if (int(rank) < 100000):
                            return 1
                        return 0
                    except :
                        return -1

                # 27. PageRank
                def PageRank(self):
                    try:
                        prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})

                        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
                        if global_rank > 0 and global_rank < 100000:
                            return 1
                        return -1
                    except:
                        return -1
                        

                # 28. GoogleIndex
                def GoogleIndex(self):
                    try:
                        site = search(self.url, 5)
                        if site:
                            return 1
                        else:
                            return -1
                    except:
                        return 1

                # 29. LinksPointingToPage
                def LinksPointingToPage(self):
                    try:
                        number_of_links = len(re.findall(r"<a href=", self.response.text))
                        if number_of_links == 0:
                            return 1
                        elif number_of_links <= 2:
                            return 0
                        else:
                            return -1
                    except:
                        return -1

                # 30. StatsReport
                def StatsReport(self):
                    try:
                        url_match = re.search(
                    'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
                        ip_address = socket.gethostbyname(self.domain)
                        ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
                        if url_match:
                            return -1
                        elif ip_match:
                            return -1
                        return 1
                    except:
                        return 1
                
                def getFeaturesList(self):
                    return self.features

            
            Features = FeatureExtraction(url)
            X = np.array(Features.getFeaturesList()).reshape(1, 30)
            y_pred =model.predict(X)[0]

            if y_pred == 1:
                result = "We guess it is a safe website"
            else:
                SuspiciousWebsite.objects.create(url=url)
                result = "Caution! Suspicious website detected"

            checked_website = url

        except Exception as e:
            result = "This website has already been verified as suspicious. Please review our blacklist for further information."
    # messages.success(request, ' Check Your Website Safe or Not...')
    return render(request, 'detection.html', {'result': result,'checked_website':checked_website})




def check_sqlinjection(request):
    result = None
    checked_website=""
    if request.method=='POST':
        url=request.POST['url']

        data = pd.read_csv("sqlinjection.csv")
        X = data.drop(["class","Index"],axis =1)
        y = data["class"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 42)
        model= GradientBoostingClassifier(max_depth=4,learning_rate=0.7)
        model.fit(X_train,y_train)

        try:
            import ipaddress
            import re
            import urllib.request
            from bs4 import BeautifulSoup
            import socket
            import requests
            import google
            from googleapiclient.discovery import build
            import whois
            from datetime import date, datetime
            import time
            from dateutil.parser import parse as date_parse
            from urllib.parse import urlparse

            class FeatureExtraction:
                features = []
                def __init__(self,url):
                    self.features = []
                    self.url = url
                    self.domain = ""
                    self.whois_response = ""
                    self.urlparse = ""
                    self.response = ""
                    self.soup = ""

                    try:
                        self.response = requests.get(url)
                        self.soup = BeautifulSoup(response.text, 'html.parser')
                    except:
                        pass

                    try:
                        self.urlparse = urlparse(url)
                        self.domain = self.urlparse.netloc
                    except:
                        pass

                    try:
                        self.whois_response = whois.whois(self.domain)
                    except:
                        pass


                    

                    self.features.append(self.UsingIp())
                    self.features.append(self.longUrl())
                    self.features.append(self.shortUrl())
                    self.features.append(self.symbol())
                    self.features.append(self.redirecting())
                    self.features.append(self.prefixSuffix())
                    self.features.append(self.SubDomains())
                    self.features.append(self.Hppts())
                    self.features.append(self.DomainRegLen())
                    self.features.append(self.Favicon())
                    

                    self.features.append(self.NonStdPort())
                    self.features.append(self.HTTPSDomainURL())
                    self.features.append(self.RequestURL())
                    self.features.append(self.AnchorURL())
                    self.features.append(self.LinksInScriptTags())
                    self.features.append(self.ServerFormHandler())
                    self.features.append(self.InfoEmail())
                    self.features.append(self.AbnormalURL())
                    self.features.append(self.WebsiteForwarding())
                    self.features.append(self.StatusBarCust())

                    self.features.append(self.DisableRightClick())
                    self.features.append(self.UsingPopupWindow())
                    self.features.append(self.IframeRedirection())
                    self.features.append(self.AgeofDomain())
                    self.features.append(self.DNSRecording())
                    self.features.append(self.WebsiteTraffic())
                    self.features.append(self.PageRank())
                    self.features.append(self.GoogleIndex())
                    self.features.append(self.LinksPointingToPage())
                    self.features.append(self.StatsReport())


                # 1.UsingIp
                def UsingIp(self):
                    try:
                        ipaddress.ip_address(self.url)
                        return -1
                    except:
                        return 1

                # 2.longUrl
                def longUrl(self):
                    if len(self.url) < 54:
                        return 1
                    if len(self.url) >= 54 and len(self.url) <= 75:
                        return 0
                    return -1

                # 3.shortUrl
                def shortUrl(self):
                    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                                'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                                'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                                'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                                'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                                'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                                'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
                    if match:
                        return -1
                    return 1

                # 4.Symbol@
                def symbol(self):
                    if re.findall("@",self.url):
                        return -1
                    return 1
                
                # 5.Redirecting//
                def redirecting(self):
                    if self.url.rfind('//')>6:
                        return -1
                    return 1
                
                # 6.prefixSuffix
                def prefixSuffix(self):
                    try:
                        match = re.findall('\-', self.domain)
                        if match:
                            return -1
                        return 1
                    except:
                        return -1
                
                # 7.SubDomains
                def SubDomains(self):
                    dot_count = len(re.findall("\.", self.url))
                    if dot_count == 1:
                        return 1
                    elif dot_count == 2:
                        return 0
                    return -1

                # 8.HTTPS
                def Hppts(self):
                    try:
                        https = self.urlparse.scheme
                        if 'https' in https:
                            return 1
                        return -1
                    except:
                        return 1

                # 9.DomainRegLen
                def DomainRegLen(self):
                    try:
                        expiration_date = self.whois_response.expiration_date
                        creation_date = self.whois_response.creation_date
                        try:
                            if(len(expiration_date)):
                                expiration_date = expiration_date[0]
                        except:
                            pass
                        try:
                            if(len(creation_date)):
                                creation_date = creation_date[0]
                        except:
                            pass

                        age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
                        if age >=12:
                            return 1
                        return -1
                    except:
                        return -1

                # 10. Favicon
                def Favicon(self):
                    try:
                        for head in self.soup.find_all('head'):
                            for head.link in self.soup.find_all('link', href=True):
                                dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                                if self.url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                                    return 1
                        return -1
                    except:
                        return -1

                # 11. NonStdPort
                def NonStdPort(self):
                    try:
                        port = self.domain.split(":")
                        if len(port)>1:
                            return -1
                        return 1
                    except:
                        return -1

                # 12. HTTPSDomainURL
                def HTTPSDomainURL(self):
                    try:
                        if 'https' in self.domain:
                            return -1
                        return 1
                    except:
                        return -1
                
                # 13. RequestURL
                def RequestURL(self):
                    try:
                        for img in self.soup.find_all('img', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                            if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for audio in self.soup.find_all('audio', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                            if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for embed in self.soup.find_all('embed', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                            if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for iframe in self.soup.find_all('iframe', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                            if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        try:
                            percentage = success/float(i) * 100
                            if percentage < 22.0:
                                return 1
                            elif((percentage >= 22.0) and (percentage < 61.0)):
                                return 0
                            else:
                                return -1
                        except:
                            return 0
                    except:
                        return -1
                
                # 14. AnchorURL
                def AnchorURL(self):
                    try:
                        i,unsafe = 0,0
                        for a in self.soup.find_all('a', href=True):
                            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or self.domain in a['href']):
                                unsafe = unsafe + 1
                            i = i + 1

                        try:
                            percentage = unsafe / float(i) * 100
                            if percentage < 31.0:
                                return 1
                            elif ((percentage >= 31.0) and (percentage < 67.0)):
                                return 0
                            else:
                                return -1
                        except:
                            return -1

                    except:
                        return -1

                # 15. LinksInScriptTags
                def LinksInScriptTags(self):
                    try:
                        i,success = 0,0
                    
                        for link in self.soup.find_all('link', href=True):
                            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                            if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        for script in self.soup.find_all('script', src=True):
                            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                            if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                                success = success + 1
                            i = i+1

                        try:
                            percentage = success / float(i) * 100
                            if percentage < 17.0:
                                return 1
                            elif((percentage >= 17.0) and (percentage < 81.0)):
                                return 0
                            else:
                                return -1
                        except:
                            return 0
                    except:
                        return -1

                # 16. ServerFormHandler
                def ServerFormHandler(self):
                    try:
                        if len(self.soup.find_all('form', action=True))==0:
                            return 1
                        else :
                            for form in self.soup.find_all('form', action=True):
                                if form['action'] == "" or form['action'] == "about:blank":
                                    return -1
                                elif self.url not in form['action'] and self.domain not in form['action']:
                                    return 0
                                else:
                                    return 1
                    except:
                        return -1

                # 17. InfoEmail
                def InfoEmail(self):
                    try:
                        if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                            return -1
                        else:
                            return 1
                    except:
                        return -1

                # 18. AbnormalURL
                def AbnormalURL(self):
                    try:
                        if self.response.text == self.whois_response:
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 19. WebsiteForwarding
                def WebsiteForwarding(self):
                    try:
                        if len(self.response.history) <= 1:
                            return 1
                        elif len(self.response.history) <= 4:
                            return 0
                        else:
                            return -1
                    except:
                        return -1

                # 20. StatusBarCust
                def StatusBarCust(self):
                    try:
                        if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 21. DisableRightClick
                def DisableRightClick(self):
                    try:
                        if re.findall(r"event.button ?== ?2", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 22. UsingPopupWindow
                def UsingPopupWindow(self):
                    try:
                        if re.findall(r"alert\(", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 23. IframeRedirection
                def IframeRedirection(self):
                    try:
                        if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                            return 1
                        else:
                            return -1
                    except:
                        return -1

                # 24. AgeofDomain
                def AgeofDomain(self):
                    try:
                        creation_date = self.whois_response.creation_date
                        try:
                            if(len(creation_date)):
                                creation_date = creation_date[0]
                        except:
                            pass

                        today  = date.today()
                        age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
                        if age >=6:
                            return 1
                        return -1
                    except:
                        return -1

                # 25. DNSRecording    
                def DNSRecording(self):
                    try:
                        creation_date = self.whois_response.creation_date
                        try:
                            if(len(creation_date)):
                                creation_date = creation_date[0]
                        except:
                            pass

                        today  = date.today()
                        age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
                        if age >=6:
                            return 1
                        return -1
                    except:
                        return -1

                # 26. WebsiteTraffic   
                def WebsiteTraffic(self):
                    try:
                        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
                        if (int(rank) < 100000):
                            return 1
                        return 0
                    except :
                        return -1

                # 27. PageRank
                def PageRank(self):
                    try:
                        prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})

                        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
                        if global_rank > 0 and global_rank < 100000:
                            return 1
                        return -1
                    except:
                        return -1
                        

                # 28. GoogleIndex
                def GoogleIndex(self):
                    try:
                        site = search(self.url, 5)
                        if site:
                            return 1
                        else:
                            return -1
                    except:
                        return 1

                # 29. LinksPointingToPage
                def LinksPointingToPage(self):
                    try:
                        number_of_links = len(re.findall(r"<a href=", self.response.text))
                        if number_of_links == 0:
                            return 1
                        elif number_of_links <= 2:
                            return 0
                        else:
                            return -1
                    except:
                        return -1

                # 30. StatsReport
                def StatsReport(self):
                    try:
                        url_match = re.search(
                    'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
                        ip_address = socket.gethostbyname(self.domain)
                        ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
                        if url_match:
                            return -1
                        elif ip_match:
                            return -1
                        return 1
                    except:
                        return 1
                
                def getFeaturesList(self):
                    return self.features

            
            Features = FeatureExtraction(url)
            X = np.array(Features.getFeaturesList()).reshape(1, 30)
            y_pred =model.predict(X)[0]

            if y_pred == 1:
                result = "We guess it is a safe website"
            else:
                SqlinjectionWebsites.objects.create(url=url)
                result = "Alert! Sql Injection Detected !"

            checked_website = url

        except Exception as e:
            result = "This website has already been verified as suspicious. Please review our blacklist for further information."
    # messages.success(request, ' Check Your Website Safe or Not...')
    return render(request, 'sqli_detection.html', {'result': result,'checked_website':checked_website})

def list_suspicious_websites(request):
    websites = SuspiciousWebsite.objects.all()
    # messages.success(request, ' Protect your data. Avoid suspicious websites.')
    return render(request, 'blacklist.html', {'websites': websites})

def list_sqlinjection_websites(request):
    sqlwebsites = SqlinjectionWebsites.objects.all()
    # messages.success(request, ' Protect your data. Avoid suspicious websites.')
    return render(request, 'sqli_list.html', {'sqlwebsites': sqlwebsites})

def adminlogin(request):
    return render(request,'admin_login.html')

def admin(request):
    return render(request,admin.site.urls)



User = get_user_model()

def change_pass(request, token):
    try:
        profile_obj = Profile.objects.filter(forget_password_token=token).first()

        if not profile_obj:
            messages.error(request, 'Invalid link or profile not found')
            return redirect('login')  # Redirect to a password reset request page

        # Check if the token has already been used
        if profile_obj.password_reset_link_used:
            messages.error(request, 'This link has already been used. Try again later.')
            return redirect('login')  # Redirect to a password reset request page

        # Check if the token has been created
        if profile_obj.forget_password_token_created_at is None:
            messages.error(request, 'Token creation time is missing. Please request a new one.')
            return redirect('login')  # Redirect to a password reset request page

        # Calculate the expiration time
        token_creation_time = profile_obj.forget_password_token_created_at
        token_expiration_time = token_creation_time + timedelta(minutes=10)
        current_time = timezone.now()

        if current_time > token_expiration_time:
            profile_obj.password_reset_link_used = False
            profile_obj.save()  # Redirect to the password reset request page

        # Check if the user can change their password
        if profile_obj.last_password_change:
            time_since_last_change = current_time - profile_obj.last_password_change
            if time_since_last_change < timedelta(hours=24):
                messages.error(request, 'You can change your password only once .')
                # return redirect('home')  # Redirect to an appropriate page
            else:
                # Reset the flag to allow password change again after 10 minutes
                profile_obj.password_reset_link_used = True
                profile_obj.save()

        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('reconfirm_password')

            if len(new_password) < 6:
                messages.error(request, 'Password must be at least 6 characters long.')
                return redirect('change_pass')

            if new_password != confirm_password:
                messages.error(request, 'Passwords do not match')
                return redirect('change_pass')

            user_obj = User.objects.get(id=profile_obj.user.id)
            user_obj.set_password(new_password)
            user_obj.save()

            # Mark the password reset link as used
            profile_obj.password_reset_link_used = True
            profile_obj.last_password_change = timezone.now()  # Update the last password change time
            profile_obj.save()

            messages.success(request, 'Password changed successfully. You can log in now.')

            return redirect('login')

    except Exception as e:
        print(e)
        messages.error(request, '')
    messages.success(request, ' Enter Your New Password ')
    return render(request, 'change_pass.html')




def forget(request):
    try:
        if request.method == 'POST':
            username = request.POST.get('username')
            
            if not User.objects.filter(username=username).first():
                messages.error(request, 'No user found')
                # return HttpResponse("<h1>No user found with this username</h1>")
            
            user_obj = User.objects.get(username=username)
            
            # Generate a unique token
            token = str(uuid.uuid4())

            # Check if a profile exists for the user
            profile_obj, created = Profile.objects.get_or_create(user=user_obj)

            # Update the forget_password_token and set the creation time
            profile_obj.forget_password_token = token
            profile_obj.forget_password_token_created_at = timezone.now()  # Set the creation time
            profile_obj.save()

            send_forget_password_mail(user_obj.email, token)
            messages.success(request, ' Email has been sent your registered Email Id..')
            
            # return HttpResponse("<h1>Email has been sent</h1>")

    except Exception as e:
        print(e)
        messages.error(request, '')
    messages.success(request, ' Enter your Username and Reset Your Passsword..')
    return render(request, 'forget.html')

