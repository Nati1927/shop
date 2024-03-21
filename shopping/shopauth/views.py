from django.shortcuts import render,HttpResponse,redirect
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages


from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.urls import NoReverseMatch,reverse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes,DjangoUnicodeDecodeError


from .utils import TokenGenerator,generate_token

from django.contrib.auth.tokens import PasswordResetTokenGenerator


from django.core.mail import send_mail,EmailMultiAlternatives
from django.core.mail import BadHeaderError,send_mail
from django.core import mail
from django.conf import settings
from django.core.mail import EmailMessage


import threading



class EmailThread(threading.Thread):
    def __init__(self,email_message):
        self.email_message=email_message
        threading.Thread.__init__(self)
        
    def run(self):
        self.email_message.send()







# Create your views here.
def signup(request):
 if request.method =="POST" :
    
     email=request.POST['email']
     password=request.POST['pass1']
     confirm_password=request.POST['pass2']
    
     if password!=confirm_password:
       messages.warning(request,"password is not matching")
       return render(request,'auth/signup.html')
         
     try:
      
      if User.objects.get(username=email):
             messages.warning(request,"Email is taken")
             return render(request,'auth/signup.html')
         
     except Exception as identifier:
         pass
    
     
     user=User.objects.create_user(email,email,password)
     user.is_active=False
     user.save()
     current_site=get_current_site(request)
     email_subject="activate your account"
     message=render_to_string('auth/activate.html',{
         'user':user ,
         'domain':'127.0.0.1:8000',
         'uid':urlsafe_base64_encode(force_bytes(user.pk)),
         'token':generate_token.make_token(user)
         
     })
     
     email_message = EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email],)
     EmailThread(email_message).start()
     messages.info(request,"Activate Your account by clicking link on your email ")
     return redirect('/shopauth/login')
        
 return render(request, 'auth/signup.html')




class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_bytes(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=uid)
            
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account Activated Successfully")
            return redirect('/shopauth/login')
        
        return render(request,'auth/activatefail.html')
            
        

def handlelogin(request):
    if request.method=="POST":
        
        username=request.POST['email']
        userpassword=request.POST['pass1']
        myuser=authenticate(username=username, password=userpassword)
        
        if myuser is not None:
            login(request,myuser)
            messages.success(request,"Login success")
            return render(request,'index.html')
        
        else:
            messages.error(request,"invalid username or password")
            return redirect('/shopauth/login')
        
    return render(request, 'auth/login.html')

def handlelogout(request):
    logout(request)
    messages.success(request,"Logout Success")
    return redirect('/shopauth/login')

class RequestResetEmailView(View):
    def get(self,request):
        return render(request,'auth/resetemail.html')
    
    def post(self,request):
        email=request.POST['email']
        user = User.objects.filter(email=email)
        
        if user.exists():
           current_site=get_current_site(request)
           email_subject='[Reset Your Password]'
           message=render_to_string('auth/resetpassword.html',
            {
               'domain': '127.0.0.1:8000',
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0])
           })
           
           email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER[email])
           EmailThread(email_message).start()
           
           message.info(request,"WE HAVE SENT AN EMAIL CHECK YOUR EMAIL")
           return render(request,'auth/resetemail.html')

class SetNewPasswordView(View):
    def get(self, request, uidb64, token):
        try:
            # Decoding uidb64
            user_id = render_to_string(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            
            # Checking token validity
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password reset link is invalid")
                return render(request, 'auth/resetemail.html')
        except (DjangoUnicodeDecodeError, User.DoesNotExist):
            messages.warning(request, "Something went wrong. Please try again.")
            return render(request, 'auth/resetemail.html')
        
        context = {
            'uidb64': uidb64,
            'token': token
        }
        return render(request, 'auth/setnewpassword.html', context)
    
    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        
        password=request.POST.get['pass1']
        confirm_password=request.POST.get['pass2']
    
        if password!= confirm_password:
            messages.warning(request, "Password do not match")
            return render(request, 'auth/setnewpassword.html', context)
        
        try:
            # Decoding uidb64
            user_id = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=user_id)
            
           
            user.set_password(password)
            user.save()
            messages.success(request, "Password reset successfully. Please login with your new password.")
            return redirect('/shopauth/login/')
        except (DjangoUnicodeDecodeError, User.DoesNotExist):
            messages.error(request, "Something went wrong")
            return render(request, 'auth/setnewpassword.html', context)