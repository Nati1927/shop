from django.urls import path
from shopapp import views

urlpatterns = [
    path('',views.index,name='index')
   
]