from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('monitor/', views.dashboard, name='dashboard'),
    path('sync/', views.sync_now, name='sync'),
    path('status/', views.system_status, name='status'),
    path('update-status/<int:pk>/', views.update_status, name='update_status'),
    path('export/', views.export_csv, name='export_csv'),
]
