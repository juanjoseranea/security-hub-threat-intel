from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('monitor/', views.dashboard, name='dashboard'),
    path('sync/', views.sync_now, name='sync'),
    path('sync-cisa/', views.sync_cisa, name='sync_cisa'),
    path('status/', views.system_status, name='status'),
    path('update-status/<int:pk>/', views.update_status, name='update_status'),
    path('trigger-manual-sync/', views.trigger_manual_sync, name='trigger_manual_sync'),
    path('add-note/<int:pk>/', views.add_note, name='add_note'),
    path('get-playbook/<int:pk>/', views.get_playbook, name='get_playbook'),
    path('mark-false-positive/<int:pk>/', views.mark_false_positive, name='mark_false_positive'),
    path('shift-report/', views.shift_report, name='shift_report'),
    path('export/', views.export_csv, name='export_csv'),
]
