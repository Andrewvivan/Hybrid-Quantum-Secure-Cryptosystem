from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('quantum_key_distribution/', views.quantum_key_distribution, name='quantum_key_distribution'),
    path('quantum_secure_communication/', views.quantum_secure_communication, name='quantum_secure_communication'),
    path('post_quantum_cryptography/', views.post_quantum_cryptography, name='post_quantum_cryptography'),
    path('key_management_system/', views.key_management_system, name='key_management_system'),
    path('dataprotection/', views.data_protection, name='data_protection'),
]
