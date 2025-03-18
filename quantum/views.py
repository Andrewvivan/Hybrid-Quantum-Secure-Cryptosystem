import subprocess
from django.shortcuts import render
from django.http import JsonResponse

# Home page
def home(request):
    return render(request, 'home.html')

# Quantum Key Distribution page
def quantum_key_distribution(request):
    if request.method == 'POST':
        role = request.POST.get('role')

        if role == 'qkd_sender':
            subprocess.Popen(['python', 'quantum/quantum_key_distribution/qkd_sender.py'])
        elif role == 'qkd_receiver':
            subprocess.Popen(['python', 'quantum/quantum_key_distribution/qkd_receiver.py'])
        elif role == 'qkd_eve':
            subprocess.Popen(['python', 'quantum/quantum_key_distribution/qkd_eve.py'])

        return render(request, 'result.html', {'message': f'{role.capitalize()} BB84 started successfully!'})

    return render(request, 'quantum_key_distribution.html')

# Post Quantum Cryptography page
def post_quantum_cryptography(request):
    if request.method == 'POST':
        role = request.POST.get('role')

        if role == 'kyber_sender':
            subprocess.Popen(['python', 'quantum/kyber_key_exchange/kyber_sender.py'])
        elif role == 'kyber_receiver':
            subprocess.Popen(['python', 'quantum/kyber_key_exchange/kyber_receiver.py'])

        return render(request, 'result.html', {'message': f'{role.replace("_", " ").capitalize()} started successfully!'})

    return render(request, 'post_quantum_cryptography.html')

# Quantum Secure Communication page
def quantum_secure_communication(request):
    if request.method == 'POST':
        role = request.POST.get('role')

        if role == 'basic_secure_sender':
            subprocess.Popen(['python', 'quantum/secure_communication/basic_secure_sender.py'])
        elif role == 'basic_secure_receiver':
            subprocess.Popen(['python', 'quantum/secure_communication/basic_secure_receiver.py'])
        # if role == 'basic_secure_sender':
        #     subprocess.Popen(['python', 'quantum/secure_communication/reference_implementations/sender_chat.py'])
        # elif role == 'basic_secure_receiver':
        #     subprocess.Popen(['python', 'quantum/secure_communication/reference_implementations/receiver_chat.py'])
        elif role == 'standard_secure_sender':
            subprocess.Popen(['python', 'quantum/secure_communication/standard_secure_sender.py'])
        elif role == 'standard_secure_receiver':
            subprocess.Popen(['python', 'quantum/secure_communication/standard_secure_receiver.py'])
        elif role == 'advanced_secure_sender':
            subprocess.Popen(['python', 'quantum/secure_communication/advanced_secure_sender.py'])
        elif role == 'advanced_secure_receiver':
            subprocess.Popen(['python', 'quantum/secure_communication/advanced_secure_receiver.py'])

        return render(request, 'result.html', {'message': f'{role.replace("_", " ").capitalize()} started successfully!'})

    return render(request, 'quantum_secure_communication.html')

# Key Management System page
def key_management_system(request):
    try:
        subprocess.Popen(['python', 'quantum/key_management_system/kms.py']) 
        message = "Quantum Secure Key Management System launched successfully!"
    except Exception as e:
        message = f"Failed to launch KMS: {str(e)}"
    
    return render(request, 'result.html', {'message': message})

# Data Protection
def data_protection(request):
    try:
        subprocess.Popen(['python', 'quantum/data_protection/dataprotection.py']) 
        message = "Quantum Secure Data Protection System launched successfully!"
    except Exception as e:
        message = f"Failed to launch Data Protection: {str(e)}"
    
    return render(request, 'result.html', {'message': message})
