# Hybrid-Quantum-Secure-Cryptosystem
##
This project is built with Django as the backend. To use this project, you need to start the Django server first and then access the development server through your localhost.

## Project setup Guide
You need to have the following installed on your system.
```
DB Browser >= 3.10
Django == 5.1.7
Python >= 3.11
Qiskit == 1.4.2
Qiskit AER == 0.17.0
```

### Follow the steps below to run the Hybrid Quantum Secure Cryptosystem on your PC.
* First, either clone this repository or download the complete source code. 
```
git clone https://github.com/andrew-vivan-x/hybrid_quantum_secure_cryptosystem.git
```
* Open the project-level directory inside the "Hybrid-Quantum-Secure-Cryptosystem" folder in your console or any IDE.
```
> cd Hybrid-Quantum-Secure-Cryptosystem-main
```
* It's best practice to run your projects in a virtual environment (VM) to avoid conflicts with other Python dependencies.
So to create one!
```
> python -m venv (your VM name)
```
* Now, navigate into your virtual environment (VM) by using the cd command.
```
> cd (your VM name)
```
* Now, navigate into "Scripts" using the cd command.
```
(your VM)> cd Scripts
```
* Activate the virtual environment using "activate"
```
(your VM)\Scripts> activate
```
* Navigate back to the main project directory using the cd command.
```
> cd ..
```
* Install the necessary requirements to run this project by using the following command:
```
> pip install -r requirements.txt
```
* Once all the requirements are installed, run your Django server using the following command:
```
> python manage.py runserver
```
* Visit the following link to access the interface
```
> http://127.0.0.1:8000/
```
##

### All the functionalities in our project are modular, except for those within a particular functionality. Therefore, run only the necessary operations that are needed to avoid port conflicts or WIN errors.

