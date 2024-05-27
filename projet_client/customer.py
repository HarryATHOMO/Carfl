import requests
import json
import re  

from InscriptionCustomer import User_enreg
from ConnexionCustomer import User_connexion

url = 'https://localhost:8443'
resources = {'hello': '/api/hello'}
cert_path = 'C:/Users/orphe/Desktop/projet_client/keys/pythonClient.crt'
key_path = 'C:/Users/orphe/Desktop/projet_client/keys/pythonClient.key'

headers = {'Content-Type': 'application/json'}

# envoie de la requette Get 
response = requests.get(url + resources['hello'], headers=headers, cert=(cert_path, key_path), verify=False)

# Vérification du statut
if response.status_code == 200:
    # Traitement du JSON
    data = response.json()  
    print("Réponse du serveur:")
    print(data)
else:
    print('Votre demande a échoué avec le code de statut:', response.status_code)


print("\nTest d'inscription :")
User_enreg('Ali', 'ibubu', 'Ali.ibubu@example.com', '1234567890', 'SPass1', '01-01-1997', '1')

print("\nTest de connexion :")
User_connexion('Ali.ibubu@example.com', 'SPass1!')
