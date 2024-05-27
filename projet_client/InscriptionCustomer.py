import requests
import json
import re

url = 'https://localhost:8443'
resources = {'register': '/api/User_enreg'}
cert_path = 'C:/Users/orphe/Desktop/projet_client/keys/pythonClient.crt'
key_path = 'C:/Users/orphe/Desktop/projet_client/keys/pythonClient.key'

headers = {'Content-Type': 'application/json'}

#control des données en entré (definition et implémentation des fonctions)
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

def is_valid_phone(phone):
    return phone.isdigit() and len(phone) == 12

def is_valid_password(password):
    regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{10,}$'
    return re.match(regex, password) is not None

#definition et implémentation de la fonction enregidtrement utilisatur
def User_enreg(prenom, nom, email, phone, password, naissance, sexe):
    if not (prenom and nom and email and phone and password and naissance and sexe):
        print("Tous les champs doivent être remplis.")
        return

    if not is_valid_email(email):
        print("L'email n'est pas valide.")
        return

    if not is_valid_phone(phone):
        print("Le numéro de téléphone n'est pas valide.")
        return

    if not is_valid_password(password):
        print("Le mot de passe doit contenir au moins 8 caractères.")
        return

    data = {
        'prenom':prenom,
        'nom':nom,
        'email': email,
        'phone': phone,
        'password': password,
        'naissance': naissance,
        'sexe':sexe
    }

    try:
        # Envoi de la requête POST avec vérification SSL (désactivée)
        response = requests.post(
            url + resources['enregistrement'],
            headers=headers,
            data=json.dumps(data),
            cert=(cert_path, key_path),
            verify=False
        )

        #statut de la réponse
        if response.status_code == 200:
            print("Utilisateur inscrit avec succès.")

        elif response.status_code == 403:
            print("Utilisateur déjà existant.")

        elif response.status_code == 400:
            print('Données incorrectes:', response.status_code)
            print('Réponse du serveur:', response.json())

        else:
            print('Votre demande a échoué avec le code de statut:', response.status_code)
            print('Réponse du serveur:', response.json())

    except requests.exceptions.RequestException as e:
        print(f"Une erreur s'est produite lors de la requête : {e}")

