
from itertools import product
import json
import requests

def generate_passwords(vectors):
    all_combinations = list(product(*vectors))
    passwords = [''.join(map(str, combination)) for combination in all_combinations]
    return passwords
    

def sign_in_with_password(username, password, api_key, return_secure_token=False):
    
    passwords = generate_passwords(json.loads(password))

    # URL da API do Firebase para autenticação com senha
    url = f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={
        api_key}'


    for pwd in passwords:
        # Corpo da requisição em formato JSON
        data = {
            'email': username,
            'password': pwd,
            'returnSecureToken': return_secure_token
        }

        try:
            # Faz a requisição POST para a API do Firebase
            response = requests.post(url, json=data)

            # Verifica se a requisição foi bem-sucedida (código de status 200)
            if response.status_code == 200:
                # Retorna os dados da resposta (geralmente incluindo o token de acesso)
                return response.json()
            else:
                if (response.text.find('TOO_MANY_ATTEMPTS') != -1):
                    print('TOO_MANY_ATTEMPTS')
                    return None
                # Se a requisição não foi bem-sucedida, imprime a mensagem de erro
                print(f'SignInWithPassword ' + str(response.status_code) + ': ' + response.text)

        except Exception as error:
            print(f'SignInWithPassword: ' + str(error))

    return None
