
import requests


def sign_in_with_password(username, password, api_key, return_secure_token=False):

    # URL da API do Firebase para autenticação com senha
    url = f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}'

    # Corpo da requisição em formato JSON
    data = {
        'email': username,
        'password': password,
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
            # Se a requisição não foi bem-sucedida, imprime a mensagem de erro
            print(f'SignInWithPassword API Error: [{response.status_code}] {response.text}')
            return None

    except Exception as error:
        print(f'SignInWithPassword API Error: {error}')
        return None
