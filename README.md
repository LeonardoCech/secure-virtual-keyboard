# Secure Virtual Keyboard

Este projeto foi desenvolvido pelos seguintes alunos de graduação de Eng. de Software na Universidade Católica de Santa Catarina - Polo de Jaraguá do Sul:

- Iohana Maria Linhares ( iohana.linhares@catolicasc.edu.br )
- Lavínia Vitória Kuhn ( lavinha.kuhn@catolicasc.edu.br )
- Leonardo Cech ( leonardo.cech@catolicasc.edu.br )
- Vinícius Henrique Bonazzoli Fogaça de Maria (vinicius.maria@catolicasc.edu.br)

### Abordagem escolhida

Foi discutido entre a equipe que para garantir maior segurança na autenticação de um usuário, é necessário que a senha não senha diretamente informada, já que isso seria um problema grave de segurança, por exemplo, ao enviar uma requisição via REST API contendo um JSON com usuário e senha, alguma entidade maliciosa poderia interceptar a requisição e ter acesso ao conteúdo.

Então, a forma escolhida de não deixar a senha vulnerável foi a de passar um vetor criptografado com os números escolhidos pelo usuário, para que o servidor backend teste cada possibilidade.

O serviço de autenticação tem um limite de requisições diária.

Exemplo de senha informada:
```
[[0, 1], [2, 5], [7, 8]]
```


### Backend

Foram utilizadas as tecnologias Poetry, Uvicorn e FastAPI para o sistema desenvolvido.

Requisitos para execução:
- Python (https://www.python.org/downloads/)
- Poetry (https://python-poetry.org/)

Para executar localmente, deve-se seguir as seguintes etapas:

- Realizar o clone do repositório;
- Acessar o diretório do clonado, e o serviço de Frontend com o seguinte comando no terminal (Windows):
```
cd /backend
``` 
- Baixar os pacotes necessários (é recomendado utilizar um ambiente virtual "venv"):
```
poetry shell
poetry install
```
- Executar o projeto:
```
py __init__.py
```

- Por fim, acessar a URL `http://localhost:7000/docs` em um navegador.

### Frontend

Foi utilizado o ReactJS como Framework para o sistema desenvolvido.

Requisitos para execução:
- Node (https://nodejs.org/en/download)

Para executar localmente, deve-se seguir as seguintes etapas:

- Realizar o clone do repositório;
- Acessar o diretório do clonado, e o serviço de Frontend com o seguinte comando no terminal (Windows):
```
cd /frontend
``` 
- Baixar os pacotes necessários (é recomendado utilizar um ambiente virtual "venv"):
```
npm install 
```
- Executar o projeto:
```
npm run dev
```
- Por fim, acessar a URL `http://localhost:4000` em um navegador.
