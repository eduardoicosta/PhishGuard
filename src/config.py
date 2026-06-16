import os
from dotenv import load_dotenv

# Carrega as variáveis ocultas do arquivo .env
load_dotenv()

EMAIL_USUARIO = os.getenv("EMAIL_USUARIO")
EMAIL_SENHA = os.getenv("EMAIL_SENHA")

if not EMAIL_USUARIO or not EMAIL_SENHA:
    print("Aviso: Credenciais de e-mail não configuradas no arquivo .env!")