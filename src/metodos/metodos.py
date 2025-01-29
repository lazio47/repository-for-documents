import base64
from datetime import datetime
import os
import sys
import json
import time
import requests
from venv import logger
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.cryptography_utils import *
from utils.auxi import *

REPO_MESSAGE = "sou o repositorio"

# Métodos para executar os comandos
def rep_subject_credentials(password, credentials_file):
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        keys_data = {
            "private_key": base64.b64encode(encrypted_private_key).decode('utf-8'),
            "public_key": base64.b64encode(public_key).decode('utf-8'),
            "created_at": datetime.utcnow().isoformat()
        }

        with open(credentials_file, "w") as f:
            json.dump(keys_data, f, indent=4)

        print(f"Credenciais geradas e salvas com sucesso no arquivo: {credentials_file}")

    except Exception as e:
        logger.error(f"Erro ao gerar credenciais: {e}")
        sys.exit(1)


def rep_decrypt_file(encrypted_file, metadata_file, output_file=None):
    try:
        if not os.path.exists(encrypted_file):
            print(f"Erro: O arquivo criptografado '{encrypted_file}' não foi encontrado.")
            sys.exit(1)

        if not os.path.exists(metadata_file):
            print(f"Erro: O arquivo de metadados '{metadata_file}' não foi encontrado.")
            sys.exit(1)

        with open(metadata_file, 'r') as f:
            metadata = json.load(f)

        algorithm = metadata.get("algorithm", "AES_CBC")
        key = base64.b64decode(metadata.get("key"))
        iv = base64.b64decode(metadata.get("iv"))

        # metadata validation 
        if not algorithm or not key or not iv:
            print("Erro: Metadados incompletos. Certifique-se de que 'algorithm', 'key' e 'iv' estão presentes.")
            sys.exit(1)

        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()

        decrypted_content = decrypt_file_content(encrypted_data, key, iv, algorithm)

        if output_file:
            with open(output_file, "wb") as f:
                f.write(decrypted_content)
            print(f"Ficheiro descriptografado em: {output_file}")
        else:
            try:
                decrypted_text = decrypted_content.decode("utf-8")
                print("Conteúdo descriptografado (como texto):")
                print(decrypted_text)
            except UnicodeDecodeError:
                print("Conteúdo descriptografado (binário):")
                print(decrypted_content)

    except Exception as e:
        print(f"Erro ao descriptografar o ficheiro: {e}")
        sys.exit(1)


def decrypt_file_content(encrypted_data, key, iv, algorithm="AES_CBC"):
    try:
        if algorithm != "AES_CBC":
            raise ValueError("Algoritmo não suportado. Use 'AES_CBC'.")

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        decrypted_content = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_content

    except Exception as e:
        raise ValueError(f"Erro na descriptografia do arquivo: {e}")



def rep_create_org(state, org, username, name, email, public_key_file):
    try:
        repo_public_key_pem = state["REP_PUB_KEY"]

        with open(public_key_file, "r") as f:
            keys_data = json.load(f)
            user_public_key_pem = base64.b64decode(keys_data["public_key"]).decode("utf-8")

        payload = {
            "organization": org,
            "username": username,
            "name": name,
            "email": email,
            "user_public_key": user_public_key_pem,
            "timestamp": time.time()
        }

        endpoint = "/organization/create"
        private_key = None
        send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(f"Organização '{org}' criada!")

    except Exception as e:
        print(f"Erro ao criar organização: {e}")
        sys.exit(1)

def rep_list_orgs(state):
    if 'REP_ADDRESS' not in state:
        logger.error("REP_ADDRESS not set")
        sys.exit(-1)

    try:
        repo_public_key = state["REP_PUB_KEY"]
        response = requests.get(f'http://{state["REP_ADDRESS"]}/organization/list')
        if response.status_code == 200:
            if verify_signature(REPO_MESSAGE, response.json()["signature"], repo_public_key):
                print("Organizações:")
                print(json.dumps(response.json()["orgs"], indent=4))
            else:
                logger.error("Ligacao comprometida!")
        else:
            print(f"Erro ao listar organizações: {response.status_code} - {response.text}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Erro ao conectar ao repositório: {e}")

def rep_create_session(state, organization, username, password, credentials_file, session_file):
    try:
        with open(credentials_file, 'r') as file:
            keys_data = json.load(file)
        private_key_bytes = base64.b64decode(keys_data["private_key"])
        private_key = serialization.load_pem_private_key(private_key_bytes, password=password.encode(), backend=default_backend())
        public_key_pem = keys_data["public_key"]

        repo_public_key_pem = state["REP_PUB_KEY"]

        # Challenge
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        # Criar sessao
        message = f"Creating a session for {username} into {organization}"
        signature = base64.b64decode(get_assinatura(message, private_key))

        payload = {
            "organization": organization,
            "username": username,
            "public_key": public_key_pem,
            "message": message,
            "signature": base64.b64encode(signature).decode(),
            "timestamp": time.time()
        }

        endpoint = "/session/create"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        with open(session_file, 'w') as f:
            session_and_credentials = decrypted_response["response"]
            session_and_credentials["public_key"] = public_key_pem

            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            session_and_credentials["private_key"] = base64.b64encode(private_key_bytes).decode('utf-8')

            json.dump(session_and_credentials, f, indent=4)

        print(f"Sessão criada e salva em: {session_file}")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)

def rep_get_file(state, file_handle, output_file=None):
    if 'REP_ADDRESS' not in state:
        logger.error("REP_ADDRESS not set")
        sys.exit(-1)

    try:
        repo_public_key_pem = state["REP_PUB_KEY"]

        payload = {"file_handle": file_handle, "timestamp": time.time()}

        endpoint = "/file/download"
        private_key = None
        response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        if response.status_code == 200:
            file_content = response.json().get("file")
            if not file_content:
                print("Erro: Nenhum conteúdo de arquivo encontrado na resposta.")
                sys.exit(1)
            
            repo_public_key = serialization.load_pem_public_key(repo_public_key_pem.encode(), backend=default_backend())
            signature = base64.b64decode(response.json()["signature"])
            if not verify_signature(REPO_MESSAGE.encode(), signature, repo_public_key):
                logger.error("Ligacao comprometida!")
                exit(1)

            file_data = base64.b64decode(file_content)

            if output_file:
                with open(output_file, "wb") as f:
                    f.write(file_data)
                print(f"Arquivo salvo em: {output_file}")
            else:
                print("Conteúdo do arquivo recebido:")
                print(file_data)

        else:
            print(f"Erro ao baixar o arquivo: {response.status_code} - {response.text}")
            sys.exit(1)

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)

def rep_add_subject(state, session_file, username, name, email, credentials_file):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]

        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        with open(credentials_file, "r") as f:
            credentials = json.load(f)
            public_key = credentials.get("public_key")
            public_key = base64.b64decode(public_key).decode("utf-8")

        if not public_key:
            print("Erro: Chave pública do novo sujeito não encontrada no arquivo de credenciais.")
            sys.exit(1)

        payload = {
            "encrypted_session": encrypted_session,
            "new_subject": {
                "username": username,
                "name": name,
                "email": email,
                "public_key": public_key
            },
            "timestamp": time.time()
        }

        endpoint = "/subject/add"
        send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        logger.info(f"Sujeito '{username}' adicionado com sucesso à organização.")

    except Exception as e:
        print(f"Erro ao adicionar sujeito: {e}")
        sys.exit(1)


def rep_change_subject_status(state, session_file, username, action):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "username": username,
            "action": action,
            "timestamp": time.time()
        }

        endpoint = "/subject/status"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)
        print(decrypted_response["message"])

    except Exception as e:
        logger.error(f"Erro ao alterar status do sujeito: {e}")
        sys.exit(1)

def rep_suspend_subject(state, session_file, username):
    rep_change_subject_status(state, session_file, username, "suspend")

def rep_activate_subject(state, session_file, username):
    rep_change_subject_status(state, session_file, username, "activate")

def rep_add_role(state, session_file, role):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "role": role,
            "timestamp": time.time()
        }

        endpoint = "/role/add"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(decrypted_response["message"])

    except Exception as e:
        print(f"Erro ao adicionar role: {e}")
        sys.exit(1)

def rep_change_role_status(state, session_file, role, action):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "role": role,
            "action": action,
            "timestamp": time.time()
        }

        endpoint = "/role/status"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(decrypted_response["message"])

    except Exception as e:
        print(f"Erro ao alterar status da role: {e}")
        sys.exit(1)


def rep_suspend_role(state, session_file, role):
    rep_change_role_status(state, session_file, role, "suspend")


def rep_reactivate_role(state, session_file, role):
    rep_change_role_status(state, session_file, role, "reactivate")


def rep_modify_role(state, session_file, role, action, target):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "role": role,
            "action": action,
            "target": target,
            "timestamp": time.time()
        }

        endpoint = "/role/modify"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(decrypted_response["message"])

    except Exception as e:
        print(f"Erro ao modificar a role: {e}")
        sys.exit(1)


def rep_add_subject_to_role(state, session_file, role, username):
    rep_modify_role(state, session_file, role, "add_subject", username)


def rep_remove_subject_from_role(state, session_file, role, username):
    rep_modify_role(state, session_file, role, "remove_subject", username)


def rep_add_permission_to_role(state, session_file, role, permission):
    rep_modify_role(state, session_file, role, "add_permission", permission)


def rep_remove_permission_from_role(state, session_file, role, permission):
    rep_modify_role(state, session_file, role, "remove_permission", permission)


def rep_add_doc(state, session_file, document_name, file_path):
    try:
        session_data, encrypted_session = load_session(session_file)

        try:
            with open(file_path, "rb") as f:
                file_content = f.read()
        except FileNotFoundError:
            logger.error(f"Ficheiro '{file_path}' não encontrado.")
            sys.exit(1)

        file_content_b64 = base64.b64encode(file_content).decode("utf-8")
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "document_name": document_name,
            "file_content": file_content_b64,
            "timestamp": time.time()
        }

        endpoint = "/document/add"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(f"Documento '{document_name}' adicionado com sucesso.")
        print(f"Document Handle: {decrypted_response['document_handle']}")

    except Exception as e:
        print(f"Erro ao adicionar documento: {e}")
        sys.exit(1)


def rep_get_doc_metadata(state, session_file, document_name, metadata_file=None):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "document_name": document_name,
            "timestamp": time.time()
        }

        endpoint = "/document/metadata"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        decrypted_metadata = decrypted_response["metadata"]
        process_metadata(decrypted_metadata, metadata_file)

    except Exception as e:
        print(f"Erro ao buscar metadados do documento: {e}")
        sys.exit(1)


def rep_get_doc_file(state, session_file, document_name, output_file=None):
    try:
        restricted_metadata_file = "restricted_metadata_temp.json"  # ficheiro temporário para metadados restritos
        rep_get_doc_metadata(state, session_file, document_name, metadata_file=restricted_metadata_file)

        if not os.path.exists(restricted_metadata_file):
            logger.error(f"Metadados não encontrados.")
            sys.exit(1)

        with open(restricted_metadata_file, "r") as f:
            restricted_metadata = json.load(f)

        file_handle = restricted_metadata.get("file_handle")
        if not file_handle:
            logger.error("file_handle nao encontrado.")
            sys.exit(1)

        encrypted_file = "encrypted_file_temp.bin"  # Arquivo temporário para o conteúdo criptografado
        rep_get_file(state, file_handle, output_file=encrypted_file)

        logger.info(f"A descriptografar...")
        rep_decrypt_file(encrypted_file, restricted_metadata_file, output_file)

        os.remove(restricted_metadata_file)
        os.remove(encrypted_file)

    except Exception as e:
        print(f"Erro ao obter e descriptografar o arquivo do documento: {e}")
        sys.exit(1)


def rep_delete_doc(state, session_file, document_name):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "document_name": document_name,
            "timestamp": time.time()
        }

        endpoint = "/document/delete"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        deleted_file_handle = decrypted_response.get("message")
        logger.info(f"Documento delected. file_handle: '{deleted_file_handle}'.")

    except Exception as e:
        print(f"Erro ao tentar deletar o documento: {e}")
        sys.exit(1)


def rep_acl_doc(state, session_file, document_name, operation, role, permission):
    try:
        session_data, encrypted_session = load_session(session_file)
        if operation not in ["+", "-"]:
            print("Erro: Operação inválida. Use '+' para adicionar ou '-' para remover.")
            sys.exit(1)

        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "document_name": document_name,
            "operation": operation,
            "role": role,
            "permission": permission,
            "timestamp": time.time()
        }

        endpoint = "/document/acl"
        send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(f"ACL do documento '{document_name}' atualizado.")

    except Exception as e:
        print(f"Erro ao atualizar ACL do documento: {e}")
        sys.exit(1)


def rep_assume_role(state, session_file, role):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "role": role,
            "timestamp": time.time()
        }

        endpoint = "/role/assume"
        send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(f"Role assumido.")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


def rep_drop_role(state, session_file, role):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "role": role,
            "timestamp": time.time()
        }

        endpoint = "/role/drop"
        send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        print(f"Role droped com sucesso.")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


def rep_list_roles(state, session_file):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "timestamp": time.time()
        }

        endpoint = "/role/list"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        roles = decrypted_response.get("roles", [])
        print("Roles da sessão atual:")
        for role in roles:
            print(f" - {role}")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


def rep_list_subjects(state, session_file, username=None):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "timestamp": time.time()
        }
        if username:
            payload["username"] = username

        endpoint = "/subject/list"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        subjects = decrypted_response["subjects"]
        if username:
            print(f"Sujeito '{username}':")
            print(json.dumps(subjects.get(username, {}), indent=4))
        else:
            print("Lista de sujeitos:")
            for user, details in subjects.items():
                status = details.get("status", "unknown")
                print(f" - {user} (Status: {status})")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


def rep_list_role_subjects(state, session_file, role):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "role": role,
            "timestamp": time.time()
        }

        endpoint = "/role/subjects"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        subjects = decrypted_response.get("subjects", [])
        print(f"Sujeitos do role '{role}':")
        for subject in subjects:
            print(f" - {subject}")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


def rep_list_subject_roles(state, session_file, username):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "username": username,
            "timestamp": time.time()
        }

        endpoint = "/subject/roles"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        roles = decrypted_response.get("roles", [])
        print(f"Roles do sujeito '{username}':")
        for role in roles:
            print(f" - {role}")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


def rep_list_role_permissions(state, session_file, role):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "role": role,
            "timestamp": time.time()
        }

        endpoint = "/role/permissions"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        permissions = decrypted_response.get("permissions", [])
        print(f"Permissões da role '{role}':")
        for permission in permissions:
            print(f" - {permission}")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


def rep_list_permission_roles(state, session_file, permission):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "permission": permission,
            "timestamp": time.time()
        }

        endpoint = "/role/permission_roles"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        org_roles = decrypted_response.get("organization_roles", [])
        doc_roles = decrypted_response.get("document_roles", [])

        print(f"Roles com a permissão '{permission}':")
        for role in org_roles:
            print(f" - {role}")
        for role in doc_roles:
            print(f" - {role}")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)



def rep_list_docs(state, session_file, filters=None):
    try:
        session_data, encrypted_session = load_session(session_file)
        private_key = load_private_key(session_data)
        public_key_pem = session_data["public_key"]
        repo_public_key_pem = state["REP_PUB_KEY"]
        challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger)

        payload = {
            "encrypted_session": encrypted_session,
            "filters": filters or {},
            "timestamp": time.time()
        }

        endpoint = "/documents/list"
        decrypted_response = send_request(endpoint, payload, state, private_key, repo_public_key_pem)

        documents = decrypted_response.get("documents", [])
        print("Documentos disponíveis:")
        for doc in documents:
            print(f" - {doc['name']} (Criado por: {doc['creator']}, Data: {doc['create_date']})")

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)
