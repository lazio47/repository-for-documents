import base64
import copy
from datetime import datetime
import hashlib
import os
import sys
import time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.cryptography_utils import *
from models.newdb import *
from flask import Flask, request
import json
from psycopg2 import Binary

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"]
)

organizations = {}
sessions = {}
files = {}
documents = {}
payload_cache = set()

MASTER_PASSWORD = "masterpassword"
MASTER_KEY_FILE = "repo_master_key.bin"
SALT = b"fixed_salt"
PRIVATE_KEY_FILE = "repo_private_key.pem"
PUBLIC_KEY_FILE = "repo_public_key.pem"
TIMEOUT = 300
MESSAGE = f"sou o repositorio"
CACHE_EXPIRATION = 10

# Funcoes auxiliares
def derive_master_key():
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(MASTER_PASSWORD.encode())

def save_master_key(key):
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(key)

def load_master_key():
    if not os.path.exists(MASTER_KEY_FILE):
        master_key = derive_master_key()
        save_master_key(master_key)

    else:
        with open(MASTER_KEY_FILE, "rb") as f:
            master_key = f.read()

    return master_key

def generate_repo_keys(master_key):
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(master_key)
        )
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(encrypted_private_key)

        public_key = private_key.public_key()
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        print("Novas chaves geradas e salvas.")
    else:
        print("Chaves ja existentes.")

def validate_session(session_id, session_key, subject, organization):
    session_data = sessions.get(session_id)
    if not session_data:
        return False, f"Sessao invalida ou inexistente."
    if session_data["keys"] != session_key:
        return False, "Chave de sessao invalida."
    if session_data["organization"] != organization:
        return False, "Organizacao nao corresponde à sessao."
    if session_data["username"] not in organizations[organization]["subjects"]:
        return False, "O subject nao pertence  organizacao."
    if time.time() > int(session_data["create_date"]) + int(session_data["timeout"]):
        del sessions[session_id]

        for role_name, role_data in organizations[organization].get("roles", {}).items():
            if role_name != "Managers":
                role_data["subjects"] = [
                    s for s in role_data["subjects"] 
                    if s != f"{session_data['username']}:{session_id}"
                ]
                
        save_updated_data(organizations, sessions, files, documents)
        return False, "Sessao expirada."
    
    subject_data = organizations[organization]["subjects"].get(subject)
    if not subject_data:
        return False, "Sujeito nao encontrado na organizacao."
    if subject_data.get("status") != "active":
        return False, "O sujeito esta suspenso."
    
    return True, None


def validate_acl_permission(organization, subject, acl, required_permission):
    roles_in_acl = acl.keys()
    user_roles = [
        role_name for role_name, role_data in organizations[organization]["roles"].items()
        if subject in role_data["subjects"] and role_name in roles_in_acl
    ]

    for role in user_roles:
        if required_permission in acl[role]:
            return True
    return False

def load_initial_data():
    # Carrega dados da base de dados e retorna as estruturas globais.

    session = SessionLocal()
    organizations1 = {org.name: org.data for org in session.query(Organization).all()}
    sessions1 = {sess.session_id: sess.data for sess in session.query(Session).all()}
    files1 = {file.file_handle: {"data": file.data} for file in session.query(File).all()}
    documents1 = {doc.document_handle: doc.data for doc in session.query(Document).all()}

    session.close()
    return organizations1, sessions1, files1, documents1

def save_updated_data(organizations, sessions, files, documents):
    # Salva as estruturas globais atualizadas no banco.

    session = SessionLocal()

    try:
        for org_name, org_data in organizations.items():
            org = session.query(Organization).filter_by(name=org_name).first()
            if org:
                org.data = org_data
            else:
                session.add(Organization(name=org_name, data=org_data))

        for sess_id, sess_data in sessions.items():
            sess = session.query(Session).filter_by(session_id=sess_id).first()
            if sess:
                sess.data = sess_data
            else:
                session.add(Session(session_id=sess_id, data=sess_data))

        for file_handle, file_data in files.items():
            file = session.query(File).filter_by(file_handle=file_handle).first()
            binary_data = Binary(file_data["data"]) if isinstance(file_data["data"], bytes) else file_data["data"]
            if file:
                file.data = binary_data
            else:
                session.add(File(file_handle=file_handle, data=binary_data))

        for doc_handle, doc_data in documents.items():
            doc = session.query(Document).filter_by(document_handle=doc_handle).first()
            if doc:
                doc.data = doc_data
            else:
                session.add(Document(document_handle=doc_handle, data=doc_data))

        session.commit()
    except Exception as e:
        session.rollback()
        raise
    finally:
        session.close()
        
def is_duplicate(payload):
    if payload in payload_cache:
        return True

    payload_cache.add(payload)
    return False


# Endpoints
@app.route("/organization/create", methods=["POST"])
@limiter.limit("5 per minute")
def create_org():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()

        repo_private_key = load_private_key(private_key_data, password=load_master_key())
        
        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)
        
        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429

        org_name = decrypted_payload["organization"]
        username = decrypted_payload["username"]
        name = decrypted_payload["name"]
        email = decrypted_payload["email"]
        user_public_key = decrypted_payload["user_public_key"]
        print(user_public_key)

        if org_name in organizations:
            return json.dumps({"error": "Organizacao ja existe"}), 400

        organizations[org_name] = {
            "creator": username,
            "subjects": {
                username: {
                    "name": name,
                    "email": email,
                    "status": "active",
                    "public_key": user_public_key
                }
            },
            "roles": {
                "Managers": {
                    "permissions": ["ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", 'ROLE_NEW', 'ROLE_DOWN', 'ROLE_UP', 'ROLE_MOD', 'DOC_READ', 'DOC_DELETE', "DOC_ACL"],
                    "subjects": [username],
                    'status': 'active'
                }
            },
            "acl": {
                "Managers": ["ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", 'ROLE_NEW', 'ROLE_DOWN', 'ROLE_UP', 'ROLE_MOD']
            },
            "documents": []
        }

        # salvar na base de dados
        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))

        message = {"message": f"Organizacao criada.", "signature": base64.b64encode(signature).decode()}

        return json.dumps(message), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao criar organizacao"}), 500

    
@app.route("/challenge", methods=["POST"])
@limiter.limit("60 per minute")
def solve_challenge():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()

        repo_private_key = load_private_key(private_key_data, password=load_master_key())
        
        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)
        challenge = decrypted_payload["challenge"]
        response_payload = {"challenge": challenge}
        client_pub_key = base64.b64decode(decrypted_payload["public_key"]).decode()

        encrypted_response = hybrid_encrypt({"response": response_payload}, client_pub_key)

        save_updated_data(organizations, sessions, files, documents)
        return json.dumps({"encrypted_response": encrypted_response}), 201
    except Exception as e:
        return json.dumps({"error": f"Invalid task. - {e}"}), 500

    
@app.route("/organization/list", methods=["GET"])
@limiter.limit("10 per minute")
def list_orgs():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()

        repo_private_key = load_private_key(private_key_data, password=load_master_key())
        return json.dumps({"orgs": list(organizations.keys()), "signature": get_assinatura(MESSAGE, repo_private_key)}), 200
    
    except Exception as e:
        return json.dumps({"error": f"Erro ao listar organizacões: {str(e)}"}), 500
    
@app.route("/session/create", methods=["POST"])
@limiter.limit("10 per minute")
def create_session():
    try:
        with open("repo_private_key.pem", "rb") as f:
            repo_private_key_data = f.read()
        repo_private_key = load_private_key(repo_private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)
        
        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429

        organization = decrypted_payload["organization"]
        username = decrypted_payload["username"]
        signature = base64.b64decode(decrypted_payload["signature"])
        message = decrypted_payload["message"].encode()
        client_public_key_pem = base64.b64decode(decrypted_payload["public_key"]).decode()

        if organization not in organizations:
            return json.dumps({"error": "Organizacao nao encontrada"}), 404
        if username not in organizations[organization]["subjects"]:
            return json.dumps({"error": "Usuario nao pertence à organizacao"}), 403

        user_public_key = serialization.load_pem_public_key(client_public_key_pem.encode(), backend=default_backend())
        if not verify_signature(message, signature, user_public_key):
            return json.dumps({"error": "Assinatura invalida"}), 401

        session_id = generate_id()
        print("Session ID criada:", session_id)
        session_data = {
            "session_id": session_id,
            "organization": organization,
            "username": username,
            "keys": base64.b64encode(os.urandom(32)).decode(),
            'create_date': int(time.time()),
            "timeout": TIMEOUT
        }

        sessions[session_id] = session_data

        master_key = load_master_key()
        encrypted_session = encrypt_symmetric(json.dumps(session_data).encode(), master_key)
        response_payload = {"encrypted_session": encrypted_session, 'key': session_data["keys"]}

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"response": response_payload, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)
        save_updated_data(organizations, sessions, files, documents)
        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao criar sessao: {e}"}), 500


@app.route("/file/download", methods=["POST"])
@limiter.limit("10 per minute")
def download_file():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        file_handle = decrypted_payload.get("file_handle")

        if file_handle not in files:
            return json.dumps({"error": "File handle invalido."}), 400

        file_content = files[file_handle]["data"]

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        # Ainda estará encriptado
        return json.dumps({"file": file_content, "signature": base64.b64encode(signature).decode()}), 200

    except Exception as e:
        return json.dumps({"error": f"Erro ao processar requisicao: {e}"}), 500


    

@app.route("/subject/list", methods=["POST"])
@limiter.limit("10 per minute")
def list_subjects():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        print(repo_private_key)

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429

        encrypted_session = decrypted_payload.get("encrypted_session")
        requested_username = decrypted_payload.get("username")

        if not encrypted_session:
            return json.dumps({"error": "Sessao criptografada ausente"}), 400

        master_key = load_master_key()

        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")
        print("good")
        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(
            session_key=session_key,
            session_id=session_id,
            organization=organization,
            subject=subject
        )
        if not valid:
            return json.dumps({"error": error}), 401

        if organization not in organizations:
            return json.dumps({"error": "Organizacao nao encontrada."}), 404

        subjects = organizations[organization]["subjects"]
        if requested_username:
            subjects = {requested_username: subjects.get(requested_username)} if requested_username in subjects else {}

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"subjects": subjects, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)
        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao listar sujeitos: {e}"}), 500

@app.route("/subject/add", methods=["POST"])
@limiter.limit("10 per minute")
def add_subject():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())
        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        new_subject = decrypted_payload.get("new_subject")

        if not encrypted_session or not new_subject:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))
        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(
            session_key=session_key,
            session_id=session_id,
            organization=organization,
            subject=subject
        )
        if not valid:
            return json.dumps({"error": error}), 401

        roles = organizations[organization].get("roles", {})
        user_roles = [
            role_name for role_name, role_data in roles.items()
            if any(subj.split(":")[0] == subject for subj in role_data.get("subjects", []))
        ]

        org_acl = organizations[organization].get("acl", {})
        has_permission = any(
            "SUBJECT_NEW" in org_acl.get(role, [])
            for role in user_roles
        )

        if not has_permission:
            return json.dumps({"error": "Sem permissao."}), 403

        username = new_subject["username"]
        if username in organizations[organization]["subjects"]:
            return json.dumps({"error": "Sujeito ja existe"}), 400

        organizations[organization]["subjects"][username] = {
            "name": new_subject["name"],
            "email": new_subject["email"],
            "status": "active",
            "public_key": new_subject["public_key"]
        }

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": f"Subject adicionado.", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)
        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao adicionar sujeito: {e}"}), 500

@app.route("/subject/status", methods=["POST"])
@limiter.limit("10 per minute")
def change_subject_status():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        target_username = decrypted_payload.get("username")
        action = decrypted_payload.get("action")  # 'suspend' or 'activate'

        if not encrypted_session or not target_username or not action:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(
            session_key=session_key,
            session_id=session_id,
            organization=organization,
            subject=subject
        )
        if not valid:
            return json.dumps({"error": error}), 401

        if organization not in organizations:
            return json.dumps({"error": "Organizacao nao encontrada."}), 404

        org_acl = organizations[organization].get("acl", {})
        roles = organizations[organization].get("roles", {})
        user_roles = [
            role_name for role_name, role_data in roles.items()
            if any(subj.split(":")[0] == subject for subj in role_data.get("subjects", []))
        ]

        required_permission = "SUBJECT_DOWN" if action == "suspend" else "SUBJECT_UP"
        has_permission = any(
            required_permission in org_acl.get(role, [])
            for role in user_roles
        )

        if not has_permission:
            return json.dumps({"error": f"Nao permitido."}), 403

        subjects = organizations[organization]["subjects"]
        if target_username not in subjects:
            return json.dumps({"error": "Sujeito nao encontrado"}), 404
        
        if any(
            sub.split(":")[0] == target_username
            for role, role_data in roles.items()
            if role == "Managers"
            for sub in role_data.get("subjects", [])
        ):
            return json.dumps({"error": "Nao permitido."}), 403

        if action == "suspend":
            subjects[target_username]["status"] = "suspended"
        elif action == "activate":
            subjects[target_username]["status"] = "active"

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": f"Sujeito foi \"{action}\" com sucesso.", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao alterar status do sujeito: {e}"}), 500
    

@app.route("/role/add", methods=["POST"])
@limiter.limit("10 per minute")
def add_role():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        role_name = decrypted_payload.get("role")

        if not encrypted_session or not role_name:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")
        subject_with_session = f"{subject}:{session_id}"

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(
            session_key=session_key,
            session_id=session_id,
            organization=organization,
            subject=subject
        )
        if not valid:
            return json.dumps({"error": error}), 401

        if organization not in organizations:
            return json.dumps({"error": "Operacao nao realizada."}), 404

        acl = organizations[organization].get("acl", {})
        user_roles = [
            role_name for role_name, permissions in acl.items()
            if "ROLE_NEW" in permissions
        ]

        roles = organizations[organization].get("roles", {})
        if not any(subject in roles[role]["subjects"] or subject_with_session in roles[role]["subjects"] for role in user_roles):
            return json.dumps({"error": "Sem permissao."}), 403

        if role_name in roles:
            return json.dumps({"error": f"Role ja existe."}), 400

        organizations[organization].setdefault("roles", {})[role_name] = {
            "permissions": [],
            "subjects": [],
            "status": "active"
        }

        organizations[organization]["acl"][role_name] = []

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": f"Role adicionada.", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao adicionar role: {e}"}), 500

@app.route("/role/status", methods=["POST"])
@limiter.limit("10 per minute")
def change_role_status():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        role_name = decrypted_payload.get("role")
        action = decrypted_payload.get("action")

        if not encrypted_session or not role_name or action not in ["suspend", "reactivate"]:
            return json.dumps({"error": "Dados incompletos ou acao invalida"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")
        subject_with_session = f"{subject}:{session_id}"

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(
            session_key=session_key,
            session_id=session_id,
            organization=organization,
            subject=subject
        )
        if not valid:
            return json.dumps({"error": error}), 401

        if organization not in organizations:
            return json.dumps({"error": "Organizacao nao encontrada"}), 404

        roles = organizations[organization].get("roles", {})
        if role_name not in roles:
            return json.dumps({"error": f"Role '{role_name}' nao existe."}), 404

        acl = organizations[organization].get("acl", {})
        required_permission = "ROLE_DOWN" if action == "suspend" else "ROLE_UP"
        user_roles = [
            role for role, permissions in acl.items()
            if required_permission in permissions
        ]

        if not any(subject_with_session in roles[user_role]["subjects"] or subject in roles[user_role]["subjects"] for user_role in user_roles):
            return json.dumps({"error": f"Permissao '{required_permission}' necessaria."}), 403
        
        roles[role_name]["status"] = "suspended" if action == "suspend" else "active"

        organizations[organization]['roles'] = roles

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": f"Role foi \"{action}\".", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao alterar status da role: {e}"}), 500


@app.route("/role/modify", methods=["POST"])
@limiter.limit("10 per minute")
def modify_role():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        role_name = decrypted_payload.get("role")
        action = decrypted_payload.get("action")
        target = decrypted_payload.get("target")

        if not encrypted_session or not role_name or not action or not target:
            return json.dumps({"error": "Dados incompletos ou acao invalida"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(
            session_key=session_key,
            session_id=session_id,
            organization=organization,
            subject=subject
        )
        if not valid:
            return json.dumps({"error": error}), 401

        if organization not in organizations:
            return json.dumps({"error": "Organizacao nao encontrada"}), 404

        acl = organizations[organization].get("acl", {})
        user_roles = [
            role for role, permissions in acl.items()
            if f"{subject}:{session_id}" in organizations[organization]["roles"][role]["subjects"] or
            subject in organizations[organization]["roles"][role]["subjects"]
        ]
        
        required_permission = "ROLE_MOD"
        if not any(required_permission in acl.get(user_role, []) for user_role in user_roles):
            return json.dumps({"error": f"Permissao '{required_permission}' necessaria."}), 403

        roles = organizations[organization].get("roles", {})
        if role_name not in roles:
            return json.dumps({"error": f"Role '{role_name}' nao existe."}), 404


        if action == "add_subject":
            if target not in organizations[organization]["subjects"]:
                return json.dumps({"error": f"Usuario '{target}' nao encontrado na organizacao."}), 404
            roles[role_name]["subjects"].append(target)
            roles[role_name]["subjects"] = list(set(roles[role_name]["subjects"]))
        elif action == "remove_subject":
            if target not in roles[role_name]["subjects"]:
                return json.dumps({"error": f"Usuario '{target}' nao encontrado no role '{role_name}'."}), 404
            
            if role_name == 'Managers':
                return json.dumps({"error": 'Permissao negada.'}), 403
            
            roles[role_name]["subjects"].remove(target)
        elif action == "add_permission":
            roles[role_name]["permissions"].append(target)
            roles[role_name]["permissions"] = list(set(roles[role_name]["permissions"]))
            organizations[organization]['acl'][role_name].append(target)
            organizations[organization]['acl'][role_name] = list(set(organizations[organization]['acl'][role_name]))
        elif action == "remove_permission":
            if target not in roles[role_name]["permissions"]:
                roles[role_name]["permissions"].remove(target)
        else:
            return json.dumps({"error": "Acao invalida."}), 400

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": f"Acao '{action}' executada.", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao modificar a role: {e}"}), 500

@app.route("/document/add", methods=["POST"])
@limiter.limit("10 per minute")
def add_document():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        print("passou")

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        document_name = decrypted_payload.get("document_name")
        file_content = base64.b64decode(decrypted_payload.get("file_content"))

        if not encrypted_session or not document_name or not file_content:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))
        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        creator = session_data.get("username")

        print("passou")

        client_public_key_pem = organizations[organization]["subjects"][creator]["public_key"]

        # Validar a sessao
        valid, error = validate_session(session_id, session_key, creator, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        acl = organizations[organization].get("acl", {})
        user_roles = [
            role for role, permissions in acl.items()
            if f"{creator}:{session_id}" in organizations[organization]["roles"][role]["subjects"] or
            creator in organizations[organization]["roles"][role]["subjects"]
        ]
        if not any("DOC_NEW" in acl.get(user_role, []) for user_role in user_roles):
            return json.dumps({"error": "Permissao 'DOC_NEW' necessaria."}), 403

        file_key = os.urandom(32)  # Chave para o ficheiro
        encrypted_file = encrypt_symmetric(file_content, file_key)

        print("passou")

        # Criptografar a chave do ficheirio com a master key
        encrypted_file_key = encrypt_symmetric(file_key, master_key)

        file_handle = generate_id()
        document_handle = generate_id()

        files[file_handle] = {
            "data": encrypted_file["data"]  # Apenas o conteúdo criptografado
        }

        document_acl = {"Managers": ["DOC_READ", "DOC_DELETE", "DOC_ACL"]}

        documents[document_handle] = {
            "public_metadata": {
                "document_handle": document_handle,
                "name": document_name,
                "create_date": int(time.time()),
                "creator": creator,
                "file_handle": file_handle,
                "acl": document_acl,
                "deleter": None
            },
            "restricted_metadata": {
                "alg": "AES_CBC",
                "key": encrypted_file_key,
                "iv": encrypted_file["iv"]
            }
        }

        # Adicionar o documento à lista da organizacao
        organizations[organization]["documents"].append(document_handle)

        save_updated_data(organizations, sessions, files, documents)

        print(client_public_key_pem)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"document_handle": str(document_handle), "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        print("passou")

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao adicionar documento: {e}"}), 500


@app.route("/document/metadata", methods=["POST"])
@limiter.limit("10 per minute")
def get_document_metadata():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        document_name = decrypted_payload.get("document_name")

        if not encrypted_session or not document_name:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        # Verificar permissões
        document_handle = next(
            (handle for handle, metadata in documents.items()
             if metadata["public_metadata"]["name"] == document_name),
            None
        )

        if not document_handle:
            return json.dumps({"error": "Documento nao encontrado"}), 404

        document_metadata = documents[document_handle]
        acl = document_metadata["public_metadata"]["acl"]

        user_roles = [
            role for role, permissions in organizations[organization]["acl"].items()
            if any(
                entry.startswith(f"{subject}:") or entry == subject
                for entry in organizations[organization]["roles"][role]["subjects"]
            )
        ]

        if not any("DOC_READ" in acl.get(user_role, []) for user_role in user_roles):
            return json.dumps({"error": "Permissao 'DOC_READ' necessaria."}), 403

        encrypted_file_key = document_metadata["restricted_metadata"]["key"]

        if isinstance(encrypted_file_key, str):
            encrypted_file_key = json.loads(encrypted_file_key)

        if not isinstance(encrypted_file_key, dict) or "iv" not in encrypted_file_key or "data" not in encrypted_file_key:
            raise ValueError("Chave criptografada do arquivo esta em um formato invalido.")
        

        decrypted_file_key = decrypt_symmetric(encrypted_file_key, master_key)

        res = copy.deepcopy(document_metadata)
        res["restricted_metadata"]["key"] = base64.b64encode(decrypted_file_key).decode()

        # Processar a chave da sessao
        try:
            session_key_bytes = base64.b64decode(session_key)
            if len(session_key_bytes) not in (16, 24, 32):
                raise ValueError(f"Tamanho da chave invalido")
        except Exception as e:
            raise ValueError(f"Erro ao processar a chave de sessao")

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        result = {"metadata": res, "signature": base64.b64encode(signature).decode()}
        encrypted_metadata = hybrid_encrypt(result, client_public_key_pem)
        return json.dumps({"encrypted_response": encrypted_metadata}), 201

    except Exception as e:
        print(e)
        return json.dumps({"error": f"Erro ao buscar metadados do documento"}), 500


@app.route("/document/delete", methods=["POST"])
@limiter.limit("10 per minute")
def delete_document():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        document_name = decrypted_payload.get("document_name")

        if not encrypted_session or not document_name:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        document_handle = next(
            (handle for handle, metadata in documents.items()
             if metadata["public_metadata"]["name"] == document_name),
            None
        )

        if not document_handle:
            return json.dumps({"error": "Documento nao encontrado"}), 404

        document_metadata = documents[document_handle]
        acl = document_metadata["public_metadata"]["acl"]

        user_roles = [
            role for role, permissions in organizations[organization]["acl"].items()
            if f"{subject}:{session_id}" in organizations[organization]["roles"][role]["subjects"] or
            subject in organizations[organization]["roles"][role]["subjects"]
        ]

        if not any("DOC_DELETE" in acl.get(user_role, []) for user_role in user_roles):
            return json.dumps({"error": "Permissao negada."}), 403

        file_handle = documents[document_handle]["public_metadata"]["file_handle"]
        documents[document_handle]["public_metadata"]["file_handle"] = None
        documents[document_handle]["public_metadata"]["deleter"] = subject

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": file_handle, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao deletar o documento: {e}"}), 500
    

@app.route("/document/acl", methods=["POST"])
@limiter.limit("10 per minute")
def modify_document_acl():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        document_name = decrypted_payload.get("document_name")
        operation = decrypted_payload.get("operation")
        role = decrypted_payload.get("role")
        permission = decrypted_payload.get("permission")

        if not all([encrypted_session, document_name, operation, role, permission]):
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        document_handle = next(
            (handle for handle, metadata in documents.items()
             if metadata["public_metadata"]["name"] == document_name),
            None
        )
        if not document_handle:
            return json.dumps({"error": "Documento nao encontrado"}), 404

        document_metadata = documents[document_handle]
        acl = document_metadata["public_metadata"]["acl"]

        user_roles = [
            role_name for role_name, permissions in organizations[organization]["acl"].items()
            if f"{subject}:{session_id}" in organizations[organization]["roles"][role_name]["subjects"] or
            subject in organizations[organization]["roles"][role_name]["subjects"]
        ]

        has_document_acl_permission = any(
            "DOC_ACL" in acl.get(role_name, []) for role_name in user_roles
        )

        if not has_document_acl_permission:
            return json.dumps({"error": "Permissao 'DOC_ACL' necessaria."}), 403

        if operation == "+":
            acl.setdefault(role, []).append(permission)
            acl[role] = list(set(acl[role]))

            if organization not in organizations:
                organizations[organization] = {"roles": {}}

            if role not in organizations[organization]["roles"]:
                organizations[organization]["roles"][role] = {
                    "permissions": [],
                    "subjects": [],
                    "status": "active"
                }

            if subject not in organizations[organization]["roles"][role]["subjects"]:
                organizations[organization]["roles"][role]["subjects"].append(subject)

            if permission not in organizations[organization]["roles"][role]["permissions"]:
                organizations[organization]["roles"][role]["permissions"].append(permission)

        elif operation == "-":
            if role in acl and permission in acl[role]:
                acl[role].remove(permission)
                if not acl[role]:
                    del acl[role]
        else:
            return json.dumps({"error": "Operacao invalida."}), 400

        # update da ACL
        document_metadata["public_metadata"]["acl"][role] += acl

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": "ACL atualizado", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao modificar ACL do documento: {e}"}), 500
    

@app.route("/role/assume", methods=["POST"])
@limiter.limit("10 per minute")
def assume_role():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        role = decrypted_payload.get("role")

        if role == "Managers":
            return json.dumps({"error": "Role nao disponivel."}), 429

        if not encrypted_session or not role:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        # Validar a sessao
        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        roles = organizations[organization].get("roles", {})
        if role not in roles:
            return json.dumps({"error": "Role nao encontrado na organizacao."}), 404
        
        subject_identifier = f"{subject}:{session_id}"

        if subject not in roles[role]["subjects"]:
            roles[role]["subjects"].append(subject_identifier)

        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": "Role assumida.", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao assumir o role: {e}"}), 500
    

@app.route("/role/drop", methods=["POST"])
@limiter.limit("10 per minute")
def drop_role():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        role = decrypted_payload.get("role")

        if not encrypted_session or not role:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        # Validar a sessao
        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        # Verificar se o role existe
        roles = organizations[organization].get("roles", {})
        if role not in roles:
            return json.dumps({"error": "Role nao encontrado na organizacao."}), 404
        
        subject_identifier = f"{subject}:{session_id}"

        # Remover o usuario do role (subjects)
        if subject in roles[role]["subjects"] or subject_identifier in roles[role]["subjects"]:
            if role == 'Managers' and len(roles[role]["subjects"]) < 3:
                return json.dumps({"error": "O role 'Managers' nao pode ser removido."}), 403
            if subject_identifier in roles[role]["subjects"]:
                roles[role]["subjects"].remove(subject_identifier)
            elif subject in roles[role]["subjects"]:
                roles[role]["subjects"].remove(subject)
        else:
            return json.dumps({"error": f"Usuario '{subject}' nao esta associado ao role."}), 400
        
        save_updated_data(organizations, sessions, files, documents)

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"message": "Role droped.", "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao remover o role: {e}"}), 500
    

@app.route("/role/list", methods=["POST"])
@limiter.limit("10 per minute")
def list_roles():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")

        if not encrypted_session:
            return json.dumps({"error": "Sessao criptografada ausente."}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401
        
        # subject_identifier = f"{subject}:{session_id}"

        roles = [
            role_name for role_name, role_data in organizations[organization].get("roles", {}).items()
            if any(subj.split(":")[0] == subject for subj in role_data.get("subjects", []))
        ]

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"roles": roles, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao listar roles: {e}"}), 500


@app.route("/role/subjects", methods=["POST"])
@limiter.limit("10 per minute")
def list_role_subjects():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        role_name = decrypted_payload.get("role")

        if not encrypted_session or not role_name:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        # Validar a sessao
        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        # Verificar se o role existe na organizacao
        if organization not in organizations:
            return json.dumps({"error": "Organizacao nao encontrada."}), 404
        roles = organizations[organization].get("roles", {})
        if role_name not in roles:
            return json.dumps({"error": f"Role '{role_name}' nao encontrado na organizacao."}), 404

        role_subjects = roles[role_name].get("subjects", [])

        subject_names = [subject.split(":")[0] for subject in role_subjects]

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"subjects": subject_names, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao listar sujeitos do role: {e}"}), 500


@app.route("/subject/roles", methods=["POST"])
@limiter.limit("10 per minute")
def list_subject_roles():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        username = decrypted_payload.get("username")

        if not encrypted_session or not username:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        # Validar a sessao
        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        roles = [
            role_name for role_name, role_data in organizations[organization].get("roles", {}).items()
            if any(subj.split(":")[0] == username for subj in role_data.get("subjects", []))
        ]


        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"roles": roles, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201


    except Exception as e:
        return json.dumps({"error": f"Erro ao listar roles do sujeito: {e}"}), 500


@app.route("/role/permissions", methods=["POST"])
@limiter.limit("10 per minute")
def list_role_permissions():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        role_name = decrypted_payload.get("role")

        if not encrypted_session or not role_name:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        # Validar a sessao
        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        # Validar organizacao e role
        if organization not in organizations:
            return json.dumps({"error": "Organizacao nao encontrada."}), 404

        roles = organizations[organization].get("roles", {})
        if role_name not in roles:
            return json.dumps({"error": f"Role '{role_name}' nao existe na organizacao."}), 404

        # role_permissions = set(roles[role_name].get("permissions", []))
        org_acl_permissions = set(organizations[organization].get("acl", {}).get(role_name, []))

        document_permissions = []
        for doc_metadata in documents.values():
            acl = doc_metadata["public_metadata"].get("acl", {})
            if role_name in acl:
                document_permissions.extend(acl[role_name])

        # Combinar permissões
        all_permissions = list(org_acl_permissions.union(document_permissions))

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"permissions": all_permissions, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao listar permissões do role: {e}"}), 500


@app.route("/role/permission_roles", methods=["POST"])
@limiter.limit("10 per minute")
def list_permission_roles():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        permission = decrypted_payload.get("permission")

        if not encrypted_session or not permission:
            return json.dumps({"error": "Dados incompletos"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        # Obter roles organizacionais com a permissao
        roles = organizations[organization].get("roles", {})
        org_roles = [
            role_name for role_name, role_data in roles.items()
            if permission in role_data.get("permissions", [])
        ]

        # Obter roles de documentos com a permissao
        doc_roles = []
        for doc_handle, doc_metadata in documents.items():
            doc_name = doc_metadata["public_metadata"]["name"]
            acl = doc_metadata["public_metadata"].get("acl", {})
            doc_role_names = [
                role_name for role_name, role_permissions in acl.items()
                if permission in role_permissions
            ]
            if doc_role_names:
                doc_roles.append({doc_name: doc_role_names})

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"organization_roles": org_roles,
                                             "document_roles": doc_roles, 
                                             "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao listar roles com a permissao '{permission}': {e}"}), 500


@app.route("/documents/list", methods=["POST"])
@limiter.limit("10 per minute")
def list_documents():
    try:
        with open("repo_private_key.pem", "rb") as f:
            private_key_data = f.read()
        repo_private_key = load_private_key(private_key_data, password=load_master_key())

        decrypted_payload = hybrid_decrypt(request.json, repo_private_key)

        if is_duplicate(str(decrypted_payload)):
            return json.dumps({"error": "Comando duplicado."}), 429
        
        encrypted_session = decrypted_payload.get("encrypted_session")
        filters = decrypted_payload.get("filters", {})

        if not encrypted_session:
            return json.dumps({"error": "Sessao criptografada ausente"}), 400

        master_key = load_master_key()
        session_data = json.loads(decrypt_symmetric(encrypted_session, master_key))

        session_id = session_data.get("session_id")
        session_key = session_data.get("keys")
        organization = session_data.get("organization")
        subject = session_data.get("username")

        client_public_key_pem = organizations[organization]["subjects"][subject]["public_key"]

        valid, error = validate_session(session_id, session_key, subject, organization)
        if not valid:
            return json.dumps({"error": error}), 401

        org_documents = [
            metadata["public_metadata"]
            for metadata in documents.values()
            if metadata["public_metadata"]["creator"] in organizations[organization]["subjects"]
        ]

        # filtros opcionais
        username_filter = filters.get("username")
        date_filter = filters.get("date")
        date_operator = filters.get("operator")  # 'nt', 'ot', 'et'

        if username_filter:
            org_documents = [doc for doc in org_documents if doc["creator"] == username_filter]

        if date_filter and date_operator:
            try:
                filter_date = datetime.strptime(date_filter, "%d-%m-%Y").date()
                if date_operator == "nt":  # newer than
                    org_documents = [doc for doc in org_documents if datetime.fromtimestamp(doc["create_date"]).date() > filter_date]
                elif date_operator == "ot":  # older than
                    org_documents = [doc for doc in org_documents if datetime.fromtimestamp(doc["create_date"]).date() < filter_date]
                elif date_operator == "et":  # equal to
                    org_documents = [doc for doc in org_documents if datetime.fromtimestamp(doc["create_date"]).date() == filter_date]
                else:
                    return json.dumps({"error": "Operador de data invalido"}), 400
            except ValueError:
                return json.dumps({"error": "Formato de data invalido"}), 400

        signature = base64.b64decode(get_assinatura(MESSAGE, repo_private_key))
        encrypted_response = hybrid_encrypt({"documents": org_documents, "signature": base64.b64encode(signature).decode()}, client_public_key_pem)

        return json.dumps({"encrypted_response": encrypted_response}), 201

    except Exception as e:
        return json.dumps({"error": f"Erro ao listar documentos: {e}"}), 500




if __name__ == "__main__":
    organizations1, sessions1, files1, documents1 = load_initial_data()
    print('org: ', organizations1)
    print('sess: ', sessions1)
    print('files: ', files1)
    print('docs: ', documents1)
    organizations = organizations1
    sessions = sessions1
    files = files1
    documents = documents1
    master_key = load_master_key()
    generate_repo_keys(master_key=master_key)
    app.run(host="127.0.0.1", port=5000, debug=True)