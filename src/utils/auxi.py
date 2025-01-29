import sys
from utils.cryptography_utils import *
from cryptography.hazmat.primitives.serialization import load_pem_private_key

REPO_MESSAGE = "sou o repositorio"

def validate_encrypted_response(response, private_key, repo_public_key_pem):
    encrypted_response = response.json()["encrypted_response"]
    decrypted_response = hybrid_decrypt(encrypted_response, private_key)
    repo_public_key = serialization.load_pem_public_key(repo_public_key_pem.encode(), backend=default_backend())
    signature = base64.b64decode(decrypted_response["signature"])
    if not verify_signature(REPO_MESSAGE.encode(), signature, repo_public_key):
        raise ValueError("Ligacao comprometida!")
    return decrypted_response

def send_request(endpoint, payload, state, private_key, repo_public_key_pem):
    encrypted_payload = hybrid_encrypt(payload, repo_public_key_pem)
    response = requests.post(f"http://{state['REP_ADDRESS']}{endpoint}", json=encrypted_payload)
    if response.status_code != 201:
        raise ValueError(f"Erro: {response.status_code} - {response.text}")
    return validate_encrypted_response(response, private_key, repo_public_key_pem)

def load_private_key(session_data):
    private_key_bytes = base64.b64decode(session_data["private_key"])
    return load_pem_private_key(private_key_bytes, password=None)

def load_session(session_file):
    with open(session_file, "r") as f:
        session_data = json.load(f)

    encrypted_session = session_data.get("encrypted_session")
    if not encrypted_session:
        print("Erro: Sessão criptografada ausente no arquivo.")
        sys.exit(1)
    
    return session_data, encrypted_session