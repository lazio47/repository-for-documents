import os
import base64
import json
import uuid
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.exceptions import InvalidSignature
import requests


def generate_id():
        return str(uuid.uuid4())

def load_private_key(encrypted_key_pem, password):
    return serialization.load_pem_private_key(
        encrypted_key_pem.encode(),
        password=password.encode(),
    )


def encrypt_with_public_key(data, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def encrypt_payload(payload, public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        encrypted_payload = public_key.encrypt(
            json.dumps(payload).encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_payload).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Erro ao criptografar payload: {e}")
    

def hybrid_encrypt(payload, public_key_pem):
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_payload = padder.update(json.dumps(payload).encode()) + padder.finalize()
        encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "encrypted_payload": base64.b64encode(encrypted_payload).decode('utf-8')
        }

    except Exception as e:
        raise ValueError(f"Erro na criptografia híbrida: {e}")


def hybrid_decrypt(encrypted_data, private_key_pem):
    try:
        if not isinstance(private_key_pem, rsa.RSAPrivateKey):
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
        else:
            private_key = private_key_pem
            
        encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
        iv = base64.b64decode(encrypted_data["iv"])
        encrypted_payload = base64.b64decode(encrypted_data["encrypted_payload"])
        aes_key = private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_payload = decryptor.update(encrypted_payload) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        payload = unpadder.update(padded_payload) + unpadder.finalize()
        return json.loads(payload.decode('utf-8'))

    except Exception as e:
        raise ValueError(f"Erro na descriptografia híbrida: {e}")

def decrypt_payload(encrypted_payload_b64, private_key_pem, password=None):
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=password.encode() if password else None,
            backend=default_backend()
        )
        
        encrypted_payload = base64.b64decode(encrypted_payload_b64)
        decrypted_payload = private_key.decrypt(
            encrypted_payload,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return json.loads(decrypted_payload.decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Erro ao descriptografar payload: {e}")

def load_private_key(key_data, password=None):
    try:
        if isinstance(key_data, str):
            key_data = key_data.encode()
        private_key = serialization.load_pem_private_key(
            key_data,
            password=password if password else None,
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        raise ValueError(f"Erro ao carregar a chave privada: {e}")

def encrypt_symmetric(data, key):
    """Criptografa dados simetricamente com AES e uma chave fornecida."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return {
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(encrypted_data).decode()
    }


def decrypt_symmetric(encrypted_data, key):
    try:
        iv = base64.b64decode(encrypted_data["iv"])
        encrypted_bytes = base64.b64decode(encrypted_data["data"])
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data
    except Exception as e:
        raise ValueError(f"Erro ao descriptografar os dados: {e}")

def get_assinatura(message, private_key):
    signature = private_key.sign(
        message.encode(),
        rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(message, signature, user_public_key):
    try:
        user_public_key.verify(
            signature,
            message,
            rsa_padding.PSS(
                mgf=rsa_padding.MGF1(hashes.SHA256()),
                salt_length=rsa_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    
def load_public_key(public_key_pem):
    return serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())

def challenge_to_repository(repo_public_key_pem, state, private_key, public_key_pem, logger):
    challenge = os.urandom(8).hex()
    payload = {"challenge": challenge, "public_key": public_key_pem}
    encrypted_payload = hybrid_encrypt(payload, repo_public_key_pem)
    response = requests.post(f"http://{state['REP_ADDRESS']}/challenge", json=encrypted_payload)
    encrypted_response = response.json()["encrypted_response"]
    decrypted_response = hybrid_decrypt(encrypted_response, private_key)
    if response.status_code == 201:
        if decrypted_response["response"]["challenge"] != challenge:
            logger.error("Ligacao comprometida.")
            exit(1)
        logger.info('Conexao segura.')
    else:
        logger.error("Error in the task.")
        exit(1)