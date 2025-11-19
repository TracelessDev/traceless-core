# decrypt_tool.py

# --- КОПИРУЕМ ВСЕ НУЖНЫЕ ФУНКЦИИ ИЗ ОСНОВНОГО СКРИПТА ---
import json
from mnemonic import Mnemonic
from eth_account import Account
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

Account.enable_unaudited_hdwallet_features()

# --- БЛОК КРИПТОГРАФИИ (без изменений) ---
def generate_shared_secret(private_key_obj, peer_public_key_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
    shared_secret = private_key_obj.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_key(shared_secret):
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b'traceless-protocol-key', backend=default_backend()
    ).derive(shared_secret)
    return derived_key

def decrypt_message(private_key_pem, encrypted_payload_str):
    try:
        payload = json.loads(encrypted_payload_str)
        ephem_public_key_pem = payload['ephemPublicKey'].encode('utf-8')
        nonce = bytes.fromhex(payload['nonce'])
        ciphertext = bytes.fromhex(payload['ciphertext'])
        private_key_obj = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        shared_secret = generate_shared_secret(private_key_obj, ephem_public_key_pem)
        derived_key = derive_key(shared_secret)
        aesgcm = AESGCM(derived_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # Возвращаем ошибку, чтобы понять, что пошло не так
        return f"ОШИБКА ДЕШИФРОВКИ: {e}"

# --- БЛОК УПРАВЛЕНИЯ КОШЕЛЬКОМ (без изменений) ---
def get_keys_from_seed(seed_phrase):
    private_key_hex = Account.from_mnemonic(seed_phrase)._private_key.hex()
    private_key_obj = ec.derive_private_key(int(private_key_hex, 16), ec.SECP256K1())
    private_key_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    return private_key_pem

# --- ОСНОВНАЯ ЛОГИКА ИНСТРУМЕНТА ---
def main():
    print("--- Traceless Decryption Tool ---")
    
    # 1. Получаем Input Data из Polygonscan
    print("\nСкопируйте 'Input Data' из транзакции на Polygonscan (в виде 0x...):")
    hex_data = input("> ").strip()
    
    # 2. Получаем сид-фразу получателя
    print("\nВведите сид-фразу ПОЛУЧАТЕЛЯ (12 слов):")
    seed_phrase = input("> ").strip()

    try:
        # 3. Конвертируем HEX в строку
        data_str = bytes.fromhex(hex_data[2:]).decode('utf-8')
        print("\n[INFO] Данные успешно сконвертированы из HEX.")
        
        # 4. Получаем приватный ключ из сида
        private_key_pem = get_keys_from_seed(seed_phrase)
        print("[INFO] Приватный ключ получателя успешно извлечен из сид-фразы.")
        
        # 5. Пытаемся расшифровать
        print("[INFO] Попытка дешифровки...")
        decrypted_message = decrypt_message(private_key_pem, data_str)
        
        print("\n" + "="*50)
        print("РЕЗУЛЬТАТ:")
        print(f"> {decrypted_message}")
        print("="*50)

    except Exception as e:
        print(f"\n[КРИТИЧЕСКАЯ ОШИБКА] Не удалось обработать данные. Причина: {e}")

if __name__ == "__main__":
    main()
