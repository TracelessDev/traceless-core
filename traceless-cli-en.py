# Traceless Protocol - Decentralized Encrypted Messaging CLI
# Version: 1.0 (MVP)
# Network: Polygon Amoy Testnet
# License: MIT / Unlicense (Public Domain)

import os
import json
import time
import getpass
from mnemonic import Mnemonic
from web3 import Web3
from hexbytes import HexBytes  # Essential for correct data type handling

# Import middleware for POA networks (Polygon)
try:
    from web3.middleware import ExtraDataToPOAMiddleware
except ImportError:
    from web3.middleware.proof_of_authority import geth_poa_middleware as ExtraDataToPOAMiddleware

from eth_account import Account

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --- CONFIGURATION ---
RPC_URL = "https://rpc-amoy.polygon.technology/"
CHAIN_ID = 80002

# Scanning settings
DEEP_SCAN_BLOCKS = 2000  # Blocks to check in "Deep Scan" mode
INITIAL_SCAN_BLOCKS = 200 # Blocks to check on first run
RPC_DELAY = 0.2  # Delay between requests to prevent rate-limiting (seconds)


# --- WEB3 INITIALIZATION ---
w3 = Web3(Web3.HTTPProvider(RPC_URL))
w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
Account.enable_unaudited_hdwallet_features()


# --- CRYPTOGRAPHY CORE ---

def generate_shared_secret(private_key_obj, peer_public_key_bytes):
    """ECDH: Generate shared secret."""
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
    shared_secret = private_key_obj.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_key(shared_secret):
    """HKDF: Derive encryption key from shared secret."""
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'traceless-protocol-key',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

def encrypt_message(recipient_public_key_pem, message):
    """Encrypt message using AES-GCM with ephemeral keys."""
    # 1. Generate ephemeral key pair for forward secrecy
    ephemeral_private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    ephemeral_public_key_pem = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # 2. Calculate shared secret
    shared_secret = generate_shared_secret(ephemeral_private_key, recipient_public_key_pem.encode())
    derived_key = derive_key(shared_secret)
    
    # 3. Encrypt
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
    
    # 4. Pack payload
    payload = {
        'ephemPublicKey': ephemeral_public_key_pem.decode('utf-8'),
        'nonce': nonce.hex(),
        'ciphertext': ciphertext.hex()
    }
    return json.dumps(payload)

def decrypt_message(private_key_pem, encrypted_payload_str):
    """Decrypt incoming message."""
    try:
        payload = json.loads(encrypted_payload_str)
        ephem_public_key_pem = payload['ephemPublicKey'].encode('utf-8')
        nonce = bytes.fromhex(payload['nonce'])
        ciphertext = bytes.fromhex(payload['ciphertext'])
        
        private_key_obj = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None
        )
        
        # Reconstruct shared secret
        shared_secret = generate_shared_secret(private_key_obj, ephem_public_key_pem)
        derived_key = derive_key(shared_secret)
        
        aesgcm = AESGCM(derived_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return None


# --- WALLET MANAGEMENT ---

def get_keys_from_seed(seed_phrase):
    """Derive keys and address from mnemonic phrase."""
    private_key_hex = Account.from_mnemonic(seed_phrase)._private_key.hex()
    
    # Convert to cryptography format
    private_key_obj = ec.derive_private_key(int(private_key_hex, 16), ec.SECP256K1())
    
    private_key_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_key_pem = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    address = Account.from_key(private_key_hex).address
    return private_key_hex, private_key_pem, public_key_pem, address


# --- NETWORK OPERATIONS ---

def send_message(sender_private_key, recipient_address, encrypted_message):
    """Send encrypted payload to blockchain."""
    sender_address = Account.from_key(sender_private_key).address
    
    tx = {
        'nonce': w3.eth.get_transaction_count(sender_address),
        'to': recipient_address,
        'value': w3.to_wei(0, 'ether'),
        'gas': 21000 + len(encrypted_message.encode('utf-8')) * 100, 
        'gasPrice': w3.eth.gas_price,
        'data': encrypted_message.encode('utf-8').hex(),
        'chainId': CHAIN_ID
    }
    
    try:
        signed_tx = w3.eth.account.sign_transaction(tx, sender_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"\n>>> Transaction Sent! Hash: {tx_hash.hex()}")
        print(">>> Waiting for confirmation...")
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(">>> Message confirmed on-chain.")
    except Exception as e:
        print(f"!!! Transaction Error: {e}")


# --- SCANNING LOGIC ---

def normalize_input_data(tx_input):
    """
    Standardizes Web3 input data to bytes.
    Handles HexBytes, str, and bytes.
    """
    if isinstance(tx_input, (bytes, HexBytes)):
        return tx_input
    elif isinstance(tx_input, str):
        if tx_input.startswith('0x'):
            return bytes.fromhex(tx_input[2:])
        return bytes.fromhex(tx_input)
    return b''

def check_messages(my_address, my_private_key_pem, scan_mode='normal'):
    state_file = f"state_{my_address}.json"
    
    try:
        latest_block = w3.eth.get_block('latest')['number']
    except Exception as e:
        print(f"RPC Connection Error: {e}")
        return

    start_block = 0
    if scan_mode == 'deep':
        start_block = max(0, latest_block - DEEP_SCAN_BLOCKS)
        print(f"--- DEEP SCAN INITIALIZED ({DEEP_SCAN_BLOCKS} blocks) ---")
    else:
        try:
            with open(state_file, 'r') as f: 
                saved_block = json.load(f).get('last_checked_block', 0)
                # Avoid overly long scans on quick check
                if latest_block - saved_block > 5000:
                     print("Long absence detected. Scanning last 1000 blocks.")
                     start_block = latest_block - 1000
                else:
                    start_block = saved_block
        except FileNotFoundError:
            start_block = max(0, latest_block - INITIAL_SCAN_BLOCKS)
            print("First run detected. Initializing archive...")

    if start_block >= latest_block:
        print("Up to date. No new blocks.")
        return

    print(f"Scanning range: {start_block + 1} -> {latest_block}")
    
    found_messages = False
    my_addr_lower = my_address.lower()
    
    current_scan = start_block + 1
    
    try:
        while current_scan <= latest_block:
            if current_scan % 10 == 0:
                print(f"\rProcessing... {current_scan}/{latest_block}", end='', flush=True)
            
            try:
                block = w3.eth.get_block(current_scan, full_transactions=True)
            except Exception as e:
                print(f"\nRead Error at block {current_scan}. Retrying in 2s...")
                time.sleep(2)
                continue

            for tx in block.transactions:
                to_addr = tx.get('to')
                if not to_addr: 
                    continue 
                
                if to_addr.lower() != my_addr_lower:
                    continue
                
                raw_input = tx.get('input', b'')
                
                if raw_input == '0x' or raw_input == b'' or raw_input == '0x0':
                    continue
                
                try:
                    encrypted_bytes = normalize_input_data(raw_input)
                    data_str = encrypted_bytes.decode('utf-8')
                    
                    if 'ephemPublicKey' in data_str and 'ciphertext' in data_str:
                        decrypted = decrypt_message(my_private_key_pem, data_str)
                        
                        if decrypted:
                            print(f"\n\n" + "="*50)
                            print(f"!!! INCOMING MESSAGE !!!")
                            print(f"From: {tx.get('from')}")
                            print(f"Block: {current_scan} | TX: {tx.get('hash').hex()}")
                            print("-" * 50)
                            print(f"> {decrypted}")
                            print("="*50 + "\n")
                            found_messages = True
                except Exception:
                    pass
            
            # Save state every 50 blocks
            if current_scan % 50 == 0:
                with open(state_file, 'w') as f: json.dump({'last_checked_block': current_scan}, f)

            current_scan += 1
            time.sleep(RPC_DELAY)
            
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
    
    print("\nScan complete.")
    
    with open(state_file, 'w') as f: json.dump({'last_checked_block': latest_block}, f)


# --- MAIN INTERFACE ---

def main():
    print("\n=== TRACELESS PROTOCOL CLI (v1.0) ===")
    print(f"Network: Polygon Amoy (ChainID: {CHAIN_ID})")
    print("Status: Decentralized & Uncensored\n")
    
    if not w3.is_connected():
        print(f"CRITICAL ERROR: Cannot connect to RPC {RPC_URL}")
        exit()

    account_data = None
    
    while not account_data:
        choice = input("1. Login (Seed Phrase)\n2. Create New Wallet\n> ").strip()
        if choice == '1':
            seed_phrase = getpass.getpass("Enter 12-word phrase: ")
            try:
                pk_hex, pk_pem, pub_pem, address = get_keys_from_seed(seed_phrase)
                account_data = {"pk_hex": pk_hex, "pk_pem": pk_pem, "pub_pem": pub_pem, "address": address}
                print(f"\nLogged in: {address}")
            except Exception as e:
                print(f"Key Error: {e}")
        elif choice == '2':
            seed_phrase = Mnemonic("english").generate(strength=128)
            pk_hex, pk_pem, pub_pem, address = get_keys_from_seed(seed_phrase)
            account_data = {"pk_hex": pk_hex, "pk_pem": pk_pem, "pub_pem": pub_pem, "address": address}
            print("\n--- SAVE THIS SEED PHRASE (IRRECOVERABLE IF LOST) ---")
            print(f"\n{seed_phrase}\n")
            input("Press Enter after saving...")
    
    while True:
        print("\n--- MENU ---")
        print("1. Send Message")
        print("2. Check Inbox (Quick)")
        print("3. Deep Scan (Find old messages)")
        print("4. Show My Keys")
        print("5. Exit")
        
        action = input("> ").strip()
        
        if action == '1':
            recipient = input("Recipient Address: ").strip()
            if not w3.is_address(recipient):
                print("Error: Invalid address format.")
                continue
                
            print("Paste Recipient's PUBLIC KEY (PEM format):")
            print("(Press Ctrl+D or Enter on empty line to finish)")
            lines = []
            while True:
                try:
                    line = input()
                except EOFError:
                    break
                if line.strip() == "-----END PUBLIC KEY-----":
                    lines.append(line)
                    break
                lines.append(line)
            recipient_pub_key = "\n".join(lines)
            
            if "-----BEGIN PUBLIC KEY-----" not in recipient_pub_key:
                print("Error: Invalid key format.")
                continue
                
            msg = input("Message: ")
            try:
                encrypted = encrypt_message(recipient_pub_key, msg)
                send_message(account_data['pk_hex'], recipient, encrypted)
            except Exception as e:
                print(f"Failure: {e}")

        elif action == '2':
            check_messages(account_data['address'], account_data['pk_pem'], scan_mode='normal')
        
        elif action == '3':
            check_messages(account_data['address'], account_data['pk_pem'], scan_mode='deep')
            
        elif action == '4':
            print(f"\nAddress: {account_data['address']}")
            print("Your Public Key (Share this with sender):")
            print(account_data['pub_pem'])
            
        elif action == '5':
            print("Session terminated.")
            break

if __name__ == "__main__":
    main()
