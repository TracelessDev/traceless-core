TRACELESS PROTOCOL (Alpha v0.0.1 - CLI Edition)
=================================================
Status: Polygon Amoy Testnet
Build: Public Alpha
Repo: https://github.com/TracelessDev/traceless-core

[ 1. MANIFESTO ]
Traceless is not a messenger. It is a protocol for permanent, uncensorable communication built on the Polygon blockchain.

Privacy on centralized servers is a myth. If they own the server, they own your words.
Traceless has no servers. No database. No admin panel.
Every message is a transaction. Every word is carved into the blockchain forever.

We cannot ban you. We cannot delete your messages. We cannot read them.

[ 2. USE CASES ]
- The Digital Dead Drop: Unstoppable delivery for journalists and sources.
- Dispute Resolution: Reveal your private key to a third party to mathematically prove what was said and when.
- Digital Inheritance: Leave instructions that will persist as long as the Ethereum Virtual Machine (EVM) exists.
- Proof of Authorship: Timestamp your ideas immutably.

[ 3. ARCHITECTURE & CRYPTOGRAPHY (DEEP DIVE) ]
For the engineers and cryptographers:

1. KEY GENERATION:
   - Standard SECP256K1 (Ethereum curve).
   - Private Key -> Derived Public Key -> Address.

2. ENCRYPTION FLOW (Client-Side):
   - Algorithm: AES-256-GCM.
   - Key Exchange: ECDH (Elliptic Curve Diffie-Hellman).
   - Process:
     a. Sender generates a temporary (Ephemeral) Key Pair.
     b. Shared Secret is calculated using: [Sender Ephemeral PrivKey] + [Recipient Static PubKey].
     c. Message is encrypted.
     d. Payload {Ephemeral PubKey + Nonce + Ciphertext} is packed into JSON.
     e. Payload is converted to HEX and put into the Transaction Input Data.

3. TRANSPORT:
   - Network: Polygon (EVM).
   - The transaction is sent with 0 Value (plus gas) to the recipient's address.
   - The message lives in the transaction history, not in the state storage.

[ 4. QUICK START GUIDE ]

WARNING: This Alpha runs on Polygon AMOY Testnet.
Messages are FREE. Do NOT use real MATIC.

STEP 1: LAUNCH
Run `traceless.exe`. Select "Create New Wallet" (Option 2).
SAVE YOUR SEED PHRASE. If you lose it, your identity is gone forever.

STEP 2: GET FUEL (GAS)
You need testnet tokens to pay for blockchain gas.
1. Copy your address from the menu (Option 4).
2. Go to a Faucet: https://faucet.polygon.technology/
3. Paste your address and claim free POL (MATIC).

STEP 3: THE HANDSHAKE
To write to someone, you need two things:
1. Their Wallet Address (The Mailbox).
2. Their Public Key (The Lock).
*Ask your contact to send you their Public Key (Option 4 in the menu).*

STEP 4: COMMUNICATE
Select "Write Message". Enter the address and paste the Public Key.
Wait 5-10 seconds for the blockchain to confirm your transaction.

[ 5. OPERATIONAL SECURITY (OPSEC) ]
The protocol protects the *content* of your messages. Your *anonymity* depends on you.

- NETWORK: The blockchain node sees your IP address when you send a transaction. For maximum anonymity, route your traffic through a system-wide VPN or Tor.
- FUNDING: On Mainnet, never fund your Traceless wallet from a KYC-exchange account if you wish to remain anonymous. Use mixers or P2P cash trades.
- METADATA: The blockchain records *who* sent a transaction to *whom* and *when*. It does not see *what* is inside.

[ 6. ROADMAP ]
- v1.0: Full GUI (Desktop App with "Glass" Design).
- v1.1: Media Support (IPFS/Arweave integration).
- v1.2: Local Database (SQLite) for instant history loading.

[ DISCLAIMER ]
This software is provided "as is". By using Traceless, you acknowledge that your encrypted messages become a public part of the blockchain history. The authors are not responsible for how this tool is used.

Welcome to the Resistance.


