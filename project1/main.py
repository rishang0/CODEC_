"""
Project 1: Cryptography Algorithms Implementation
Interactive command-line interface for SHA-256, AES-256, and RSA-2048 demonstrations.
"""

import rsa
import crypto_engine


def handle_sha256_menu() -> None:
    print("\n--- SHA-256 Hashing & Integrity Check ---")
    print("1. Generate SHA-256 Digest")
    print("2. Verify Message Integrity")
    choice = input("Select option (1-2): ").strip()

    if choice == "1":
        message = input("Enter text to hash: ")
        digest = crypto_engine.sha256_hash(message)
        print(f"\nSHA-256 Digest:\n{digest}")
    elif choice == "2":
        message = input("Enter original text: ")
        expected = input("Enter expected SHA-256 hex digest: ")
        is_valid = crypto_engine.verify_sha256(message, expected)
        status = "VALID (Integrity Verified)" if is_valid else "INVALID (Data Altered or Mismatch)"
        print(f"\nVerification Result: {status}")
    else:
        print("Invalid selection.")


def handle_aes_menu() -> None:
    print("\n--- AES-256 Symmetric Encryption (CTR + HMAC-SHA256) ---")
    print("1. Encrypt Message (Auto-generate 256-bit Key)")
    print("2. Decrypt Message")
    choice = input("Select option (1-2): ").strip()

    if choice == "1":
        message = input("Enter plaintext message: ")
        key = crypto_engine.generate_aes_key()
        result = crypto_engine.aes_encrypt(message, key)

        print("\nEncryption Successful:")
        print(f"Key (Hex)        : {result['key_hex']}")
        print(f"IV (Base64)      : {result['iv_b64']}")
        print(f"Ciphertext (B64) : {result['ciphertext_b64']}")
        print(f"HMAC Tag (B64)   : {result['tag_b64']}")
    elif choice == "2":
        try:
            key_hex = input("Enter AES Key (Hex): ").strip()
            iv_b64 = input("Enter IV (Base64): ").strip()
            ciphertext_b64 = input("Enter Ciphertext (Base64): ").strip()
            tag_b64 = input("Enter HMAC Tag (Base64): ").strip()

            key = bytes.fromhex(key_hex)
            plaintext = crypto_engine.aes_decrypt(ciphertext_b64, iv_b64, tag_b64, key)
            print(f"\nDecrypted Plaintext:\n{plaintext}")
        except Exception as exc:
            print(f"\nDecryption Error: {exc}")
    else:
        print("Invalid selection.")


def handle_rsa_menu(state: dict) -> None:
    print("\n--- RSA-2048 Asymmetric Encryption ---")
    print("1. Generate New RSA-2048 Key Pair")
    print("2. Encrypt Message with Current Public Key")
    print("3. Decrypt Ciphertext with Current Private Key")
    print("4. Display Current PEM Keys")
    choice = input("Select option (1-4): ").strip()

    if choice == "1":
        print("\nGenerating RSA-2048 key pair... please wait.")
        pub, priv = crypto_engine.generate_rsa_keypair(2048)
        state["rsa_pub"] = pub
        state["rsa_priv"] = priv
        print("RSA-2048 key pair generated and stored for this session.")
    elif choice == "2":
        if state["rsa_pub"] is None:
            print("No RSA keys in session. Generate a key pair first (Option 1).")
            return
        try:
            message = input("Enter plaintext message (max 245 bytes): ")
            ciphertext_b64 = crypto_engine.rsa_encrypt(message, state["rsa_pub"])
            print(f"\nRSA Ciphertext (Base64):\n{ciphertext_b64}")
        except Exception as exc:
            print(f"\nEncryption Error: {exc}")
    elif choice == "3":
        if state["rsa_priv"] is None:
            print("No RSA keys in session. Generate a key pair first (Option 1).")
            return
        try:
            ciphertext_b64 = input("Enter RSA Ciphertext (Base64): ").strip()
            plaintext = crypto_engine.rsa_decrypt(ciphertext_b64, state["rsa_priv"])
            print(f"\nDecrypted Plaintext:\n{plaintext}")
        except (rsa.DecryptionError, ValueError) as exc:
            print(f"\nDecryption Failed: {exc}")
    elif choice == "4":
        if state["rsa_pub"] is None or state["rsa_priv"] is None:
            print("No RSA keys in session. Generate a key pair first (Option 1).")
            return
        pub_pem, priv_pem = crypto_engine.export_rsa_keys_pem(
            state["rsa_pub"], state["rsa_priv"]
        )
        print("\n--- Public Key (PEM) ---")
        print(pub_pem)
        print("--- Private Key (PEM) ---")
        print(priv_pem)
    else:
        print("Invalid selection.")


def main() -> None:
    session_state = {"rsa_pub": None, "rsa_priv": None}

    while True:
        print("\n========================================================")
        print("  PROJECT 1: CRYPTOGRAPHY ALGORITHMS IMPLEMENTATION")
        print("========================================================")
        print("1. SHA-256 Hashing & Integrity Verification")
        print("2. AES-256 Symmetric Encryption & Decryption")
        print("3. RSA-2048 Asymmetric Encryption & Decryption")
        print("4. Exit")

        choice = input("\nEnter your choice (1-4): ").strip()

        if choice == "1":
            handle_sha256_menu()
        elif choice == "2":
            handle_aes_menu()
        elif choice == "3":
            handle_rsa_menu(session_state)
        elif choice == "4":
            print("\nExiting Project 1. Goodbye.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSession terminated by user.")