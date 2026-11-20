"""
Project 2: Password Hashing, Cracking Simulation & Security Auditor
Interactive command-line tool for demonstrating hashing defenses and auditing passwords.
"""

import hashing_engine


def handle_unsalted_vs_salted() -> None:
    print("\n--- Unsalted vs. Salted Hashing Comparison ---")
    password = input("Enter a password to test: ")

    unsalted_1 = hashing_engine.unsalted_hash(password, "sha256")
    unsalted_2 = hashing_engine.unsalted_hash(password, "sha256")

    salt_1, salted_1 = hashing_engine.salted_sha256_hash(password)
    salt_2, salted_2 = hashing_engine.salted_sha256_hash(password)

    print("\n[1] Unsalted SHA-256 (Two separate users with the SAME password):")
    print(f"    User A Hash : {unsalted_1}")
    print(f"    User B Hash : {unsalted_2}")
    print("    -> Risk: Identical digests expose duplicate passwords and allow rainbow table lookups.")

    print("\n[2] Salted SHA-256 (Unique 16-byte random salt per user):")
    print(f"    User A Salt : {salt_1}")
    print(f"    User A Hash : {salted_1}")
    print(f"    User B Salt : {salt_2}")
    print(f"    User B Hash : {salted_2}")
    print("    -> Defense: Unique salts produce completely different digests for the same password.")


def handle_dictionary_attack() -> None:
    print("\n--- Offline Dictionary Attack Simulation (Educational) ---")
    print("1. Hash a password and test cracking it")
    print("2. Crack an existing unsalted MD5 or SHA-256 hex hash")
    choice = input("Select option (1-2): ").strip()

    algo = input("Algorithm (md5 / sha256) [default: sha256]: ").strip().lower() or "sha256"
    if algo not in ("md5", "sha256"):
        print("Unsupported algorithm. Using sha256.")
        algo = "sha256"

    if choice == "1":
        pw = input("Enter password (try 'admin123' or 'qwerty' to see a hit): ")
        target_hash = hashing_engine.unsalted_hash(pw, algo)
        print(f"Generated {algo.upper()} hash: {target_hash}")
    elif choice == "2":
        target_hash = input(f"Enter target {algo.upper()} hex hash: ").strip()
    else:
        print("Invalid selection.")
        return

    result = hashing_engine.simulate_dictionary_attack(target_hash, algorithm=algo)
    print("\nAttack Result:")
    if result["cracked"]:
        print(f"  Status     : CRACKED")
        print(f"  Plaintext  : {result['password']}")
        print(f"  Attempts   : {result['attempts']}")
        print(f"  Time Taken : {result['elapsed_ms']:.4f} ms")
    else:
        print(f"  Status     : NOT FOUND in built-in wordlist")
        print(f"  Attempts   : {result['attempts']}")
        print(f"  Time Taken : {result['elapsed_ms']:.4f} ms")


def handle_pbkdf2_benchmark() -> None:
    print("\n--- PBKDF2-HMAC-SHA256 Key Stretching & Benchmark ---")
    password = input("Enter password to hash and benchmark: ")
    iter_input = input("Enter iteration count [default: 600000]: ").strip()

    try:
        iterations = int(iter_input) if iter_input else 600_000
        if iterations < 1000:
            print("Iteration count too low; using minimum of 1000.")
            iterations = 1000
    except ValueError:
        print("Invalid number; defaulting to 600,000.")
        iterations = 600_000

    record = hashing_engine.pbkdf2_hash(password, iterations=iterations)
    bench = hashing_engine.benchmark_hashing(password, iterations=iterations)

    print("\nStored PBKDF2 Record:")
    print(f"  Algorithm  : {record['algorithm']}")
    print(f"  Iterations : {record['iterations']:,}")
    print(f"  Salt (Hex) : {record['salt_hex']}")
    print(f"  Hash (Hex) : {record['hash_hex']}")

    print("\nPerformance Benchmark (Defending Against GPU Brute-Force):")
    print(f"  Raw SHA-256 Time : {bench['sha256_ms']:.4f} ms")
    print(f"  PBKDF2 Time      : {bench['pbkdf2_ms']:.2f} ms")
    print(f"  Slowdown Factor  : ~{bench['slowdown_factor']:,.1f}x slower for an attacker")

    # Verification check
    verify_pw = input("\nRe-enter password to test PBKDF2 verification: ")
    is_match = hashing_engine.verify_pbkdf2(
        verify_pw, str(record["salt_hex"]), str(record["hash_hex"]), iterations
    )
    print(f"Verification Result: {'MATCH' if is_match else 'NO MATCH'}")


def handle_password_audit() -> None:
    print("\n--- Password Strength & Entropy Auditor ---")
    password = input("Enter a password to audit: ")
    report = hashing_engine.audit_password(password)

    print("\nAudit Summary:")
    print(f"  Length                  : {report['length']} characters")
    print(f"  Character Pool Size     : {report['pool_size']} possible characters")
    print(f"  Estimated Entropy       : {report['entropy_bits']} bits")
    print(f"  Security Rating         : {report['rating']}")
    print(f"  In Common Breach List   : {'YES' if report['in_common_list'] else 'No'}")
    print(f"  Crack Time (Unsalted)   : {report['crack_time_unsalted_sha256']}")
    print(f"  Crack Time (PBKDF2)     : {report['crack_time_pbkdf2_600k']}")

    print("\nRemediation Recommendations:")
    for idx, tip in enumerate(report["remediation"], start=1):
        print(f"  {idx}. {tip}")


def main() -> None:
    while True:
        print("\n============================================================")
        print("  PROJECT 2: PASSWORD HASHING & SECURITY AUDITOR")
        print("============================================================")
        print("1. Compare Unsalted vs. Salted SHA-256 Hashing")
        print("2. Simulate Offline Dictionary Attack on Unsalted Hashes")
        print("3. PBKDF2-HMAC-SHA256 Key Stretching & Speed Benchmark")
        print("4. Password Strength, Entropy & Crack-Time Auditor")
        print("5. Exit")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == "1":
            handle_unsalted_vs_salted()
        elif choice == "2":
            handle_dictionary_attack()
        elif choice == "3":
            handle_pbkdf2_benchmark()
        elif choice == "4":
            handle_password_audit()
        elif choice == "5":
            print("\nExiting Project 2. Goodbye.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSession terminated by user.")