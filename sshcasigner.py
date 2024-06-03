import argparse
import configparser
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta

# Load configuration from /etc/sshcasigner.conf
CONFIG_FILE = '/etc/sshcasigner.conf'
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Configuration options
CA_KEY = config.get('DEFAULT', 'user_ca')
DB_FILE = config.get('DEFAULT', 'sqlite_file')
HOST_CA = config.get('DEFAULT', 'host_ca', fallback=None)
DEFAULT_VALIDITY = config.get('DEFAULT', 'default_validity', fallback=None)
KRL_FILE = config.get('DEFAULT', 'krl_file', fallback=None)

# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS certificates (
                        id INTEGER PRIMARY KEY,
                        identity TEXT NOT NULL,
                        public_key TEXT NOT NULL,
                        principals TEXT NOT NULL,
                        issued_at TEXT NOT NULL,
                        valid_until TEXT,
                        certificate TEXT,
                        revoked TEXT DEFAULT NULL)''')
    conn.commit()
    conn.close()
    print("Database initialized.")

# Get identity from the public key file
def get_identity_from_key(public_key_file):
    with open(public_key_file, 'r') as pubkey:
        first_line = pubkey.readline().strip()
        return first_line.split()[2]

# Insert initial certificate information into the database and get the ID
def insert_initial_info(identity, user_public_key, principals, valid_until):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    issued_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''INSERT INTO certificates (identity, principals, public_key, issued_at, valid_until) 
                      VALUES (?, ?, ?, ?, ?)''', 
                      (identity, principals, user_public_key, issued_at, valid_until))
    cert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return cert_id

# Delete preliminary entry from the database
def delete_preliminary_entry(cert_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''DELETE FROM certificates WHERE id = ?''', (cert_id,))
    conn.commit()
    conn.close()

# Update certificate information in the database
def update_certificate_info(cert_id, certificate):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''UPDATE certificates 
                      SET certificate = ? 
                      WHERE id = ?''', 
                      (certificate, cert_id))
    conn.commit()
    conn.close()

# Sign a user certificate
def sign_user_certificate(cert_id, identity, user_public_key_file, principals, validity_end=None):
    cert_file = f"{os.path.splitext(os.path.abspath(user_public_key_file))[0]}-cert.pub"

    # Base command
    cmd = [
        "ssh-keygen",
        "-s", CA_KEY,
        "-I", identity,
        "-n", principals,
        "-z", str(cert_id),
        user_public_key_file
    ]

    # Add validity argument if specified
    if validity_end:
        cmd.insert(-1, "-V")
        cmd.insert(-1, validity_end)

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error signing certificate: {e}")
        delete_preliminary_entry(cert_id)
        return None

    if os.path.exists(cert_file):
        with open(cert_file, 'r') as cert:
            certificate = cert.read().strip()

        # Update certificate information in the database
        update_certificate_info(cert_id, certificate)

        print(f"Certificate signed and stored for identity {identity}.")
    else:
        print(f"Failed to find the signed certificate file {cert_file}.")
        delete_preliminary_entry(cert_id)

# Create Key Revocation List (KRL) file
def make_krl(output_file=None, force=False):
    if not output_file:
        output_file = KRL_FILE
    if not output_file:
        raise ValueError("Output file not specified.")
    if os.path.exists(output_file) and not force:
        print("KRL file already exists. Use --force to overwrite.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM certificates WHERE revoked IS NOT NULL")
    revoked_ids = [str(row[0]) for row in cursor.fetchall()]
    conn.close()

    if revoked_ids:
        cmd = ["ssh-keygen", "-k", "-f", output_file] + revoked_ids
        subprocess.run(cmd)
        print(f"KRL file generated: {output_file}")
    else:
        print("No revoked keys found. KRL file not generated.")

# Update existing Key Revocation List (KRL) file
def update_krl(output_file=None):
    if not output_file:
        output_file = KRL_FILE
    if not output_file or not os.path.exists(output_file):
        raise ValueError("KRL file not specified or does not exist.")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM certificates WHERE revoked IS NOT NULL")
    revoked_ids = [str(row[0]) for row in cursor.fetchall()]
    conn.close()

    if revoked_ids:
        cmd = ["ssh-keygen", "-u", "-f", output_file] + revoked_ids
        subprocess.run(cmd)
        print(f"KRL file updated: {output_file}")
    else:
        print("No revoked keys found. KRL file not updated.")

# Revoke a user certificate
def revoke(identity, update_krl_file=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    revoked_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''UPDATE certificates 
                      SET revoked = ? 
                      WHERE identity = ? AND revoked IS NULL''', 
                      (revoked_date, identity))
    revoked_count = cursor.rowcount
    conn.commit()
    conn.close()

    print(f"Revoked {revoked_count} certificates for identity {identity}.")

    if update_krl_file:
        update_krl()

# Show certificates
def show(identity=None):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if identity:
        cursor.execute('''SELECT id, identity, principals, issued_at, valid_until 
                          FROM certificates 
                          WHERE revoked IS NULL AND identity = ?''', (identity,))
    else:
        cursor.execute('''SELECT id, identity, principals, issued_at, valid_until 
                          FROM certificates 
                          WHERE revoked IS NULL''')
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        print("No certificates found.")
    else:
        print("Certificates:")
        print("{:<5} {:<20} {:<20} {:<20} {:<20}".format("ID", "Identity", "Principals", "Issued At", "Valid Until"))
        for row in rows:
            row = [col if col is not None else "" for col in row]  # Replace None with empty string
            print("{:<5} {:<20} {:<20} {:<20} {:<20}".format(*row))

# Main function to handle command-line arguments and execute commands
def main():
    parser = argparse.ArgumentParser(description="Manage SSH CA user certificates and store information in a SQLite database.")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Subparser for the initdb command
    initdb_parser = subparsers.add_parser('initdb', help='Initialize the database.')

    # Subparser for the sign command
    sign_parser = subparsers.add_parser('sign', help='Sign a user certificate.')
    sign_parser.add_argument("public_key_file", help="Path to the user's public key file")
    sign_parser.add_argument("principals", help="Comma-separated list of principals")
    sign_parser.add_argument("--validity-days", type=int, help="Number of days the certificate should be valid")
    sign_parser.add_argument("--validity-end", help="Last date of validity (format: YYYYMMDD)")
    sign_parser.add_argument("--identity", help="Identity for the certificate (default is extracted from the public key file)")

    # Subparser for the makekrl command
    makekrl_parser = subparsers.add_parser('makekrl', help='Generate Key Revocation List (KRL).')
    makekrl_parser.add_argument("--output", help="Output file path for the KRL")
    makekrl_parser.add_argument("--force", action="store_true", help="Force overwrite if the output file already exists")

    # Subparser for the updatekrl command
    updatekrl_parser = subparsers.add_parser('updatekrl', help='Update Key Revocation List (KRL).')
    updatekrl_parser.add_argument("--output", help="Output file path for the KRL")

    # Subparser for the revoke command
    revoke_parser = subparsers.add_parser('revoke', help='Revoke a user certificate.')
    revoke_parser.add_argument("identity", help="Identity to revoke certificate for")
    revoke_parser.add_argument("--update", action="store_true", help="Update the KRL file after revoking")

    # Subparser for the show command
    show_parser = subparsers.add_parser('show', help='Show non-revoked certificates.')
    show_parser.add_argument("--identity", help="Identity to filter certificates")

    args = parser.parse_args()

    if args.command == "initdb":
        init_db()
    elif args.command == "sign":
        public_key_file = args.public_key_file
        principals = args.principals
        identity = args.identity or get_identity_from_key(public_key_file)

        if args.validity_days:
            validity_end = (datetime.now() + timedelta(days=args.validity_days)).strftime('%Y%m%d')
        elif args.validity_end:
            validity_end = args.validity_end
        else:
            validity_end = (datetime.now() + timedelta(days=int(DEFAULT_VALIDITY))).strftime('%Y%m%d') if DEFAULT_VALIDITY else None

        cert_id = insert_initial_info(identity, public_key_file, principals, validity_end)
        sign_user_certificate(cert_id, identity, public_key_file, principals, validity_end)
    elif args.command == "makekrl":
        make_krl(args.output, args.force)
    elif args.command == "updatekrl":
        update_krl(args.output)
    elif args.command == "revoke":
        revoke(args.identity, args.update)
    elif args.command == "show":
        show(args.identity)

if __name__ == "__main__":
    main()

