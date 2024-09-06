import subprocess
import os
import hashlib
import shutil

res_path = './symmetric_enc_result/'
encrypted_file_path = res_path + 'encrypted_json.enc'
decrypted_file_path = res_path + 'decrypted_json.json'
hashed_pass_path = res_path + 'passphrase_hash.txt'

file_to_be_encrypted = './mock_person.json'

def save_hash(hash):
    hash_file = open(hashed_pass_path, 'w')
    hash_file.write(hash)
    hash_file.close()

def generate_hash(passphrase):
    hash_object = hashlib.sha256(passphrase.encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    return hex_dig

def verify_passphrase(passphrase_hash):
    
    hash_file = open(hashed_pass_path, 'r')
    stored_hash = hash_file.read()
    hash_file.close()
    
    return passphrase_hash == stored_hash
    

def encrypt_file(input_file, output_file):
    print(f"Beginning encryption of {file_to_be_encrypted}")
    passphrase_hash = generate_hash(input("Create a passphrase for encryption: "))
    os.makedirs(res_path, exist_ok=True)
    save_hash(passphrase_hash)
    
    
    command = [
        'openssl', 'enc', '-aes-256-cbc', '-salt', '-pbkdf2',
        '-in', input_file,
        '-out', output_file,
        '-k', passphrase_hash
    ]
    
    try:
        res = subprocess.run(command, check="True", text="True", capture_output="True")

        if res.stderr:
            print("Error:", res.stderr)
            return
            
        print("File successfully encrypted.\n")

    except subprocess.CalledProcessError as e:
        print(f"Error during process")


def decrypt_file(input_file, output_file):
    passphrase = generate_hash(input("Enter passphrase to decrypt: "))
    
    if not verify_passphrase(passphrase):
        print("Wrong passphrase, decryption canceled.")
        return
    
    command = [
        'openssl', 'enc', '-aes-256-cbc', '-d', '-salt', '-pbkdf2',
        '-in', input_file,
        '-out', output_file,
        '-k', passphrase
    ]

    try:
        
        result = subprocess.run(command, check=True, text=True, capture_output=True)

        if result.stderr:
            print("Error:", result.stderr)
            return

        print("File successfully decrypted.\n")
        
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during decryption: {e}")
        
def remove_files():
    if os.path.exists(res_path):
        shutil.rmtree(res_path)
    
    if os.path.exists(hashed_pass_path):
            os.remove(hashed_pass_path)
               
def main():
    try:
        if os.path.exists(res_path) and not os.path.exists(decrypted_file_path):
            if input('Continue previous decryption attempt? y/n ') == 'y':
                decrypt_file(encrypted_file_path, decrypted_file_path)
                return
            else:
                print("Initiating new encryption example.\n")
        
        remove_files()
        encrypt_file(file_to_be_encrypted, encrypted_file_path)

        decrypt_file(encrypted_file_path, decrypted_file_path)
        
    except OSError as e:
        print(e)
        
main()