import subprocess
import os


def encrypt_file(input_file, output_file, password):
    command = [
        'openssl', 'enc', '-aes-256-cbc', '-salt', '-pbkdf2',
        '-in', input_file,
        '-out', output_file,
        '-k', password
    ]
    try:
        res = subprocess.run(command, check="True", text="True", capture_output="True")

        if res.stdout:
            print(f"Resulting output: {res.stdout}")

        if res.stderr:
            print("Error:", res.stderr)

    except subprocess.CalledProcessError as e:
        print(f"Error during process oh noes")


def decrypt_file(input_file, output_file, password):
    command = [
        'openssl', 'enc', '-aes-256-cbc', '-d', '-salt', '-pbkdf2',
        '-in', input_file,
        '-out', output_file,
        '-k', password
    ]

    try:
        # Run the OpenSSL command
        result = subprocess.run(command, check=True, text=True, capture_output=True)

        # Print any output from the command (if needed)
        if result.stdout:
            print(result.stdout)

        # Check for errors
        if result.stderr:
            print("Error:", result.stderr)

        print("File decrypted successfully.")
        
    except subprocess.CalledProcessError as e:
        print(f"An error occurred during decryption: {e}")
        

try:
    os.makedirs('./same_key_res', exist_ok=True)
    encrypt_file('./mock_person.json', './same_key_res/encryptedjson.enc', 'password123')

    decrypt_file('./same_key_res/encryptedjson.enc', './same_key_res/decryptedjson.json', 'password123')
except OSError as e:
    print(e)
