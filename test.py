import os
import subprocess
import hashlib
import pickle

def insecure_password_hash(password):
    # Insecure hashing function
    return hashlib.md5(password.encode()).hexdigest()  # Vulnerable: MD5 is weak and outdated

def command_injection(user_input):
    # Vulnerable: Unsanitized user input in a shell command
    command = f"echo {user_input}"
    subprocess.call(command, shell=True)

def hardcoded_secrets():
    # Vulnerable: Hardcoded credentials
    username = "admin"
    password = "password123"
    print(f"Username: {username}, Password: {password}")

def insecure_deserialization(data):
    # Vulnerable: Unsafe use of pickle for deserialization
    return pickle.loads(data)

def world_writable_file():
    # Vulnerable: Creating a world-writable file
    with open("temp_file.txt", "w") as f:
        f.write("Temporary file")
    os.chmod("temp_file.txt", 0o777)  # World-writable file permissions

# Example Usage (with intentionally unsafe behavior)
if __name__ == "__main__":
    user_input = input("Enter a command: ")  # Command injection
    command_injection(user_input)

    password_hash = insecure_password_hash("mysecretpassword")
    print(f"Insecure hash of password: {password_hash}")

    hardcoded_secrets()

    serialized_data = pickle.dumps({"key": "value"})
    print("Deserialized data:", insecure_deserialization(serialized_data))

    world_writable_file()
    print("Temporary file created with world-writable permissions.")
