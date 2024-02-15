import os

# Generate a random byte string
random_bytes = os.urandom(24)

# Convert the byte string to a hexadecimal representation
secret_key = random_bytes.hex()

print(secret_key)
