# How to Write Protection Level Code in Python

# Import necessary modules
# We're bringing in some built-in Python modules that help with security.
import hashlib
import os

# Define constants
# Constants are values that don't change. 
# We use them to store things like a salt for hashing passwords.
HASH_SALT = b'secure_salt'

# Function to hash passwords
# When we store passwords, we don't want to store them as plain text.
# Hashing transforms the password into a fixed-size string of characters, which is more secure.
def hash_password(password: str) -> str:
    """
    Hash a password using the SHA-256 algorithm and a salt for added security.
    Args:
        password (str): The password to be hashed.
    Returns:
        str: The hashed password.
    """
    # Use the hashlib library to create a SHA-256 hash
    # We're adding a salt to the password to make it harder for attackers to use precomputed hashes.
    hash_obj = hashlib.sha256(HASH_SALT + password.encode())
    # The hexdigest method returns the hash in hexadecimal format
    return hash_obj.hexdigest()

# Function to create a new user with a hashed password
# This function simulates creating a user and storing their hashed password.
def create_user(username: str, password: str) -> dict:
    """
    Create a new user with a hashed password.
    Args:
        username (str): The username of the new user.
        password (str): The password of the new user.
    Returns:
        dict: A dictionary containing the username and hashed password.
    """
    # Hash the password before storing it
    hashed_password = hash_password(password)
    # Return a dictionary representing the user
    return {
        'username': username,
        'password': hashed_password
    }

# Function to verify a user's password
# This checks if the provided password matches the stored hashed password.
def verify_password(stored_password: str, provided_password: str) -> bool:
    """
    Verify a provided password against the stored hashed password.
    Args:
        stored_password (str): The hashed password stored in the database.
        provided_password (str): The plain text password provided by the user.
    Returns:
        bool: True if the passwords match, False otherwise.
    """
    # Hash the provided password
    hashed_provided_password = hash_password(provided_password)
    # Compare the stored password with the hashed provided password
    return stored_password == hashed_provided_password

# Example usage
# Let's create a user and then verify their password.
def main():
    # Create a user with a username and password
    user = create_user("john_doe", "secure_password123")
    print("User created:", user)
    
    # Now let's verify the user's password
    is_valid = verify_password(user['password'], "secure_password123")
    print("Password verification result:", is_valid)
    
    # Try verifying with a wrong password
    is_valid = verify_password(user['password'], "wrong_password")
    print("Password verification result with wrong password:", is_valid)

if __name__ == "__main__":
    main()

# Why is this important?
# 1. **Security**: Hashing passwords protects user information in case of a data breach.
# 2. **Data Integrity**: Using a salt prevents attackers from using precomputed hash tables to guess passwords.
# 3. **Maintainability**: Keeping code modular with clear functions makes it easier to manage and update.
