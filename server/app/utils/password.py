# Import the passlib library for password hashing
from passlib.context import CryptContext

# Create a password context using bcrypt algorithm, which is considered very secure
# We're using bcrypt as it's the same algorithm used in your existing database
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify if a plain password matches its hashed version
    
    Args:
        plain_password: The password in plain text
        hashed_password: The hashed version of the password
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Generate a hashed version of a plain password
    
    Args:
        password: The password in plain text
        
    Returns:
        str: The hashed version of the password
    """
    return pwd_context.hash(password)