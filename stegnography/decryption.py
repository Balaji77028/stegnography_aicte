from PIL import Image
import numpy as np
from cryptography.fernet import Fernet, InvalidToken
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SteganographyDecoder:
    def __init__(self):
        self.delimiter = "$$END$$"
        self.signature = "STEGO"
    
    def _generate_key(self, password):
        if not password:
            raise ValueError("Password is required")
            
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _decrypt_message(self, encrypted_message, password):
        try:
            key = self._generate_key(password)
            f = Fernet(key)
            decrypted_message = f.decrypt(encrypted_message)
            return decrypted_message.decode()
        except InvalidToken:
            raise ValueError("Incorrect password")
        except Exception:
            raise ValueError("Failed to decrypt message")

    def decode(self, image_path, password):
        if not password:
            raise ValueError("Password is required for decoding")
            
        try:
            # Read image
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_array = np.array(img)
            
            # Extract LSBs
            binary_data = ''
            height, width, channels = img_array.shape
            
            for x in range(height):
                for y in range(width):
                    for c in range(channels):
                        binary_data += str(img_array[x, y, c] & 1)
                        
                        # Try to find delimiter every 8 bits
                        if len(binary_data) % 8 == 0:
                            # Convert binary to string
                            message = ''
                            for i in range(0, len(binary_data), 8):
                                byte = binary_data[i:i+8]
                                if len(byte) == 8:
                                    message += chr(int(byte, 2))
                                    
                                    # Check for delimiter
                                    if message.endswith(self.delimiter):
                                        # Remove delimiter
                                        message = message[:-len(self.delimiter)]
                                        
                                        try:
                                            # Decode base64 and decrypt
                                            encrypted = base64.b64decode(message)
                                            decrypted = self._decrypt_message(encrypted, password)
                                            
                                            # Verify signature
                                            if not decrypted.startswith(self.signature):
                                                raise ValueError("Invalid steganography image")
                                                
                                            # Remove signature and return message
                                            return decrypted[len(self.signature):]
                                            
                                        except Exception as e:
                                            raise ValueError(str(e))
            
            raise ValueError("No hidden message found in this image")
            
        except Exception as e:
            raise Exception(f"Decoding error: {str(e)}")