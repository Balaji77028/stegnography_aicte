from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SteganographyEncoder:
    def __init__(self):
        self.delimiter = "$$END$$"
        self.signature = "STEGO"  # Add signature to verify encrypted images
    
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

    def _encrypt_message(self, message, password):
        key = self._generate_key(password)
        f = Fernet(key)
        encrypted_message = f.encrypt(message.encode())
        return encrypted_message

    def encode(self, image_path, message, password):
        if not password:
            raise ValueError("Password is required for encoding")
            
        try:
            # Add signature to message
            message = self.signature + message
            
            # Open and convert image to RGB
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_array = np.array(img)
            
            # Encrypt the message
            encrypted = self._encrypt_message(message, password)
            encrypted_message = base64.b64encode(encrypted).decode()
            
            # Add delimiter
            final_message = encrypted_message + self.delimiter
            
            # Convert to binary
            binary_message = ''.join(format(ord(char), '08b') for char in final_message)
            
            if len(binary_message) > img_array.size:
                raise ValueError("Message too large for this image")
            
            # Create copy of image array
            encoded_img_array = img_array.copy()
            height, width, channels = encoded_img_array.shape
            
            # Convert binary message to array of bits
            message_bits = np.array([int(bit) for bit in binary_message])
            
            # Encode message
            for i in range(len(binary_message)):
                x = i // (width * channels)
                y = (i // channels) % width
                c = i % channels
                
                if x < height:
                    encoded_img_array[x, y, c] = (encoded_img_array[x, y, c] & 0xFE) | message_bits[i]
            
            return Image.fromarray(encoded_img_array)
            
        except Exception as e:
            raise Exception(f"Encoding error: {str(e)}")

    def can_encode(self, image_path, message):
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_array = np.array(img)
            # Account for signature, encryption overhead, and delimiter
            message_size = (len(self.signature) + len(message) + len(self.delimiter)) * 8 * 2
            return message_size <= img_array.size
        except Exception:
            return False