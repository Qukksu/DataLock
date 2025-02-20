from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class DataLock:
    # Consolidated constants
    SALT_SIZE, BUFFER_SIZE = 8, 4096
    KEY_SIZE, IV_SIZE = 32, 16
    ITERATIONS = 100000

    def __init__(self, password: str = None):
        self.password = password

    def _derive_key_and_iv(self, password: str, salt: bytes) -> tuple[bytes, bytes]:
        """Generate key and IV from password and salt using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE + self.IV_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
        )
        key_iv = kdf.derive(password.encode())
        return key_iv[:self.KEY_SIZE], key_iv[self.KEY_SIZE:]

    def _pad_data(self, data: bytes) -> bytes:
        padding_length = 16 - (len(data) % 16)
        return data + bytes([padding_length]) * padding_length

    def encrypt_file(self, in_filename: str, out_filename: str, password: str = None) -> bool:
        try:
            if not (use_password := password or self.password):
                raise ValueError("Password not provided")

            salt = os.urandom(self.SALT_SIZE)
            key, iv = self._derive_key_and_iv(use_password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            with open(in_filename, 'rb') as fin, open(out_filename, 'wb') as fout:
                fout.write(salt)
                while chunk := fin.read(self.BUFFER_SIZE):
                    if len(chunk) % 16:
                        chunk = self._pad_data(chunk)
                    fout.write(encryptor.update(chunk))
                fout.write(encryptor.finalize())
            return True

        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return False

    def decrypt_file(self, in_filename: str, out_filename: str, password: str = None) -> bool:
        try:
            if not (use_password := password or self.password):
                raise ValueError("Password not provided")

            with open(in_filename, 'rb') as fin:
                salt = fin.read(self.SALT_SIZE)
                encrypted_data = fin.read()

            key, iv = self._derive_key_and_iv(use_password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()

            try:
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                padding_length = decrypted_data[-1]

                if padding_length > 16:
                    raise ValueError("Invalid padding")

                with open(out_filename, 'wb') as fout:
                    fout.write(decrypted_data[:-padding_length])
                return True

            except Exception:
                print("Invalid password or corrupted file")
                return False

        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return False

def main():
    import sys

    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <encrypt|decrypt> <filename> <password>")
        sys.exit(1)

    mode, filename, password = sys.argv[1:4]
    data_lock = DataLock()

    if mode == "encrypt":
        output_file = f"{filename}.enc"
        if data_lock.encrypt_file(filename, output_file, password):
            os.remove(filename)
            print(f"File successfully encrypted to: {output_file}")
            return
    elif mode == "decrypt" and filename.endswith(".enc"):
        output_file = filename[:-4]
        if data_lock.decrypt_file(filename, output_file, password):
            os.remove(filename)
            print(f"File successfully decrypted to: {output_file}")
            return
    else:
        print("Invalid mode or file extension")
    sys.exit(1)

if __name__ == "__main__":
    main()