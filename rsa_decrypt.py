from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import binascii
import io

with open("b64_text.txt", "rb") as f: 
    b64_text = f.read()
bin_cipher = io.BytesIO(binascii.a2b_base64(b64_text))

private_key = RSA.import_key(open("private.pem").read())

enc_session_key, nonce, tag, ciphertext = [ bin_cipher.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)

with open("decrypted_text.txt", "w") as f: 
    f.write(data.decode("utf-16"))
