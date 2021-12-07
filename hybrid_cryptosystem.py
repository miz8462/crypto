# PKCS: Public-Key Cryptography Standars RSA暗号標準
# OAEP: Optimal Asymmetric Encryption Padding
#       最適非対称暗号化パディング
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def generate_public_key(size=1024):
    key = RSA.generate(size)
    with open("private-key.pem", "wb") as f:
        private_key = key.export_key()
        f.write(private_key)

    with open("public-key.pem", "wb") as f:
        public_key = key.public_key().export_key()
        f.write(public_key)


def encrypt(public_key, data, size=16):
    public_key = RSA.import_key(public_key.read())
    data = data.read().encode("utf-8")
    session_key = get_random_bytes(size)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    # session_key: 共通鍵
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, MAC_tag = cipher_aes.encrypt_and_digest(data)
    with open("encrypted_data.bin", "wb") as f:
        [ f.write(x) for x in (enc_session_key, cipher_aes.nonce, MAC_tag, ciphertext) ]



def decrypt(private_key, encrypted_data):
    private_key = RSA.import_key(private_key.read())
    # encrypted_data = encrypted_data.read()
    enc_session_key, nonce, MAC_tag, ciphertext = \
        [ encrypted_data.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, MAC_tag)
    decrypted_data = data.decode("utf-8")
    with open("decrypted_data.txt", "w") as f:
        f.write(decrypted_data)


if __name__ == '__main__':

    data = open("plain_data.txt")

    generate_public_key()
    public_key = open("public-key.pem", "r")
    encrypt(public_key, data)
    private_key = open("private-key.pem")
    encrypted_data = open("encrypted_data.bin", "rb")
    decrypt(private_key, encrypted_data)
