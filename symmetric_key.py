# 共通鍵暗号

# 共通鍵を作成し暗号化、復号化する


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_key():
    # 16bytes = 128bits
    key = get_random_bytes(16)
    return key

def encrypt(key, data):
    if type(data) != bytes:
        data = data.encode()

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # MAC tag
    nonce = cipher.nonce
    return ciphertext, tag, nonce

def decrypt(key, ciphertext, tag, nonce):
    cipher_dec = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher_dec.decrypt_and_verify(ciphertext, tag)

    if type(data) == bytes:
        data = data.decode()

    return data


if __name__ == '__main__':
    key = generate_key()
    data = "人生の勝負所は待ったなしだ"
    encrypted_data, tag, nonce = encrypt(key, data)
    decrypted_data = decrypt(key, encrypted_data, tag, nonce)
    print(data)
    print(encrypted_data)
    print(decrypted_data)
