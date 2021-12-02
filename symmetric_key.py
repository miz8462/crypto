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
    file_out = open("encrypted.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()

def decrypt(key, encrypted_data):
    nonce, tag, ciphertext = [ encrypted_data.read(x) for x in (16, 16, -1) ]
    encrypted_data.close()
    cipher_dec = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher_dec.decrypt_and_verify(ciphertext, tag)

    if type(data) == bytes:
        data = data.decode()

    return data


if __name__ == '__main__':
    key = generate_key()
    data = "人生の勝負所は待ったなしだ"
    encrypt(key, data)
    encrypted_file = "encrypted.bin"
    encrypted_data = open(encrypted_file, "rb")
    encrypted_data_bin = open(encrypted_file, "rb")
    decrypted_data = decrypt(key, encrypted_data)
    print('暗号前：', data)
    print('暗号後：', encrypted_data_bin.read())
    print('復号後：', decrypted_data)
