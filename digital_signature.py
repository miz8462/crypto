from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA


def generate_public_key(size=2048):
    key = RSA.generate(size)
    private_key = key.export_key()
    public_key = key.public_key().export_key()
    return public_key, private_key


def generate_signature(private_key, message):
    key= RSA.import_key(private_key)
    message = message.read().encode('utf-8')
    hash = SHA256.new(message)

    signature = pkcs1_15.new(key).sign(hash)
    return signature


def verify_signature(public_key, signature, message):
    key = RSA.import_key(public_key)
    message = message.read().encode('utf-8')
    hash = SHA256.new(message)

    try:
        pkcs1_15.new(key).verify(hash, signature)
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")


if __name__ == "__main__":
    public_key, private_key = generate_public_key()
    message = open("plain_data.txt")
    signature = generate_signature(private_key, message)
    message = open("plain_data.txt")
    verify_signature(public_key, signature, message)
