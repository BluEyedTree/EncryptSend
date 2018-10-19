from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Encryption:

    bstring_To_Encrypt = "Hello"
    decrypted_String = "Hi"
    the_Key = b"Sixteen byte key"
    nonce = " "
    cipher_Text = " "

    #def __init__(self):

    def get_and_Set_Key(self):
        a_Key = input("Enter the key to be used for the encryption: ")
        key =str(hash(a_Key))
        key = key[4:]
        self.the_Key = key.encode()
        return

    def encrypt_It(self):
        cipher = AES.new(self.the_Key, AES.MODE_EAX)
        string_To_Encrypt = input("Enter the message to be encrypted: ")
        self.bstring_To_Encrypt = string_To_Encrypt.encode()
        self.nonce = cipher.nonce
        self.cipher_Text, tag = cipher.encrypt_and_digest(self.bstring_To_Encrypt)
        return

    def decrypt_It(self):
        cipher = AES.new(self.the_Key, AES.MODE_EAX, nonce = self.nonce)
        data = str(cipher.decrypt(self.cipher_Text))
        self.decrypted_String = data[2:len(data)-1]
        return

    def print_Message(self):
        print(self.decrypted_String)
        return

#key = b'Sixteen byte key'
#cipher = AES.new(key, AES.MODE_EAX)
#mystring = 'hello fuck this world'
#d = mystring.encode()

#nonce = cipher.nonce
#ciphertext, tag = cipher.encrypt_and_digest(d)

#print(ciphertext)

#cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
#plaintext = cipher.decrypt(ciphertext)
#print(plaintext)

x = Encryption()
x.get_and_Set_Key()
x.encrypt_It()
x.decrypt_It()
x.print_Message()

