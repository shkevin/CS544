# from Crypto.Cipher import AES
# from Crypto import Random

# class AESCipher(object):

#     def __init__(self, key): 
#         self.key = key

#     def encrypt(self, raw):
#         #This needs to be CBC, not ECB
#         iv = Random.new().read(AES.block_size)
#         cipher = AES.new(self.key, AES.MODE_ECB)
#         if len(raw) % 16 != 0:
#             #This needs to change from spaces to hex(1 .. 16)
#             raw += ' ' * (16 - (len(raw) % 16))
#         return cipher.encrypt(raw)

#     def decrypt(self, enc):
#         cipher = AES.new(self.key, AES.MODE_ECB)
#         return cipher.decrypt(enc)


# https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.key = key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc))

    def _pad(self, s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]