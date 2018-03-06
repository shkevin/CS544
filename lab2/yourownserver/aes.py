from Crypto.Cipher import AES
from Crypto import Random


# pad = lambda s: s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)
# unpad = lambda s: s[:-ord(s[len(s)-1:])]

class AESCipher(object):

    def __init__(self, key): 
        self.key = key

    # https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    def pad(self,s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    def unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self.pad(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        # if len(raw) % 16 != 0:
        #     raw += ' ' * (16 - (len(raw) % 16))
        return cipher.encrypt(raw)

    def decrypt(self, enc):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return self.unpad(cipher.decrypt(enc))
        # return cipher.decrypt(enc)