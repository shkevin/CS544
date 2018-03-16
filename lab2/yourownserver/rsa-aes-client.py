import argparse
import socket
import sys
import os
from aes import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import *

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress", help='ip address where the server is running', required=True)
parser.add_argument("-p", "--port", help='port where the server is listening on', required=True)
parser.add_argument("-m", "--message", help='message to send to the server', required=True)

#parser.add_argument("-b", "--block", help='the 32-byte block sent to the server', required=True)
#parser.add_argument("-id", "--keyid", help='unique key id', required=True)
args = parser.parse_args()

MESSAGE_LENGTH = 15

# Initial AES Key to be all 0
AESKey = "0"*128

pcap = bytearray.fromhex('5fcb94936bd5926ec03a70fee7380687f9c523371e08b7bd19a511f5f548f80af265ec1044e3a5cfa9a2d52a13b19496819253231e19eca855f1a734e1eb3584d85a9bfc4a3600ca9018bb55bf20e468d5b9f18a8bc786a25bbe0c6c9fbc2ce15cd7d689385b136bb2428c7b514b358849c6cb422127275b5dc40d92b873e2763c26cb7e0bca5ab484a3522a6df975c909df67f9c4999826ef801c31375a7d93')

msgToCrack = bytearray.fromhex('5cce0bde11f5f815ae0292cd08c3c81f4b6036ec39f10c45fbe61c1a8822c9e6')

cipherText = bytes_to_long(pcap[:128])

aesToCrack = bytes_to_long(pcap[128:-1])

for x in range(0, 128):

  # load server's public key
  serverPublicKeyFileName = "serverPublicKey"
  f = open(serverPublicKeyFileName,'r')
  key = RSA.importKey(f.read())
  n, e = key.n, key.e

  # Create a TCP/IP socket
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  # Connect the socket to the port where the server is listening
  server_address = (args.ipaddress, int(args.port))
  sock.connect(server_address)

  b = (127-x)
  
  print 'Iteration: %d' % x

  msg = ""
  encryptedKey = str(key.encrypt(AESKey.encode(), 16)[0])
  msg += encryptedKey

  aes = AESCipher(AESKey.encode()) 

  shiftedCipher = (cipherText * (2**(b*e))) % n

  # tmpRSACipher = (bytes_to_long(rsaCiperText) * (2**(b*e))) % n

  print 'Trying RSA cipertext... \n', shiftedCipher, '\n...which is...'
  print cipherText, '\n...multiplied by 2^{%de} mod n'% b

  try:
    # Send data

    message = str(args.message)
    print 'Trying AES key...\n', AESKey
    print '...with plaintext "%s"' % message

    msg += aes.encrypt(message)

    print "here"
    # print 'Sending: "%s"' % message
    # msg: AES key encrypted by the public key of RSA  + message encrypted by the AES key
    sock.sendall(msg)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)
    
    if amount_expected % 16 != 0:
      amount_expected += (16 - (len(message) % 16))

    answer = ""

    if amount_expected > amount_received:
      while amount_received < amount_expected:
        data = sock.recv(MESSAGE_LENGTH)
        amount_received += len(data)
        answer += data

      decAnswer = aes.decrypt(answer)

      if decAnswer:
        print "Server sent back %s" %decAnswer
      else:
        print "Server sent back junk"

  finally:
    sock.close()
