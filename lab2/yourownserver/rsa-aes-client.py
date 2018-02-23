import argparse
import socket
import sys
import os
from aes import *
from Crypto.PublicKey import RSA

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress", help='ip address where the server is running', required=True)
parser.add_argument("-p", "--port", help='port where the server is listening on', required=True)
parser.add_argument("-m", "--message", help='message to send to the server', required=True)

#parser.add_argument("-b", "--block", help='the 32-byte block sent to the server', required=True)
#parser.add_argument("-id", "--keyid", help='unique key id', required=True)
args = parser.parse_args()


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = (args.ipaddress, int(args.port))
sock.connect(server_address)

AESKey = os.urandom(16)
print "Using AES key " + ':'.join(x.encode('hex') for x in AESKey)

# load server's public key
serverPublicKeyFileName = "serverPublicKey"
f = open(serverPublicKeyFileName,'r')
key = RSA.importKey(f.read())
n, e = key.n, key.e
MESSAGE_LENGTH = 15


#Cipher pulled from 10041.pcap
# 0x79, 0xef, 0xed, 0xee, 0x65, 0x52, 0x00, 0xb9, 
# 0x9d, 0xa1, 0x00, 0xce, 0x43, 0x70, 0x76, 0xec, 
# 0x0a, 0x26, 0xf0, 0x9d, 0x76, 0x67, 0x43, 0xa4, 
# 0x24, 0xe6, 0x99, 0x12, 0x80, 0x7d, 0xd7, 0xea, 
# 0x03, 0xaf, 0x63, 0x6e, 0xc3, 0x7c, 0xbc, 0xe5, 
# 0x69, 0x6d, 0x92, 0x38, 0xee, 0xae, 0xbb, 0x84, 
# 0x2f, 0xb3, 0x25, 0x5e, 0x0c, 0xeb, 0x73, 0x0b, 
# 0x9a, 0x70, 0x2d, 0xeb, 0xcd, 0x67, 0x37, 0x66, 
# 0x0b, 0x0c, 0xb7, 0xc3, 0xc2, 0x0b, 0x70, 0xd1, 
# 0xb3, 0xb9, 0x13, 0xb5, 0x34, 0x4f, 0xc1, 0xe9, 
# 0xf2, 0x18, 0x88, 0x44, 0x73, 0x84, 0x18, 0x92, 
# 0x6c, 0xe4, 0x90, 0x82, 0x00, 0xe3, 0x9d, 0x6a, 
# 0xaa, 0x35, 0x71, 0x3e, 0x6c, 0x34, 0xa1, 0x9a, 
# 0x46, 0x0b, 0x6e, 0x25, 0x6a, 0xa9, 0xad, 0x00, 
# 0x65, 0x4c, 0x89, 0xf4, 0xc2, 0x0c, 0x3b, 0xd6, 
# 0x1c, 0xef, 0xe8, 0xef, 0xf0, 0xb3, 0x0d, 0x67, 
# 0x93, 0x76, 0xae, 0xf9, 0x6a, 0x6d, 0xb3, 0x89, 
# 0x4e, 0x83, 0x27, 0x58, 0x48, 0x27, 0x4e, 0x0d, 
# 0xa0, 0x99, 0xd7, 0xb5, 0x43, 0x08, 0x13, 0x41, 
# 0x3c, 0x0e, 0xd1, 0x82, 0x96, 0x41, 0x75, 0x89, 
# 0xb1, 0xe7, 0x12, 0x21, 0xfb, 0xf5, 0x93, 0xb5, 
# 0x80, 0x1a, 0x47, 0xfd, 0x0b, 0x5a, 0xf0, 0x37, 
# 0x33, 0x13, 0x4e, 0xe2, 0x9b, 0xf0, 0x76, 0xc0, 
# 0x18, 0x02, 0xce, 0x15, 0x0b, 0xe4, 0xe5, 0x2d"

#This should all be in a loop to try the padding attack
msg = ""
encryptedKey = str(key.encrypt(AESKey, 16)[0])
msg += encryptedKey

aes = AESCipher(AESKey)
try:
  # Send data
  message = str(args.message)
  msg += aes.encrypt(message)
  print 'Sending: "%s"' % message
  # msg: AES key encrypted by the public key of RSA  + message encrypted by the AES key
  sock.sendall(msg)

  # Look for the response
  amount_received = 0
  amount_expected = len(message)
  
  # Ensure that we recieve everything we are supposed to
  if amount_expected % 16 != 0:
    amount_expected += (16 - (len(message) % 16))

  # answer = ""

  # if amount_expected > amount_received:
  #   while amount_received < amount_expected:
  #     data = sock.recv(MESSAGE_LENGTH)
  #     amount_received += len(data)
  #     answer += data

  answer = sock.recv(1024)

  print aes.decrypt(answer)
#End loop

finally:
  sock.close()

