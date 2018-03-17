import argparse
import socket
import sys
import os
from aes import *
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
import time

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress", help='ip address where the server is running', required=True)
parser.add_argument("-p", "--port", help='port where the server is listening on', required=True)
parser.add_argument("-m", "--message", help='message to send to the server', required=True)

#parser.add_argument("-b", "--block", help='the 32-byte block sent to the server', required=True)
#parser.add_argument("-id", "--keyid", help='unique key id', required=True)
args = parser.parse_args()

 # load server's public key
serverPublicKeyFileName = "serverPublicKey"
f = open(serverPublicKeyFileName,'r')
key = RSA.importKey(f.read())
n, e = key.n, key.e
MESSAGE_LENGTH = 15

# Initial AES Key to be all 0
AESKey = "0"*128

pcap = bytearray.fromhex('05a91e3b3197c36783f986eb7c7ba88b40a9e76224b49557aafd0a4ca0aeff9525781b13bd6accf3bb05b20235cf1d63ef7bcef8d5c0414b75aaeb08279aa4c1c412e72082aeaf6ee303e30dee1d56d5d97388e55088247d655ecc5e12dbc02581c97f2c30c42518db2d10a7e9540497e6dc9db442945740a701494eadd0b439de5c41c0908590f6e36f7dd295f3d069ccff6fbd16b411f488ffa99e2b4fc509')

cipherText = bytes_to_long(pcap[:128])

msgToCrack = str(pcap[128:])

for x in range(0, 128):

  bitNotCorrect = False 
  b = (127-x)

  print 'Iteration: %d' % x

  shiftedCipher = (cipherText * 2**(b*e)) % n
  guess = str(long_to_bytes(shiftedCipher, 128))

  print 'Trying RSA cipertext... \n', shiftedCipher, '\n...which is...'
  print cipherText, '\n...multiplied by 2^{%de} mod n'% b

  # Send data
  message = 'Example Text 123'
  print 'Trying AES key...\n', AESKey
  print '...with plaintext "%s"' % message

  while not bitNotCorrect:
    # time.sleep(.1)

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (args.ipaddress, int(args.port))
    sock.connect(server_address)

    msg = ""
    msg += guess

    aes = AESCipher(long_to_bytes(int(AESKey,2), 16))

    try:
      msg += aes.encrypt(message)

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

        decAnswer = aes.decrypt(answer).strip()
        print decAnswer

        if message.upper() == decAnswer:
          print "Server sent back %s" %message.upper()
          if x == 127:
            break
          AESKey = '0' + AESKey[0:127]
          print AESKey
          bitNotCorrect = True
        else:
          print "Server sent back junk"
          AESKey = '1' + AESKey[1:128]
          print AESKey


    finally:
      sock.close()

  print AESKey
  aes = AESCipher(long_to_bytes(int(AESKey,2), 16))
  print aes.decrypt(msgToCrack)