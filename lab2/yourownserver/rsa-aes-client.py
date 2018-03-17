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

pcap = bytearray.fromhex('068cbe8e5e1b9dfc5e3e78ea94c8c6b3b51129688973c9670a926b7079bbfaf3b4ac76a6c58ea62565920024e8b6ac74cb0ad5150df09807aa5f2e1350049d6872ef5befb3877248ba5d11060cdd5435034515570778c29359f972bae369745d377de1c647f4fa86b0e97ee12857796a7a855b89bb5b2aa93948e899410aad2ac970534ee6c1e9e0638da20189dcd6d31715e5d427e997b668408f953d7be3362185f2ba2c2b1f0ed2abdc1352978bd4')

cipherText = bytes_to_long(pcap[0:128])

msgToCrack = str(pcap[128:len(pcap)])

for x in range(0, 1):

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
    time.sleep(.01)

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

        if message.upper() == decAnswer:
          print "Server sent back %s" %message.upper()
          AESKey = '0' + AESKey[0:127]
          print AESKey
          bitNotCorrect = True
        else:
          print "Server sent back junk"
          AESKey = '1' + AESKey[1:128]
          print AESKey


    finally:
      sock.close()

  aes = AESCipher(long_to_bytes(int(AESKey,2), 16))
  last = aes.decrypt(str(msgToCrack))
  print last