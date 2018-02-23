# Written by Meisam Navaki, maintained by crandall@cs.unm.edu

import Crypto
import ast
import os
import argparse
import socket
import sys
from aes import *
from rsa import *
from Crypto.Util.number import *
import binascii

def getSessionKey(rsa, cipher):
    """
    Get the AES session key before decrypting the RSA ciphertext
    """
    try:
        AESEncrypted = cipher[:128]
        AESKey = rsa.decrypt(AESEncrypted)
        return AESKey[(len(AESKey)-16):]
    except:
        return False

def myDecrypt(rsa, cipher):
    """
    Decrypt the client message: 
    AES key encrypted by the public RSA key of the server + message encrypted by the AES key
    """
    try:
        messageEncrypted = cipher[128:]
        AESKey = getSessionKey(rsa, cipher) 
        print "aes len: ", len(AESKey)
        aes = AESCipher(AESKey)
        print "AES ", bytes_to_long(aes.key)

        # p = bytes_to_long(aes.decrypt(messageEncrypted));
        # print byteToHex(bytes_to_long(messageEncrypted))

        return aes.decrypt(messageEncrypted)
    except:
        return False

def byteToHex(byteStr):
    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

def checkPadding(text):
    return text[-text[-1]:] == [text[-1] for _ in range(text[-1])]

def bytesToInts(ciphertext): return [ord(c) for c in ciphertext]

def oracle(ciphertext):
    return checkPadding(bytesToInts(ciphertext))


# Parse Command-Line Arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress")
parser.add_argument("-p", "--port")
args = parser.parse_args()

# Create TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind socket to port
server_address = (args.ipaddress, int(args.port))
print >>sys.stderr, 'Starting up on: %s port %s' % server_address
sock.bind(server_address)

# Listen for incoming connections
sock.listen(10)

rsa = RSACipher()

while True:
    print >>sys.stderr, 'Waiting for a connection...' # Wait for a conneciton
    connection, client_address = sock.accept()
  
    try:
        print >>sys.stderr, 'Connection from:', client_address
        # Receive the data
        cipher = connection.recv(1024)
        print("Message Received...")

        # print byteToHex(cipher)
        print bytesToInts(cipher)
        print checkPadding(bytesToInts(cipher))

        message = myDecrypt(rsa, cipher)
        # print byteToHex(message)
        print checkPadding(bytesToInts(message))

        if message:
            print "decrypted successfully!"
            print message
            aes = AESCipher(getSessionKey(rsa, cipher))
            msg = aes.encrypt(message.upper())

            #send the decrypted message back to the client
            connection.sendall(msg)
        else:
            connection.sendall("Couldn't decrypt!")



    finally:
        # Clean up the connection
        connection.close()

# def attack(data, block, validPadding):

# def validPadding(iv, ciphertext):
