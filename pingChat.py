#!/usr/bin/python

import time
import socket
import struct
import sys
import array
import threading
import base64
from Crypto.Cipher import AES

## Recommended that you change the listeningIP and the secret key used in the AES encryption...
# If the message to encrypt and encode causes the sequence number to be greater that 65,535 the application will crash...
# The receiving end is only meant to recieve 1 message at a time.  Multiple messages will not be able to be received at this time...

# Also on Windows you need the Microsoft Visual C++ Compiler for Python 2.7 installed with the pycrypto libraries...
# My solution was to rename the folder from ..Lib\site-packages\crypto to ..Lib\site-packages\Crypto. The lower case "c" was causing the import error.

# the block size for the cipher object; must be 16, 24, or 32 for AES
BLOCK_SIZE = 32

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# Random Secret Key used in the Encryption  - Recommended to change this each time
# Needs to be the same size as the BLOCK_SIZE and match on both sides of a conversation
secret = "e4re3waq2ew34w3e4rdvgt6ytr45tgfd"

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# create a cipher object using the random secret
cipher = AES.new(secret)

# String that is used to detect the end of an encoded string.  This is necessary to tell the receiving end when the encoded message
# has terminated so it at that time can decode, decrypt and display the message
# The longer the string the better...
endString = "y7y7Y7Y7purplechickens"

listeningIP = "192.168.88.1"
seqNumber = 1   # Sequence Number is Incremented every time a ping is sent...
ICMP_ECHOREPLY = 0		# Echo reply (per RFC792)
ICMP_ECHO = 8			# Echo request (per RFC792)
ICMP_MAX_RECV = 2048

# Referenced the following locations and derived the following script...
#https://gist.github.com/pklaus/856268
#https://github.com/l4m3rx/python-ping/blob/master/ping.py
#https://gist.github.com/sekondus/4322469

def default_timer():
    if sys.platform == "win32":
        return time.clock()
    else:
        return time.time()

def calcChecksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    if (len(source_string) % 2):
        source_string += "\x00"
    converted = array.array("H", source_string)
    if sys.byteorder == "big":
        converted.bytewap()
    val = sum(converted)
    val &= 0xffffffff # Truncate val to 32 bits (a variance from ping.c, which
                      # uses signed ints, but overflow is unlikely in ping)
    val = (val >> 16) + (val & 0xffff)    # Add high 16 bits to low 16 bits
    val += (val >> 16)                    # Add carry from above (if any)
    answer = ~val & 0xffff                # Invert and truncate to 16 bits
    answer = socket.htons(answer)
    return answer

def listenPing():
    counter = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind((listeningIP, 1))
    encodedMessage = ''
    while True:
        try:
            data = s.recv(1024)
            ipHeader = data[:20]
            iphVersion, iphTypeOfSvc, iphLength, \
            iphID, iphFlags, iphTTL, iphProtocol, \
            iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
                "!BBHHHBBHII", ipHeader
            )
            icmpHeader = data[20:28]
            icmpType, icmpCode, icmpChecksum, \
            icmpPacketID, icmpSeqNumber = struct.unpack(
                "!BBHHH", icmpHeader
            )
            srcIP = socket.inet_ntoa(struct.pack("!L", iphSrcIP))
            if str(data[28:32]) == '99zz':
                break
            else:
                if str(srcIP) != listeningIP and icmpType != 0:
                    #print "SrcIP:" + str(srcIP) + " M:" + data[28:]
                    encodedMessage = encodedMessage + data[28:]
                    if endString in encodedMessage:
                        encodedMessage = encodedMessage.replace(endString,'')
                        decodedMessage = DecodeAES(cipher, encodedMessage)
                        print "SrcIP:" + str(srcIP) + " M: " + decodedMessage
                        encodedMessage = ''
        except:
            print "\nUnable to listen for icmp packets...\n"
    s.close()

def sendPing(destIP, destMessage):
    global seqNumber, ICMP_ECHO
    from random import randint
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError as e:
        print("Failed with socket error: %s" % str(e))
        print("This requires root privileges...")
        raise
    exitLoop = False
    # Encrypt and Encode the message unless it is the exit loop message...
    if not destMessage == '99zz':
        encodedMessage = EncodeAES(cipher, destMessage) + endString
    else:
        encodedMessage = destMessage
    #print encodedMessage
    while exitLoop == False:
        if len(encodedMessage) > 64:
            currentMessage = encodedMessage[:63]
            encodedMessage = encodedMessage[63:]
        else:
            currentMessage = encodedMessage
            exitLoop = True
        randomInt = randint(0,30000)
        packetID = (13927 ^ randomInt) & 0xFFFF
        packetChecksum = 0
        icmpHeader = struct.pack("!BBHHH", ICMP_ECHO, 0, packetChecksum, packetID, seqNumber)
        bytes = struct.calcsize("d")
        icmpData = currentMessage
        #icmpData = struct.pack("d", default_timer()) + icmpData
        packetChecksum = calcChecksum(icmpHeader + icmpData)
        # Reconstruct the header with the correct checksum...
        #print packetChecksum
        #print packetID
        #print seqNumber
        icmpHeader = struct.pack("!BBHHH", ICMP_ECHO, 0, packetChecksum, packetID, seqNumber)
        icmpPacket = icmpHeader + icmpData
        sentTime = default_timer()
        try:
            s.sendto(icmpPacket, (destIP, 1))
        except OSError as e:
            print ("Failure to Send ICMP Packet %s" % str(e))
            return 0
        except:
            return 0
        # Increment the sequence number of the packet...
        seqNumber += 1
    s.close()
    return sentTime

def main():
    print
    print "pingChat was built as a proof-of-concept to demonstrate how to"
    print "exfil information using the ICMP protocol."
    print
    print "Remember to modify the listeningIP at the beginning of the file..."
    print
    t = threading.Thread(target=listenPing)
    t.start()
    exitLoop = False
    while exitLoop == False:
        # Listen for incoming icmp messages until a message is crafted to be sent...
        print "\n"
        selection = raw_input("Press S at any time to Send a Message, Q to Quit\n")
        if selection == 'S' or selection == 's':
            destIP = raw_input("Destination IP: ")
            destMessage = raw_input("Message to Send: ")
            sentTime = sendPing(destIP, destMessage)
            if sentTime == 0:
                print "Failed to send the message. Verify the IP is correct."
            else:
                print "Message Sent Successfully @ " + str(sentTime)
        elif selection == 'Q' or selection == 'q':
            sendPing(listeningIP,'99zz')
            sys.exit(0)
        else:
            pass





if __name__ == '__main__':
    main()