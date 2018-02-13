#!/usr/bin/python

import time
import socket
import struct
import sys
import array
import threading

listeningIP = "192.168.88.1"
seqNumber = 1   # Sequence Number is Incremented every time a ping is sent...
ICMP_ECHOREPLY = 0		# Echo reply (per RFC792)
ICMP_ECHO = 8			# Echo request (per RFC792)
ICMP_MAX_RECV = 2048


#https://gist.github.com/pklaus/856268
#https://github.com/l4m3rx/python-ping/blob/master/ping.py

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
        converted.byteswap()
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
                    print "SrcIP:" + str(srcIP) + " M:" + data[28:]
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
    while exitLoop == False:
        if len(destMessage) > 64:
            currentMessage = destMessage[:63]
            destMessage = destMessage[63:]
        else:
            currentMessage = destMessage
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