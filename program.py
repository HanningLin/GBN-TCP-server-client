import sys, os, random, threading, hashlib, select, time, argparse
from socket import *
from datetime import datetime

BUFSIZE = 512#size of packets
TIMEOUT = 2 # Wait for 10 seconds.
SYN = '\x16\x00'
ACK = '\x06\x00'
SYNACK = '\x16\x06'
RST = '\x18\x00'
FIN = '\x19\x00'
ACKFIN = '\x06\x19'
def is_number(s):# used to check if a str is number or not
    try:
        float(s)
        return True
    except ValueError:
        pass

    try:
        import unicodedata
        unicodedata.numeric(s)
        return True
    except (TypeError, ValueError):
        pass

    return False
def monitorQuit(genSock):#used to monitor the program and exit anytime
    while True:
        sentence = input()
        if sentence == "exit":
            genSock.shutdown(SHUT_RDWR)
            genSock.close()
            os.kill(os.getpid(), 9)

def findFileName(filepath):
    if '/' in filepath:
        # the last segment of the math is the filename
        filepath_splited = filepath.split('/')
        filename = filepath_splited[-1]
    else:
        # if no "/", the path is the name of the file
        filename = filepath
    return filename

def makePacket(seqnum, content, lastflag):#make packet
    packet = str(seqnum) + "%03d"%(len(content)) + str(lastflag) + content
    if len(content)<467:
        packet = packet + '\x00' * (467 - len(content))#make sure packet is 467 bytes
    checksum = hashlib.sha1(packet.encode()).hexdigest()
    if len(checksum)<40:
        checksum = (40 - len(checksum)) * " " + checksum#make sure that checksum is 40 bytes
    return checksum+ packet

def validate_packet(data):#used to check if the packet is valid or not
    content = data[40:]
    pktchecksum = data[:40]
    localchecksum = hashlib.sha1(content.encode()).hexdigest()
    localchecksum = (40 - len(localchecksum)) * " " + localchecksum
    print("len: {}".format(len(data)))
    print("{}\n{}\nseq: {}".format(pktchecksum, localchecksum, data[40]))
    return pktchecksum == localchecksum

def serverCore(connectedSock, addr):#this is the core code of server
    print("----Waiting for packet from a client----\n")
    recv_filename = ""
    sSock = connectedSock
    expnum = 0#the sequence number the server is expecting
    seqnum=0
    packet_sending = ""
    ACKed = False
    while True:
        ready = select.select([sSock], [], [])
        print("\nTime: {}".format(str(datetime.now())))
        if ready[0]:
            data = sSock.recv(BUFSIZE).decode()
            print("Packet Receiving: Received a packet from the client.")
        if not validate_packet(data):
            # invalid packet, discard the packet
            print("Packet Receiving: The packet received is invalid, discard it.")
            continue
        #if valid, parse the packet
        seqnum = int(data[40])
        pkt_size = int(data[41:44])
        lastsign = int(data[44])
        content = data[45:]
        if not ACKed: #this is the first time that server received a pkt
            ACKed=True
            recv_filename = content[:pkt_size]
            print("Packet Received: The first pkt which contains the filename recieved")
            fd = open(recv_filename, "w")
            packet_sending = makePacket(seqnum, ACK, 0)
            print("ACK[#{}] Sending: Sending an ACK packet to the client...".format(seqnum))
            sSock.send(packet_sending.encode())
            expnum = (expnum + 1) % 10
            continue
        else:# not the first pkt
            if expnum == seqnum and lastsign == 0:#this is the pkt that server is waiting for
                print("Packet Received: A valid Pkt received. Data will be delivered to the upper layer...")
                fd.write(content[:pkt_size])
                packet_sending = makePacket(seqnum, ACK, 0)
                print("ACK[#{}] Sending: Sending an ACK packet to the client...".format(seqnum))
                sSock.send(packet_sending.encode())
                expnum = (seqnum + 1) % 10
            elif expnum !=seqnum:
                print("Packet Received: A duplicate Pkt received. Discard the pkt")
                packet_sending = makePacket(seqnum, ACK, 0)
                print("ACK[#{}] Sending: Sending an ACK packet to the client...".format(seqnum))
                sSock.send(packet_sending.encode())
            elif expnum == seqnum and lastsign == 1:
                print("Packet Received: The last Pkt received. Data will be delivered to the upper layer...")
                fd.write(content[:pkt_size])
                packet_sending = makePacket(seqnum, ACK, 1)
                print("ACK[#{}] Sending: Sending an ACK packet to the client...".format(seqnum))
                sSock.send(packet_sending.encode())
                print("Connection closed.")
                sSock.shutdown(SHUT_RDWR)
                sSock.close()
                break
def server(host, port):# the code of TCP server
    print("Server starts to listen to {}:{}\n".format(host, port))
	#create a socket object, SOCK_STREAM for TCP:
    try:
        sSock = socket(AF_INET, SOCK_STREAM)
    except error as msg:
        print(msg)
        return -1
    sSock.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)#to tells the kernel to reuse a local socket in TIME_WAIT state
    try:#bind socket to the current address on port 5001
        sSock.bind((host, port))#bind local IP addresses which is 127.0.0.1 and port which is 5001
        sSock.listen(20)#Listen on therep_seqnum given socket maximum number of connections queued is 20
    except error as msg:
        print(msg)
        return -1
    #monitor exit
    monitor = threading.Thread(target = monitorQuit, args = [sSock])# open a thread for users to exit the server
    monitor.start()
    print("Server is listening...\n")
    while True:
        #blocked until a remote machine connects to the local port 5001
        connectedSock, addr = sSock.accept()
        server = threading.Thread(target = serverCore, args=[connectedSock, addr[0]])
        #open a thread to do dnsQuery so that the server can serve multiple client at the same time
        server.start()

def client(host, port, filepath):
    # open the file that need to be read
    try:
        fd = open(filepath, 'r')
        file_content = fd.read()
        fd.close()
        file_len = len(file_content)# this is the length of the whole file
        file_send_start = 0#
        file_send_end = min(file_send_start + 467, file_len)
    except error as msg:
        print(msg)
        return -1
        sended=False
    # client starts to establish connection
    try:
        cSock = socket(AF_INET, SOCK_STREAM)
    except error as msg:# Handle exceptio
        cSock=None
    try:
        cSock.connect((host, port))
    except error as msg:
        cSock = None # Handle exception
    if cSock is None:
        print("ERROR:Cannot open socket!\n")
        sys.exit(1)# If the socket cannot be opened, quit the program.
    seqnum = 0
    lastflag=False
    filename_received=False
    # find the name of the file
    filename=findFileName(filepath)
    content_sending = filename
    #the first pkt is a packet of filename
    packet_sending = makePacket(seqnum, content_sending, 0)
    print("\nTime: {}".format(str(datetime.now())))
    print("Packet[#{}] Sending: Sending a packet contained the file content to the server...".format(packet_sending[40]))
    cSock.send(packet_sending.encode())
    while True:
        ready = select.select([cSock], [], [], TIMEOUT)
        print("\nTime: {}".format(str(datetime.now())))
        if ready[0]:
            print("Packet Receiving: Received a packet from the server.")
            data = cSock.recv(BUFSIZE).decode()
            if lastflag:
                print("Client: Transmission finished! Connection closed.")
                cSock.shutdown(SHUT_RDWR)
                cSock.close()
                break
            if not validate_packet(data):# invalid packet, discard the packet
                print("Packet Receiving: The packet received is invalid, discard it.")
                continue
            rep_seqnum = int(data[40])
            pkt_size = int(data[41:44])
            lastsign = int(data[44])
            content = data[45:]
            if lastsign==1:
                print("Client: Transmission finished! Connection closed.")
                cSock.shutdown(SHUT_RDWR)
                cSock.close()
                break
            if seqnum== rep_seqnum and lastsign == 0:#normal valid ACK not last ACK
                seqnum = (seqnum + 1) % 10
                file_send_end = min(file_send_start + 467, file_len)
                content_sending = file_content[file_send_start:file_send_end]
                file_send_start = file_send_end
                if len(content_sending) == 467:
                    packet_sending=makePacket(seqnum,content_sending,0)
                    print("Packet[#{}] Sending: Sending a packet contained the file content to the server...".format(packet_sending[40]))
                    cSock.send(packet_sending.encode())
                else:
                    packet_sending=makePacket(seqnum,content_sending,1)
                    print("Packet[#{}] Sending: Sending the last packet contained the file content to the server...".format(packet_sending[40]))
                    cSock.send(packet_sending.encode())
                    lastflag=True
            if seqnum!=rep_seqnum:
                continue
        else:#timeout
            print("Packet Lost: Timeout! Retransmit packet[#{}]......\n".format(packet_sending[40]))
            cSock.send(packet_sending.encode())
def main():

    if len(sys.argv)==3:#if 3 parameters, this is server
        host,port=sys.argv[1],int(sys.argv[2])
        server(host,port)
    elif len(sys.argv)==4:# if 4 parameters, this is client
        host,port=sys.argv[1],int(sys.argv[2])
        client(host,port,sys.argv[3])
    else:# else this is wrong
        print("Wrong number of args, expected 3 for client and 4 for server.\n")

main()
