# CSCI4211-Programming Assignment 2

- date: 03/18/18
- name: Hanning Lin 

## Compilation script
### network layer:
   - python3 netWorkLayer.py <port> <maxNoPackets> <delay> <probMangle>
   - e.p.:python3 networkLayer.py 5002 10 0.1 1 20
### client:
   - python3 program.py <host> <port> <path of the file>
   - e.p.:python3 program.py localhost 5002 /home/hanninglin/Documents/CSCI4211-proj2/Prog2res/TESTCASE/test.txt 
### server:
   - python3 program.py <host> <port> 
   - e.p.:python3 program.py localhost 5001

## Machine that I used:
  - I used ubuntu 16.04 LTS to test my program

## Logic of the code:
 - First, if there is 3 parameters, the program will run as a server. And if there are 4 parameters, the program will run as a client.
 -The TCP connection is established using Sock.connect((host,port)) and it tears down using Sock.shutdown(SHUT_RDWR) and Sock.close(). Once the connection is established, the first packet that the client send will have the filename and the other packets will have the content of the packet. Once the server receive a correct packet, it will send an ACK back to the client. If the server doesn't receive an ACK in time, it will timeout and resend the packet to the client. I use SHA-1 to verify the packet.

## Packet Structure
 - 40-byte checksum(SHA-1)
 - 1-byte seqnum
 - 3-byte size of actual data
 - 1-byte flag if the packet if the last one
 - 467-byte of actual data
                
