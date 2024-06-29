import socket
import sys
import re
import struct

# Function for receiving data
def ReceiveData(s):
    data = ''
    try:
        data = s.recvfrom(65565)  # max bytes that can be captured
    except socket.timeout: #Returns empty string in case of timeout
        data = ''
    except:
        print("Unable to receive data")
        sys.exc_info() #for exception type, value and traceback
    return data[0]

# Type of service (8 bits[1 bit is reserved])
def getTOS(data):
    #precedence settings using dictionary(3 bits)
    prec = {0: "Routine", 1: "Priority", 2: "Immediate", 3: "Flash",4: "Flash Override",
            5: "CRITIC/ECP", 6: "Internetwork Control", 7: "Network Control"}

    #delay settings using dictionary(1 bit)
    delay = {0: "Normal Delay", 1: "Low Delay"}

    # throughput settings using dictionary(1 bit)
    throughput = {0: "Normal Throughput", 1: "High Throughput"}

    # reliability settings using dictionary(1 bit)
    reliability = {0: "Normal reliability", 1: "High reliability"}

    # Monitory cost settings using dictionary(1 bit)
    cost = {0: "Normal Monetary Cost", 1: "Minimize Monetary cost"}

    # Bit masking
    D = data & 0x10  # Storing delay bit
    D >>= 4
    T = data & 0x8  # Storing throughput bit
    T >>= 3
    R = data & 0x4  # Storing reliability bit
    R >>= 2
    M = data & 0x2  # Storing Monetary cost bit
    M >>= 1

    tabs = '\n\t\t\t'
    # Concatenation of multiple strings
    TOS = prec[data >> 5] + tabs + delay[D] + tabs + throughput[T] + tabs + reliability[R] + tabs + cost[M]
    return TOS

def getFlags(data):
    #for reserved bit flag
    flagR = {0: "0 - Reserved bit"}

    # dont fragment bit
    flagDF = {0: "0 - Fragment if necessary", 1: "Don't fragment"}

    #more fragment bit
    flagMF = {0: "0 - Last fragment", 1: "More fragments"}

    #bit isolation and masking alongwith shifting accordingly
    R = data & 0x8000
    R >>= 15
    DF = data & 0x4000
    DF >>= 14
    MF = data & 0x2000
    MF >>= 13
    tabs = '\n\t\t\t'
    # Concatenation of multiple strings
    flags = flagR[R] + tabs + flagDF[DF] + tabs + flagMF[MF]
    return flags

def getProtocol(protocolNum):
    with open(r"C:\Users\HP\PycharmProjects\basic sniffer\protocols.txt", 'r') as protocolFile:
        protocolData = protocolFile.read()
        protocol = re.findall(r"\b" + str(protocolNum) + r"\s+(\w+)", protocolData)
        if protocol:
            return protocol[0]
        else:
            return "Unknown protocol"

#getting machine name from its IP Address
HOST = socket.gethostbyname(socket.gethostname())

#creating raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

#binding socket to non-specific port num
s.bind((HOST, 0))

#setting operations
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

#promiscuous mode on
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

data = ReceiveData(s)

#parsing an IPV4 header
unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])

version_IHL = unpackedData[0]

#shifting 4 places for isolating group of bits
version = version_IHL >> 4

#bit masking by hexa
IHL = version_IHL & 0xF

TOS = unpackedData[1]

totalLength = unpackedData[2]

ID = unpackedData[3]

flags = unpackedData[4]

fragmentOffset = unpackedData[4] & 0x1FFF

TTL = unpackedData[5]

protocolNum = unpackedData[6]

checksum = unpackedData[7]

sourceaddress = socket.inet_ntoa(unpackedData[8])

destinationaddress = socket.inet_ntoa(unpackedData[9])

print("An IP Packet with the size {} was captured".format(totalLength))

print("Raw data: ")

print(data)

print("\nParsed Data:")

print("Version:\t\t" + str(version))

print("Header Length:\t\t" + str(IHL * 4) + " bytes")

print("Type of Service:\t" + getTOS(TOS))

print("Length:\t\t\t" + str(totalLength))

print("ID:\t\t\t" + str(hex(ID)) + " (" + str(ID) + ')')

print("Flags\t\t\t" + getFlags(flags))

print("Fragment Offset\t" + str(fragmentOffset))

print("TTL:\t\t\t" + str(TTL))

print("Protocol:\t\t" + getProtocol(protocolNum))

print("Checksum:\t\t" + str(checksum))

print("Source Address:\t\t" + sourceaddress)

print("Destination Address:\t" + destinationaddress)

print("Payload:\n")

print(data[20:])

#setting promiscuous mode off
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
