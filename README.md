#IP Packet Sniffer in Python
This Python script captures and parses IP packets using raw sockets. It provides functionalities to analyze various fields of the IPv4 header and extract meaningful information from network packets.

Features:
.Captures IP packets using a raw socket.
.Parses and displays IPv4 header fields such as version, header length, type of service (TOS), total length, identification, flags, fragment offset, time-to-live (TTL), protocol, checksum, source and destination addresses.
.Supports decoding of TOS flags (precedence, delay, throughput, reliability, cost) and IP header flags (reserved, don't fragment, more fragments).
.Retrieves protocol names from a predefined protocols.txt file based on protocol numbers.

Prerequisites:
.Python 3.12 installed.
.Administrator/root privileges may be required to run due to the use of raw sockets.

Setup
Clone the Repository:
-------------------------------------------------------------------------------
bash
Copy code
git clone https://github.com/your/repository.git
cd repository-name
-------------------------------------------------------------------------------
Install Dependencies:
No additional dependencies required beyond Python standard library.

Configure Network Interface:
Ensure the script is run with appropriate network interface configuration to capture packets.

Usage
Run the script from the command line:
-------------------------------------------------------------------------------
bash
Copy code
python sniffer.py
-------------------------------------------------------------------------------
Notes:
.The script captures 1 packet per exectuion(to prevent unwanted usage of system resources)
.Adjust paths and permissions as necessary for your environment.
.Ensure protocols.txt contains the protocol definitions in the expected format for correct protocol name resolution.

Example Output:
Upon capturing an IP packet, the script outputs:

---------------------------------------------------------------------------------
An IP Packet with the size 84 was captured                                       
Raw data:
b'\x00\x00\x1c\x00\x00\x00\x00\x00@\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01'

Parsed Data:
Version:            4
Header Length:      20 bytes
Type of Service:    Routine
Length:             28
ID:                 0x0 (0)
Flags:              0 - Reserved bit
Fragment Offset     0
TTL:                64
Protocol:           ICMP
Checksum:           0x0 (0)
Source Address:     127.0.0.1
Destination Address:127.0.0.1
Payload:
b'@\x01\x00\x00\x7f\x00\x00\x01\x7f\x00\x00\x01'
----------------------------------------------------------------------------------
License
This project is licensed under the License - see the license.txt file for details.








