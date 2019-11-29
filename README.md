# ProbeDemon
## Usage
ProbeDemon is using the scapy libary to capture probe requests send out by phones and computers. It can log these with timestamp, MAC address and SSID to a SQLite database. ProbeDemon can work alone by parsing arguments to it or you can use it as libary. It has a TFTP client, which can send your database to a TFTP server when there is a new entry: This is perfect as a headless Raspberry Pi probe collector.

## Requirements
You will need a WiFi network interface card that can be forced into monitormode. The easiest way is to use airmon-ng, you can also do it with iwconfig:  
$sudo ip link set [NIC NAME] down  
$sudo iw dev [NIC NAME] set type monitor  
$sudo ip link set [NIC NAME] up  

## Library dependencies
You will need to install some python libaries for this to work:  
$pip install sqlite3 tftpy argparse scapy

