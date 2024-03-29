# ProbeDemon
## Usage
ProbeDemon is using the scapy libary to capture probe requests send out by phones and computers. It can log these with timestamp, MAC address and SSID to a SQLite database. ProbeDemon can work alone by parsing arguments to it or you can use it as libary. It has a TFTP client, which can send your database to a TFTP server when there is a new entry: This is perfect as a headless Raspberry Pi probe collector. If you don't descripe a TFTP IP it will NOT use this module. 

As a new feature the script will also try to indicate which vendor the device MAC address belongs to. 

ProbeDemon is 100% passive and will not interact with devices or access-points. 

## What is a probe?
A probe is sent by WiFi devices asking for networks it has been connected to in the past. As an observer you can use this to collect information about a specific person/device or devices around you. Some devices uses a random generated MAC address before connection, so you can't always trust the probe package. They tend to regenerate this MAC address for every probe request, so it's really easy to detect when they're doing it. 

## Exambles
**Sniffing and logging:**  
```
python ProbeDemon.py --sniff -i wlan0mon -t table101  
```
**Sniffing, logging and TFTP put:**  
```
python ProbeDemon.py --sniff -i wlan0mon -t tftptable101 --server 192.168.1.12   
```

## Requirements
You will need a WiFi network interface card that can be forced into monitormode. The easiest way is to use airmon-ng, but you can also do it with iwconfig:  
```bash
sudo ip link set [NIC NAME] down  
sudo iw dev [NIC NAME] set type monitor  
sudo ip link set [NIC NAME] up  
```

## Library dependencies
You will need to install some python libaries:
```bash
sudo pip install -r requirements.txt
```

## Arguments
**Argument** | **Description**
------------ | ---------------
**--sniff, -s** | This will start the sniffing and for now logging
**--iface, -i** | Use this to parse the name of the NIC
**--table, -t** | Datebase table name (it will append if already exits)
**--server** | If you want to put the database in a TFTP server, you should define this with server IP/domain
**--port** | If your TFTP server use a different port than 69, please define in this option


