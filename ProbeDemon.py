#!/usr/bin/env python

from scapy.all import *
import sqlite3
import time
import argparse
import tftpy

from MacLookup import maclookup

class ProbeSniffer():
    def __init__(self, TableName, iface, TFTPip, TFTPport):
        self.mac = maclookup()
        #self.mac.UpdateVendorList()

        self.LOGLIST = {}
        self.TableName = TableName
        self.TFTPip = TFTPip
        if TFTPport != None:
            self.TFTPport = TFTPport
        elif TFTPport == None:
            self.TFTPport = 69
   
        if iface == None:
            print("No interface parsed - Use argument --iface to specify network interface or --help")
            quit()
        else:
            if iface == None:
                self.iface = "LOG"
            else:
                self.iface = iface
        
        

    def StartSniff(self):
        sniff(iface = self.iface, prn = self.PacketHandler, store=False)
         

    def PacketHandler(self, pkt):
        if not pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:
                if pkt.info != b"":
                    MAC = pkt.addr2
                    try:
                        SSID = pkt.info.decode('utf-8')
                    except:
                        SSID = str(pkt.info)
                    VENDOR = self.mac.lookup(MAC)
                    print("MAC: " + MAC + "(" + VENDOR + ")" + " with SSID: " + SSID)
                    self.InsertIntoTable(MAC, SSID, VENDOR)
                 
    
    
    def StartDatabase(self):
        self.conn = sqlite3.connect('database.sqlite')
        self.cur = self.conn.cursor()
    
    def CreateTable(self):
        try:
            command = "CREATE TABLE " + self.TableName + " (MAC, SSID, VENDOR, FIRST_SEEN, LAST_SEEN, COUNTER INT)"
            self.cur.execute(command)
            self.conn.commit()  
        except Exception as e:
            print("Exception: ", str(e))
    
    def ImportFromTable(self):
        command = "SELECT * FROM " + self.TableName
        self.cur.execute(command)
        for row in self.cur:
            if row[0] in self.LOGLIST.keys():
                self.LOGLIST[row[0]][row[1]] = {"vendor":row[2],"first_seen":row[3],"last_seen":row[4],"counter":row[5]}
            else:
                self.LOGLIST[row[0]] = {row[1]:{"vendor":row[2],"first_seen":row[3],"last_seen":row[4],"counter":row[5]}}
    
    def InsertIntoTable(self, MAC, SSID, VENDOR):
        FIRST_SEEN = int(time.time())
        # Check if MAC is already logget
        if MAC in self.LOGLIST.keys():
            # Check if the logget MAC already has made a probe for the same SSID and updating counter/last_seen
            if SSID in self.LOGLIST[MAC].keys():
                LAST_SEEN = time.time()
                COUNTER = self.LOGLIST[MAC][SSID]["counter"] + 1
                self.LOGLIST[MAC][SSID]["counter"] = COUNTER
                self.LOGLIST[MAC][SSID]["last_seen"] = LAST_SEEN

                command = "UPDATE " + self.TableName + " SET LAST_SEEN = ?,COUNTER = ? WHERE MAC = ? AND SSID = ?"
                self.cur.execute(command, (LAST_SEEN, COUNTER, MAC, SSID))
                return

            # Adds the new SSID to the MAC's dictionary in the logging list
            elif SSID not in self.LOGLIST[MAC].keys():
                self.LOGLIST[MAC][SSID] = {"vendor":VENDOR,"first_seen":FIRST_SEEN,"last_seen":FIRST_SEEN,"counter":0}
                command = "INSERT INTO " + self.TableName + " (MAC, SSID, VENDOR, FIRST_SEEN, COUNTER) VALUES (?,?,?,?,?)"
                self.cur.execute(command, (MAC, SSID, VENDOR, FIRST_SEEN, 0))
                self.conn.commit()
                if self.TFTPip != None:
                    UploadToTFTP(self.TFTPip, self.TFTPport)

        # Creating a new MAC dictionary in the logging list
        elif MAC not in self.LOGLIST.keys():
            self.LOGLIST[MAC] = {SSID: {"vendor": VENDOR, "first_seen": FIRST_SEEN, "last_seen": FIRST_SEEN, "counter": 0}}
            command = "INSERT INTO " + self.TableName + " (MAC, SSID, VENDOR, FIRST_SEEN, COUNTER) VALUES (?,?,?,?,?)"
            self.cur.execute(command, (MAC, SSID, VENDOR, FIRST_SEEN, 0))
            self.conn.commit()
            if self.TFTPip != None:
                UploadToTFTP(self.TFTPip, self.TFTPport)
            
def Arguments():
    parser = argparse.ArgumentParser(description='This script can sniff and analyze probe requests. Before running the script force your NIC into monitor mode and parse some arguments')
    parser.add_argument("-s","--sniff",help="Set this option to start sniffing", action='store_true')
    parser.add_argument("-i","--iface", metavar="",help="Parse the desired network interface you want to sniff on")
    parser.add_argument("-t","--table", metavar="",help="Parse the name of the table you want the script to save data to")
    parser.add_argument("--server", metavar="",help="If you wan't the script to upload the database to a TFTP server input with IP address/domain")
    parser.add_argument("--port", metavar="",type=int,help="If you uses a TFPT server with a different port than 69 call this option and input port")
    
    args = parser.parse_args()
    
    iface = args.iface
    TableName = str(args.table)
    StartSniff = args.sniff
    TFTPip = args.server
    TFTPport = args.port
    return StartSniff,iface,TableName,TFTPip,TFTPport
    
def UploadToTFTP(ip, port):
    try:
        TFTPclient = tftpy.TftpClient(ip, port)
        TFTPclient.upload("database.sqlite","database.sqlite", packethook=None, timeout=5)
    except:
        print("Failed to upload to TFTP server")
    
if __name__ == "__main__":
    #StartSniff,iface, TableName,TFTPip,TFTPport = Arguments()
    StartSniff = True
    TableName = "test"
    iface = "wlp0s20f0u1mon"
    TFTPip = None
    TFTPport = None

    if StartSniff == True:
        ProbeSniffer = ProbeSniffer(TableName, iface, TFTPip, TFTPport)
        ProbeSniffer.StartDatabase()
        ProbeSniffer.CreateTable()
        ProbeSniffer.ImportFromTable()
        ProbeSniffer.StartSniff()
