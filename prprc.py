import os 
from colorama import init, Fore
import psutil
from scapy.all import Raw, sniff, IP, Ether, ARP 
from scapy.layers.tls.all import TLS
from scapy.layers.http import HTTPRequest, HTTPResponse
from pathlib import Path
import subprocess
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")

ETHERTYPE = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x0842: "Wake-on-LAN",
    0x22F3: "TRILL",
    0x6003: "DECnet",
    0x8035: "RARP",
    0x809B: "AppleTalk",
    0x80F3: "AARP",
    0x8100: "VLAN_8021Q",
    0x8137: "IPX",
    0x86DD: "IPv6",
    0x8847: "MPLS_unicast",
    0x8848: "MPLS_multicast",
    0x8863: "PPPoE_Discovery",
    0x8864: "PPPoE_Session",
    0x88CC: "LLDP",
    0x8808: "Ethernet_Flow_Control",
    0x88A8: "QinQ"
}

header = r"""
  ____            ____                              
 |  _ \ _ __ ___ |  _ \ _ __ ___   ___ ___  ___ ___ 
 | |_) | '__/ _ \| |_) | '__/ _ \ / __/ _ \/ __/ __|
 |  __/| | | (_) |  __/| | | (_) | (_|  __/\__ \__ \
 |_|   |_|  \___/|_|   |_|  \___/ \___\___||___/___/ 
"""

init(autoreset=True)

Parameters = {
    "autofreeze": False
}


helpie = """
WindowsProPacket — CLI Help
Usage

Interactive command-line tool for process monitoring, network inspection, and packet analysis on Windows.

Commands
process
Show processes
process show all
process show pid <pid>
process grep <name>

Show process network connections
process show connections <pid>

process detect <count> create
Monitor process creation events.

process detect <count> deleted
Monitor process termination events.

process freeze <pid>
Suspend a process.

process hot <pid>
Resume a process.

process scan connections <process_name>
Inspect process network connections by process name.

sniff connection <src>=<dst> <count>
Capture and analyze network traffic for a specific connection.

sniff files <count> <path>
Capture Deleted or Created files in a path

Example:
sniff connection 192.168.1.10=8.8.8.8 5

params autofreeze
Show autofreeze status

params autofreeze <on|off>
Enable or disable automatic process freezing

Notes
Process operations require valid PID or process name
Network scanning relies on psutil network interfaces
Sniffing uses Scapy and may require elevated privileges
Autofreeze automatically suspends newly created processes when enabled
"""

def Clean():
    os.system("cls")

    print(Fore.GREEN + f"\n{header}")
    print(Fore.YELLOW + f" python-windows based - " + Fore.LIGHTBLACK_EX + "version 1.0")

def DetectNewPids(count: int):
    old_pids = []

    for pid in psutil.pids():
        try:
            prc = psutil.Process(pid=pid)
            name = prc.name()
            old_pids.append([name, pid])
        except:
            pass

    ccnt = 0
    while ccnt < count:
        time.sleep(1)

        new_pids = []

        for pid in psutil.pids():
            try:
                prc = psutil.Process(pid=pid)
                name = prc.name()
                new_pids.append([name, pid])
            except:
                pass
        
        for element in new_pids:
            if not element in old_pids:
                try:
                    if Parameters["autofreeze"] == True:
                        prc = psutil.Process(element[1])
                        prc.suspend()
                        print("Automaticly Freezed...")

                    print(f"[NEW PROCESS] {element[0]} | PID: {element[1]}")
                    ccnt += 1
                except:
                    pass
        
        old_pids = new_pids

def DetectOldPids(count: int):
    old_pids = []

    for pid in psutil.pids():
        try:
            prc = psutil.Process(pid=pid)
            name = prc.name()
            old_pids.append([name, pid])
        except:
            pass

    ccnt = 0
    while ccnt < count:
        time.sleep(1)

        new_pids = []

        for pid in psutil.pids():
            try:
                prc = psutil.Process(pid=pid)
                name = prc.name()
                new_pids.append([name, pid])
            except:
                pass
        
        for element in old_pids:
            if not element in new_pids:
                try:
                    print(f"[CLOSED PROCESS] {element[0]} | PID: {element[1]}")
                    ccnt += 1
                except:
                    pass
        
        old_pids = new_pids

def is_encrypted(pkt):
    if pkt.haslayer(TLS):
        return True

    if pkt.haslayer(HTTPRequest) or pkt.haslayer(HTTPResponse):
        return False

    if pkt.haslayer(Raw) and not pkt.haslayer(HTTPRequest):
        return "unknown (maybe encrypted or fragmented)"

    return "unknown"

def PacketHandler(pkt, dst, src):
    if pkt.haslayer(IP):
        if dst in pkt[IP].dst or dst in pkt[IP].src:
            if src in pkt[IP].src or src in pkt[IP].dst:
                print("-----------------------------------------------")

                real_src = pkt[IP].src
                real_dst = pkt[IP].dst

                print(f"FROM {real_src} -----> {real_dst}")

                if pkt.haslayer(Ether):
                    print(f"ETHER PACKET / {ETHERTYPE[pkt[Ether].type]}")

                if pkt.haslayer(ARP):
                    if pkt[ARP].op == 1:
                        print(f"ARP PACKET / REQUEST")
                    elif pkt[ARP].op == 2:
                        print(f"ARP PACKET / REPLY")

                if pkt.haslayer(HTTPRequest):
                    print(f"HTTP REQUEST: {pkt[IP].src} -> {pkt[IP].dst}")
                    print(pkt[HTTPRequest].Method)
                    req = pkt[HTTPRequest]
                    for k, v in req.fields.items():
                        print(f"{k}: {v}")
                    return True
                elif pkt.haslayer(HTTPResponse):
                    print(f"HTTP RESPONSE: {pkt[IP].src} -> {pkt[IP].dst}")
                    resp = pkt[HTTPResponse]
                    for k, v in resp.fields.items():
                        print(f"{k}: {v}")
                    return True

                proto = pkt[IP].proto

                if proto == 6:
                    print("TCP Packet")
                elif proto == 17:
                    print("UDP Packet")
                elif proto == 1:
                    print("ICMP Packet")

                if is_encrypted(pkt=pkt) == True:
                    print("Encrypted with TLS")


                print("-----------------------------------------------")
                return True

def FileSniff(path, count):
    try:
        class Handler(FileSystemEventHandler):
            def __init__(self):
                self.ccn = 0

            def on_created(self, event):
                if self.ccn >= count:
                    return
                
                print("Created:", event.src_path)
                self.ccn += 1

            def on_deleted(self, event):
                if self.ccn >= count:
                    return

                print("Deleted:", event.src_path)
                self.ccn += 1


        handler = Handler()

        observer = Observer()
        observer.schedule(handler, path, recursive=True)
        observer.start()
    except:
        print(Fore.RED + "Failed to sniff.. may the path is wrong")

    try:
        while handler.ccn < count:
            time.sleep(0.1)
    finally:
        observer.stop()
        observer.join()

    return True

def ProPacket():
    Clean()

    while True:
        pt = input(Fore.CYAN + "[  $ ")
        wrs = pt.lower().strip().split()
        if len(wrs) == 1:
            if wrs[0] == "clear" or wrs[0] == "clr" or wrs[0] == "cls":
                Clean()
            elif wrs[0] == "help" or wrs[0] == "-help" or wrs[0] == "--help":
                print(helpie)

        if len(wrs) >= 2:
            if wrs[0] == "params":
                if wrs[1] == "autofreeze" or wrs[1] == "autofrz" or wrs[1] == "atfrz" or wrs[1] == "p1":
                    if Parameters["autofreeze"] == True:
                        print("Allowed.")
                    else:
                        print("Disallowed.")
            elif wrs[0] == "process":
                if wrs[1] == "show":
                    if wrs[2] == "all":
                        for process in psutil.process_iter(["pid" , "name"]):
                            print(f"{Fore.RED + f"\n PROCESS NAME: {process.info['name']}"} " + f" {Fore.MAGENTA + f'||'} " + f"{Fore.GREEN + f"PROCESS PID: {process.info['pid']}"}")
                
                    elif wrs[2] == "pid":
                        if len(wrs) > 3:
                            spid = wrs[3]

                            try:
                                int(spid)
                            except:
                                print("Invalid PID.")
                                continue
                            
                            ipid = int(spid)
                            size = 0

                            for process in psutil.process_iter(["pid" , "name"]):
                                if str(process.info["pid"]) == str(ipid):
                                    size += 1
                                    print(f"{Fore.RED + f"\n PROCESS NAME: {process.info['name']}"} " + f" {Fore.MAGENTA + f'||'} " + f"{Fore.GREEN + f"PROCESS PID: {process.info['pid']}"}")

                            if size == 0:
                                print(Fore.MAGENTA + "Nothing Found.")
                    elif wrs[2] == "connections":
                        if len(wrs) > 3:
                            spid = wrs[3]

                            try:
                                int(spid)
                            except:
                                print("Invalid PID.")
                                continue
                            
                            ipid = int(spid)
                            process = psutil.Process(ipid)

                            cntcs = process.net_connections()
                            if cntcs == []:
                                print("No Connections.")
                                continue

                            for connection in process.net_connections():
                                print(f"{connection.laddr} <-------> {connection.raddr}")
                
                elif wrs[1] == "grep":
                    name = str(wrs[2])
                    size = 0
                    for process in psutil.process_iter(["pid" , "name"]):
                        if name.lower() in str(process.info["name"]).lower():
                            size += 1
                            print(f"{Fore.RED + f"\n PROCESS NAME: {process.info['name']}"} " + f" {Fore.MAGENTA + f'||'} " + f"{Fore.GREEN + f"PROCESS PID: {process.info['pid']}"}")

                    if size == 0:
                        print(Fore.MAGENTA + "Nothing Found.")
                elif wrs[1] == "detect":
                    scount = str(wrs[2])

                    try:
                        int(scount)
                    except:
                        print("Invalid Count.")
                        continue

                    count = int(scount)

                    if len(wrs) == 4:
                        type = str(wrs[3])

                        if type == "create" or type == "-create" or type == "--create" or type == "new" or type == "-new" or type == "--new":
                            a = DetectNewPids(count=count)
                        elif type == "deleted" or type == "-deleted" or type == "--deleted" or type == "old" or type == "-old" or type == "--old":
                            a = DetectOldPids(count=count)
                elif wrs[1] == "freeze":
                    spd = str(wrs[2])

                    try:
                        int(spd)
                    except:
                        print("Invalid Count.")
                        continue

                    pid = int(spd) 

                    try:
                        process = psutil.Process(pid)
                    except:
                        print("Process not found.")
                        continue

                    try:
                        print("Freezing...")
                        process.suspend()
                    except Exception as e:
                        print(f"Error: {e}")
                        continue

                    print(f"Freezed {process.name()} Successfuly !")
                elif wrs[1] == "hot":
                    spd = str(wrs[2])

                    try:
                        int(spd)
                    except:
                        print("Invalid Count.")
                        continue

                    pid = int(spd) 

                    try:
                        process = psutil.Process(pid)
                    except:
                        print("Process not found.")
                        continue

                    try:
                        print("Unfreezing...")
                        process.resume()
                    except Exception as e:
                        print(f"Error: {e}")
                        continue

                    print(f"Unfreezed {process.name()} Successfuly !")
                elif wrs[1] == "scan":
                    if wrs[2] == "connections":
                        if len(wrs) > 3:
                            name = str(wrs[3])
                            value = 0
                            prc_value = 0
                            
                            for prc in psutil.process_iter(["pid" , "name"]):
                                if str(prc.info["name"]).lower() == str(name).lower():
                                    prc_value += 1
                                    for cnc in prc.net_connections():
                                        print(f"{cnc.laddr[0] if cnc.laddr else '-'} <-> {cnc.raddr[0] if (cnc.raddr and len(cnc.raddr)>0) else '-'} , SNIFF-SYNTAX: {cnc.laddr[0] if cnc.laddr else '-'}={cnc.raddr[0] if (cnc.raddr and len(cnc.raddr)>0) else '-'}")
                                        value += 1

                            if prc_value == 0:
                                print("No Process found.")
                                continue

                            if value == 0:
                                print("No Connections found.")
                            
                            continue    
            elif wrs[0] == "params":
                if wrs[1] == "autofreeze" or wrs[1] == "autofrz" or wrs[1] == "atfrz" or wrs[1] == "p1":
                    svlu = str(wrs[2]).lower()

                    if svlu == "true" or svlu == "yes" or svlu == "allow" or svlu == "on":
                        if Parameters["autofreeze"] == True:
                            print("AutoFreeze is already turned on.")
                            continue
                        else:
                            Parameters["autofreeze"] = True
                            print("AutoFreeze turned on successfuly !")
                    elif svlu == "false" or svlu == "no" or svlu == "disallow" or svlu == "off":
                        if Parameters["autofreeze"] == True:
                            print("AutoFreeze is already turned off.")
                            continue
                        else:
                            print("AutoFreeze turned off successfuly !")
                            Parameters["autofreeze"] = False
            elif wrs[0] == "sniff":
                if wrs[1] == "files":
                    scnt = wrs[2]
                    try:
                        int(scnt)
                    except:
                        print(Fore.RED + "Invalid Count.")
                        continue

                    count = int(scnt)

                    if count < 1:
                        print(Fore.RED + "Count must be bigger than zero.")
                        continue

                    if len(wrs) > 3:
                        path = str(wrs[3])
                        a = FileSniff(path, count)

                if wrs[1] == "connection":
                    connections = str(wrs[2])
                    if not "=" in connections:
                        print("Invalid Connection.")
                        continue

                    elements = connections.split("=")
                    if len(elements) != 2:
                        print("Invalid Connection.")
                        continue

                    src = elements[0]
                    dst = elements[1]

                    if len(wrs) == 4:
                        scnt = str(wrs[3])
                        
                        try:
                            int(scnt)
                        except:
                            print("Invalid Count.")
                            continue

                        count = int(scnt)
                        packeting = True

                        def handler(pkt):
                            nonlocal count
                            nonlocal packeting

                            a = PacketHandler(pkt, dst, src)

                            if a is True:
                                count -= 1

                            if count <= 0:
                                return True

                        sniff(prn=handler, stop_filter=lambda x: count <= 0)
                          

def LAUNCHER():
    print("[*] Checking Operating system... ")
    if os.name != "nt":
        print("This tool only works on Windows.")
        return
   
    print("[*] Checking Requirements...")
    if not Path("requirements.txt").exists():
        print("[FATAL ERROR] requirements.txt file is not satisfied")
        return
    
    subprocess.run(["python" , "-m" , "pip" , "install" , "-r", "requirements.txt"] , check=True)

    print("[*] All requirements installed successfully")
    print("[*] Launching WindowsProPacket..")
    ProPacket()
    
    
LAUNCHER()
