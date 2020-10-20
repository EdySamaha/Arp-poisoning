import os, platform, subprocess, threading
from datetime import datetime
from scapy.all import *

"""
NOTE: Some Scapy specific funtions may show up as errors/undefined in editors
but actually they are not errors just subprocesses that run on command line
"""
numarp=0 #number of arp packets detected on network
#region FUNCTIONS
def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """
    # Packet options as a function of OS: Windows/Unix
    num_packets = '-n' if platform.system().lower()=='windows' else '-c' #-n/-c packet number
    size_packets= '-l' if platform.system().lower()=='windows' else '-s' #-l/-s byte size
    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', num_packets,'1',size_packets,'1', host]
    
    rstatus, response_ip= subprocess.getstatusoutput(command)     #rstatus= subprocess.call(command)
    response_ip = re.search('Reply from (.*):', response_ip).group(1)
    print(rstatus, response_ip)
    if(rstatus==0 and response_ip==host): #avoid another ip responding with target unreachable
        return True
    else:
        return False

def getNetworkIPs():
    for i in range(0,256):
        ip=prefix+str(i) #still working on this: idea is getting the prefix of router to scan the network
    if(ping(ip)):
        print(ip,getMac(ip))

def getArpTable():
    command = ['arp', '-a']
    subprocess.call(command)

def getMac(ip): #WORKS #can also use getmacbyip(ip) which is specific to Scapy
    p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip) #Create arp packet with dst=dest_broadcast and pdst=ip_target
    result = srp(p, timeout=3, verbose=False)[0] #Send created packet above over network
    try:
        mac= result[0][1].hwsrc #mac location in packet
        # print(mac)
        return mac
    except: #IndexError:
        #maybe fake IP or firewall (Apple devices) is blocking packets
        # print('No Mac found for',ip)
        return None
    
def checkMac(packet): #used with sniff() which is a Scapy specific function 
     global numarp
     if packet.haslayer(ARP): # if it is an ARP response (ARP reply)
        numarp+=1
        #Scapy encodes the type of ARP packet in a field called "op" which stands for operation, by default the "op" is 1 or "who-has" which is an ARP request, and 2 or "is-at" is an ARP reply
        if packet[ARP].op == 2: #check ARP replies (op=2)
            try:
                ip =packet[ARP].psrc
                real_mac = getMac(ip) # get the real MAC address of the sender
                if(real_mac==None):
                    print("[*] No MAC found for",ip)
                    return
                response_mac = packet[ARP].hwsrc # get the MAC address from the packet sent to us
                if real_mac != response_mac: # if they're different, there is an attack
                    print(f"[*] Fake arp detected:\n REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
            except:
                print("Couldn't check MAC of",ip)

def Detect(duration=10):
    start_time=datetime.now()
    print("Started at",start_time)
    print('Sniffing and checking...')
    
    """ For Scapy specific funtions below
    prn=checkMac runs checkMac for every packet (of course we focus on ARP packets as set in the function)
    store=False means don't save the packets
    """
    # sniff(store=False, prn=checkMac) #Scapy specific, ^C to stop, can also add filter="arp" as param
    #Asynchronous to implement time:
    t = AsyncSniffer(prn=checkMac, store=False)
    t.start()
    time.sleep(duration)
    t.stop()
    # print('Results:\n',t.results) #store=False so no output + no need
    print(numarp,'ARP packets were detected')

    print('\nStoped. Time taken:', datetime.now()-start_time)
#endregion

#RUN HERE
if __name__ == "__main__":
    # print('Your network:')
    # getNetworkIPs()
    print('\nYour current ARP table:',end='')
    getArpTable()

    print('\n')
    duration=input('Enter how many SECONDS you would like to sniff packets:\n')
    while(type(duration)!=int or duration<1):
        try:
            duration=int(duration)
            if(duration<1):
                duration=int(input("Please enter a positive integer: "))
        except:
            duration=input("Please enter an integer: ")
    # print(duration)
    Detect(duration)
   