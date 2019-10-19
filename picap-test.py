#!/usr/bin/python
import os
import subprocess
import time
from time import sleep
from papirus import PapirusComposite
import RPi.GPIO as GPIO


# Global switch variables.
SW1 = 21
SW2 = 16
SW3 = 20
SW4 = 19
SW5 = 26

def setup_buttons():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(SW1, GPIO.IN)
    GPIO.setup(SW2, GPIO.IN)
    GPIO.setup(SW3, GPIO.IN)
    GPIO.setup(SW4, GPIO.IN)
    if SW5 != -1:
        GPIO.setup(SW5, GPIO.IN)

current_essid_list = []
total_essid_list = []

display = PapirusComposite(False, 0)
def initialise_display():
    display.Clear()
    display.WriteAll()
    display.AddText("______________________________________________", 0, 5, 10, Id="top-boarder-line" )
    display.AddText("______________________________________________", 0, 76, 10, Id="bottom-boarder-line" )
    display.AddText("PICAP V!.0", 2, 2, 10, fontPath='fonts/computer.ttf', Id="header" )
    display.AddText("PWND:", 2, 88, 10, fontPath='fonts/computer.ttf', Id="footer-pwnd" )
    display.AddText("0" , 45, 86, 11, fontPath='fonts/FreeMonoBold.ttf', Id="footer-num-pwnd" )
    display.AddText("STATUS" , 130, 86, 11, fontPath='fonts/computer.ttf', Id="footer-status" )
    display.AddText('root@picap:>', 2, 15, 13, Id='term')
    display.AddText('Booting Up.....', 2, 28, 13, Id='term-output')
    display.WriteAll(True)

## Update Screen
def update_footer_status(status):
    display.UpdateText("footer-status", status)
def update_num_pwnd(num_pwnd, total_num_pwnd):
    display.UpdateText("footer-num-pwnd", str(num_pwnd) + "[%s]" % total_num_pwnd)
def update_ssid_term(ssid):
    display.UpdateText('term','root@%s:>' % ssid)
def update_term_output(text_to_update):
    display.UpdateText("term-output", text_to_update)
def update_all():
    if len(current_essid_list) > 0 & len(current_essid_list) < 5:
        update_num_pwnd(len(current_essid_list), len(total_essid_list))
        update_ssid_term(current_essid_list[len(current_essid_list) - 1])
        update_term_output("KEEP THEM COMING!")
    elif len(current_essid_list) > 5 & len(current_essid_list) < 10:
        update_num_pwnd(len(current_essid_list))
        update_ssid_term(len(current_essid_list) - 1)
        update_term_output("OH SHIT YEAH!")
    elif len(current_essid_list) > 10 & len(current_essid_list) < 15:
        update_num_pwnd(len(current_essid_list))
        update_ssid_term(len(current_essid_list) - 1)
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
        print("Error is wlan0mon enabled? or has it cooked it?")
        pass

def start_passive_packet_capture():
    #os.spawn(os.P_DETACH, 'hcxdumptool -i wlan0mon -o picap-handshakes.pcapng')
    os.system('rm /home/pi/picap/captures/picap-handshakes.pcapng')
    global hcxdump_passive_capture
    hcxdump_passive_capture = subprocess.Popen(["hcxdumptool", "-i", "wlan0mon", "-o", "/home/pi/picap/captures/picap-handshakes.pcapng"], stdout=subprocess.PIPE)

def start_active_packet_capture():
    #os.spawn(os.P_DETACH, 'hcxdumptool -i wlan0mon -o picap-handshakes.pcapng')
    os.system('rm /home/pi/picap/captures/picap-handshakes.pcapng')
    global hcxdump_active_capture
    hcxdump_active_capture = subprocess.Popen(["hcxdumptool", "-i", "wlan0mon", "-D", "10", "-o", "/home/pi/picap/captures/picap-handshakes.pcapng"], stdout=subprocess.PIPE)

## sorted(np.unique(list1+list2))
def process_pcap():
    ## Seperate pmkids/epol handshakes
    os.system('rm /home/pi/picap/captures/picap-handshakes.hccapx')
    os.system('rm /home/pi/picap/captures/picap-handshakes.16800')
    os.system('hcxpcaptool -I /home/pi/picap/captures/essid-names -o /home/pi/picap/captures/picap-handshakes.hccapx -z /home/pi/picap/captures/picap-handshakes.16800 /home/pi/picap/captures/picap-handshakes.pcapng')
    try:
        handshake_file=open("/home/pi/picap/captures/picap-handshakes.16800", "r")
        if handshake_file.mode == 'r':
            handshakes = handshake_file.read()
            handshakes = handshakes.replace("\n", "*")
            handshakes = handshakes.split('*')
            current_essid_list_unsorted = []
            for i in range(3, len(handshakes), 4):
                current_essid_list_unsorted.append(handshakes[i].decode('hex'))

            for i in current_essid_list_unsorted:
                if i not in current_essid_list:
                    current_essid_list.append(i)
    except:
        update_term_output("NO PMKIDS YET")
        display.WriteAll(True)
## Process 
def process_pmkid_stash():
    try:
        handshake_file=open("captures/PMKID-stash", "r")
        if handshake_file.mode == 'r':
            handshakes = handshake_file.read()
            handshakes = handshakes.replace("\n", "*")
            handshakes = handshakes.split('*')
            total_essid_list_unsorted = []
            for i in range(3, len(handshakes), 4):
                total_essid_list_unsorted.append(handshakes[i].decode('hex'))
            for i in total_essid_list_unsorted:
                if i not in total_essid_list:
                    total_essid_list.append(i)
            update_num_pwnd(len(current_essid_list), len(total_essid_list))
            display.WriteAll(True)
    except:
        print('error, maybe no pmkids in stash?')
        pass

## RUN PMKID CAPTURE
def passive_capture_handshakes():
    update_footer_status("PASSIVE MODE")
    start_monitor_mode()
    start_passive_packet_capture()
    time.sleep(10)
    while not GPIO.input(SW1) == False:
        current_num_handshakes = len(current_essid_list)
        process_pcap()
        process_pmkid_stash()
        update_all()
        time.sleep(5)
## QUITING PMKID CAPTURE
    ## Kill hcxdump and hcxpcaptools properly
    hcxdump_passive_capture.kill()
    update_term_output("Shutting Down HCXDUMPTOOL")
    ## Save PMKIDS to stash
    os.system('cat captures/picap-handshakes.16800 >> captures/PMKID-stash')
    os.system('sort -u -o captures/PMKID-stash captures/PMKID-stash')
    ## Save HANDSHAKES to shash
    os.system('cat captures/picap-handshakes.hccapx >> captures/HANDSHAKE-stash')
    os.system('sort -u -o captures/HANDSHAKE-stash captures/HANDSHAKE-stash')
    # sleep to prevent button from registering twice
    time.sleep(2)
    #os.system()

def active_capture_handshakes():
    update_footer_status("ACTIVE MODE")
    start_monitor_mode()
    start_active_packet_capture()
    time.sleep(10)
    while not GPIO.input(SW1) == False:
        current_num_handshakes = len(current_essid_list)
        process_pcap()
        process_pmkid_stash()
        update_all()
        time.sleep(5)
## QUITING PMKID CAPTURE
    ## Kill hcxdump and hcxpcaptools properly
    hcxdump_active_capture.kill()
    update_term_output("Shutting Down HCXDUMPTOOL")
    ## Save PMKIDS to stash
    os.system('cat captures/picap-handshakes.16800 >> captures/PMKID-stash')
    os.system('sort -u -o captures/PMKID-stash captures/PMKID-stash')
    ## Save HANDSHAKES to shash
    os.system('cat captures/picap-handshakes.hccapx >> captures/HANDSHAKE-stash')
    os.system('sort -u -o captures/HANDSHAKE-stash captures/HANDSHAKE-stash')
    # sleep to prevent button from registering twice
    time.sleep(2)
    #os.system()



def main():
    while True:
        update_term_output('======~MAIN MENU~======')
        process_pmkid_stash()
        # Exit when SW1 and SW2 are pressed simultaneously
        if (GPIO.input(SW1) == False) and (GPIO.input(SW2) == False) :
            update_term_output('Cya Yall')
            sleep(0.2)
            display.clear()
            sys.exit()
        if GPIO.input(SW1) == False:
            passive_capture_handshakes()
            print('PASSIVE MODE')
        if GPIO.input(SW2) == False:
            active_capture_handshakes()
            print('PASSIVE MODE')
        if GPIO.input(SW3) == False:
            update_term_output('three')
            print('3')
        if GPIO.input(SW4) == False:
            update_term_output('four')
            print('4')
        if (SW5 != -1) and (GPIO.input(SW5) == False):
            update_term_output('five')
            print('5')
        display.WriteAll(True)
        sleep(0.1)

if __name__ == "__main__":
    initialise_display()
    setup_buttons()
    main()


## for decoding hexsting back into essid
# "hex value".decode('hex')

