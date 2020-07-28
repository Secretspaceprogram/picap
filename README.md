# picap
## HANDSHAKE AND PKMID CAPTURE TOOL FOR RASPBERRY PI
### INFO:
This tool is written in python and is intended to be used on a Raspberry Pi Zero with a PaPiRus ePaper display. It can be run in active or passive mode. Active mode sends out deauth packets while it is capturing to try and Increase the chances of capturing a 4 way handshake. In passive mode it doeesn't send out deauth packets and will be much more likely to just capture PMKIDS. All hashes are processed then saved in a hashcat friendly format on the raspberry pi.
