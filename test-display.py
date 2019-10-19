#!/usr/bin/python
import os
import subprocess
import time
from papirus import PapirusComposite

essid_list = []

display = PapirusComposite(False, 0)
test = "hey there fucker"

def initialise_display():
    display.AddText("______________________________________________", 0, 5, 10, Id="top-boarder-line" )
    display.AddText("______________________________________________", 0, 76, 10, Id="bottom-boarder-line" )
    display.AddText("PICAP V!.0", 2, 2, 10, fontPath='fonts/computer.ttf', Id="header" )
    display.AddText("PWND:", 2, 88, 10, fontPath='fonts/computer.ttf', Id="footer-pwnd" )
    display.AddText("0" , 45, 86, 11, fontPath='fonts/FreeMonoBold.ttf', Id="footer-num-pwnd" )
    display.AddText("-%s-" % test , 70, 88, 10, fontPath='fonts/computer.ttf', Id="footer-ssid")

    display.AddText('root@picap:>', 2, 15, 13, Id='term')
    display.AddText('Booting Up.....', 2, 28, 13, Id='term-output')
    display.WriteAll()

initialise_display()



#{-0_0}
#{*l*}
#{*_*}
#{*o*}
#{uwu}
