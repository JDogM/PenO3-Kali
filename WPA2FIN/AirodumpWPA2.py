import os
import sys

mac = sys.argv[1]
filepath = sys.argv[2]

os.system("sudo airodump-ng --bssid {} ".format(mac) + " -c 1 -w " + filepath + "/WPA_{} ".format(mac) + "--output-format cap wlan1mon")
