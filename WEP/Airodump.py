import os
import sys

mac = sys.argv[1]
os.system("sudo airodump-ng --bssid {} -c 1 -w IV_{} --output-format cap wlan1mon".format(mac, mac))
