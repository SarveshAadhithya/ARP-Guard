import os
import time
import subprocess
import threading
import scapy.all as scapy

orig_ip_mac = {}
arpfreq = False
arpcache = False
def final_check():
    print("[Code 11]")
    if arpcache==True and arpfreq==False:print("[WARNING] : ARP cache has multiple Ip mapped to one mac address. Please verify it as soon as possible.")
    if arpcache==False and arpfreq==True:print("[WARNING] : ARP Frequency per second is more than 10 packets to your nic. Please verify it as soon as possible.")
    if arpcache==True and arpfreq==True:
        print("[ALERT] : ARP frequncy exceeded and ARP cache has duplicate mac address.\n *Disabling internet access in (10) seconds.")
        post_attack_action()


def table_format(a):
    print('\n[CODE 1]\n')
    ip_mac = {}
    listed_table = []
    for i in a:
        if len(i.split()) == 0 or (i.split()[0]=='Interface:' or i.split()[0]=='Internet'): 
            continue
        ip_mac[i.split()[0]] = i.split()[1]
    for i in list(ip_mac.keys()):
        if ip_mac[i] == 'ff-ff-ff-ff-ff-ff':
            del ip_mac[i]
    return dict(set(list(ip_mac.items())))


def command():
    print('\n[CODE 2]\n')
    command = "arp -a"
    output = os.popen(command).readlines()
    return table_format(output)


def arp_frequency(pkt):
    global arpfreq
    print('\n[CODE 3]\n')
    recent_packets = []
    threshold_freq = 10
    if pkt[scapy.ARP].op == 1:
        recent_packets.append(time.time())
        recent_packets_in_last_second = [p for p in recent_packets if p > time.time() - 1]
        # Calculate the ARP packet frequency
        arp_frequency = len(recent_packets_in_last_second)
        if arp_frequency>10:
            arpfreq = True
            final_check()
            #print("[ALERT] Attack detected. MORE THAN 10 ARP packets per second found.\n*DISABLING INTERNET ACCESS. CONTACT THE NETWORK ADMINISTRATOR.")   
        arpfreq = False
        #print(f"ARP packet frequency: {arp_frequency} per second")


def check_duplicate_ipmacpair(ip_mac):
    global arpcache
    print('\n[CODE 4]\n')
    global orig_ip_mac
    print('* Checking arp entries..')
    check_output_dic = command()
    if check_output_dic!= orig_ip_mac:
        attacker = get_attacker_ip(check_output_dic,find_attacker(check_output_dic))
        print('* ALERT : ARP spoof found') 
        print('YOUR IP AND ATTACKER IP : ',attacker )
        #print('* Disabling Wi-Fi/Ethernet in (10)secs')  
        #time.sleep(10)
        arpcache = True
        final_check()
        #print('\n\nDisabled your Internet access.Contact network adminsitrator/remove the attacker ip from the network.')


    else:
        if arpcache!=True:arpcache=False
        print('* No spoofing detected.')


def get_attacker_ip(table,spoofmac):
    print('\n[CODE 5]\n')
    if len(spoofmac) >= 1:
        return [i for i in table.keys() if table[i] == spoofmac[0]]
    return None



def find_attacker(dup_table):
    print('\n[CODE 6]\n')
    spoofed_mac = []
    for i in list(dup_table.values()):
        if list(dup_table.values()).count(i) > 1:
            spoofed_mac.append(i)
    return list(set(spoofed_mac))


def precheck(ip_mac_table):
    print('\n[CODE 7]\n')
    attacker = get_attacker_ip(ip_mac_table,find_attacker(ip_mac_table))
    if (attacker) != None:
        return True,attacker
    return False,attacker  


def post_attack_action():
    print('\n[CODE 8]\n')
    # Get list of available network interfaces
    output = subprocess.check_output('netsh interface show interface', shell=True)
    # Find interface name for wireless connection
    interface_name = []
    listed = []
    for line in output.splitlines():
        
        line = line.decode('utf-8').strip()
        listed.append(line.split())
        '''if 'Wi-Fi' in line:
            interface_name = line.split()[-1]
            break'''
    
    for i in listed:
        if len(i) > 1:
            if i[1] == 'Connected' :
                interface_name.append(' '.join(i[3:]))
    if len(interface_name) != 0:
        # Disable network adapter
        
        for i in interface_name:
            subprocess.run(f'netsh interface set interface "{i}" admin=disable', shell=True)
            print(f"{i} disabled.")


def monitoring_intialize():
    print('\n[CODE 9]\n')
    scapy.sniff(prn=arp_frequency, filter="arp", store=0)

"""
netsh interface set interface "{i}" admin=disable"""

def arp_cache_intialize():
    print('\n[CODE 10]\n')
    print('Monitoring ARP attacks...\n\n')
    ip_mac_table = command()
    result,attacker = precheck(ip_mac_table)
    global arpcache
    if result==False and attacker==None:
        
        arpcache = True
        global orig_ip_mac
        orig_ip_mac = ip_mac_table
        print('* Captured ARP table.[No spoofing so far]')
        time.sleep(10)
        try:
            while True:
                check_duplicate_ipmacpair(orig_ip_mac)# This function should be executed every 10mins/some periodic time in order to detect any new spoofing
                time.sleep(10)
        except KeyboardInterrupt:
            print('[ARP SPOOF MONITORING STOPPED]')
    else:
        print('* Captured ARP table.[DETECTED MAC SPOOFED]')
        print('* ATTACKER IP and YOUR IP : ',attacker)
        #print('* Disabling Wi-Fi/Ethernet in (10)secs')
        #time.sleep(10)
        arpcache = True
        final_check()
        time.sleep(10)
        arp_cache_intialize()
        #print('\n\nDisabled your Internet access.Contact network adminsitrator/remove the attacker ip from the network.')

t1 = threading.Thread(target=arp_cache_intialize)
t2 = threading.Thread(target=monitoring_intialize)

t1.start()
t2.start()



    