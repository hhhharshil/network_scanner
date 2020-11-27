#!/usr/bin/python
import scapy.all as scapy
import optparse #parse command line arguments from user
logo = '''

 /$$   /$$ /$$   /$$ /$$   /$$ /$$   /$$                               /$$       /$$ /$$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$                              | $$      |__/| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$  /$$$$$$   /$$$$$$   /$$$$$$$| $$$$$$$  /$$| $$
| $$$$$$$$| $$$$$$$$| $$$$$$$$| $$$$$$$$ |____  $$ /$$__  $$ /$$_____/| $$__  $$| $$| $$
| $$__  $$| $$__  $$| $$__  $$| $$__  $$  /$$$$$$$| $$  \__/|  $$$$$$ | $$  \ $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$ /$$__  $$| $$       \____  $$| $$  | $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$|  $$$$$$$| $$       /$$$$$$$/| $$  | $$| $$| $$
|__/  |__/|__/  |__/|__/  |__/|__/  |__/ \_______/|__/      |_______/ |__/  |__/|__/|__/

'''
print(logo)

def arguments():
    parser = optparse.OptionParser() #object created 
    parser.add_option("-t","--target", dest="ip_range", help="IP Range we would like to scan.") #added options to object
    (options, arguments) = parser.parse_args()
    if not options.ip_range:
        parser.error("[x] Please enter a valid IP Range, use --help for more information...")
    return options 

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) 
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_ls = scapy.srp(arp_request_broadcast, timeout=1, verbose = False)[0]

    
    client_list = [] #empty list used to store clients list
    for element in answered_ls: #for loop for each element that would be in the answered list returned by arp broadcast print the element back
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc} #dictionary created with an IP and a MAC key 
        client_list.append(client_dict) #dictionary is added as an element to the clients list.
        #print(element[1].psrc + "\t\t" + element[1].hwsrc) #the element answered_ls we are calling has a list inside it containing the request and response. we want to get the response back so we are grabbing [1]
    return client_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~") #making a header \t is used for tabing \n go on the next line
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = arguments()
scan_results = scan(options.ip_range)
print_result(scan_results)