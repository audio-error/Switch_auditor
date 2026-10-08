import re, os, sys, csv, time
import argparse
import ipaddress
import logging
from secret_loader import Auth
from scrapli.driver.core import IOSXEDriver

parser = argparse.ArgumentParser(
    prog='SwitchAuditor',
    description='Will conect to a list of switches and check if the MAC address in the description field of each port matches the MAC address in the Mac table',
    epilog='Text at the bottom of help',
    suggest_on_error=True)
parser.add_argument(
    "-s",
    nargs="+",
    dest="ip_addresses",
    type=str,
    help='a list of IP address that are CISCO switches'
)
parser.add_argument(
    "-v", "--verbose",
    action='store_true',
    help='Verbose mode will print the commands being sent for debugging.'
)

args = parser.parse_args()
ip_addresses = args.ip_addresses
verbose = args.verbose

# Validate each IP
for ip in ip_addresses:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        logging.warning(f"{ip} is not a valid IP Address")
        sys.exit(2)

auth = Auth().get_secrets()['values']

username = auth["username"]
password = auth["password"]
out_file = "switch_audit.csv"

# MAC address regex pattern
mac_pattern = r"([A-Fa-f0-9]{2}[:\-][A-Fa-f0-9]{2}[:\-][A-Fa-f0-9]{2}[:\-][A-Fa-f0-9]{2}[:\-][A-Fa-f0-9]{2}[:\-][A-Fa-f0-9]{2}|[A-Fa-f0-9]{4}\.[A-Fa-f0-9]{4}\.[A-Fa-f0-9]{4})"

def print_verbose(value):
    if verbose:
        print("\x1b[0m\x1b7",end='')#save cursor pos
        print(f"\x1b[0K Sending Command: {value}",end='', flush=True)#move to bottom of the terminal and print
        print("\x1b8\x1b[0K",end='')#return cursor
        time.sleep(0.3)

def print_ports(value, port, block_size=12, rows=2, interface_level=0):    
    def whichLine(n):
        if rows == 1:
            return 1
        if n % 2 == 0:
            return 1
        else:
            return 2

    if 1 < rows > 2:
        raise("Rows must be either 1 or 2.")
    
    if value == 'X': print('\033[31m', end='')
    elif value == '?' or value == '!': print('\033[36m', end='')
    if value == 'T': print('\033[32m', end='')
    elif value == 'F': print('\033[33m', end='')

    port_width = len(value) + 2

    match(port):
        case n if n % 2 != 0:
            #Odd number
            #print(n, end='')
            print(f"[{value}]", end='', flush=True)
            if rows == 2:
                if n == 1:
                    print(f'\x1b[{port_width}D\n', end='') # hacky way to fix but \x1b[1B (move down one line) wont create a new line if the cursors at the bottom of the terminal so this fixes the issue where the ports are printed upside down
                else:
                    print(f'\x1b[{port_width}D\x1b[1B', end='')

        case n if n % 2 == 0:
            #Even number
            print(f"[{value}]", end='', flush=True)
            if rows == 2:
                print('\x1b[1A', end='')
        case _:
            pass

    #spacing between blocks
    if port % block_size == 0:
        if rows == 2:
            print("\x1b[1B  \x1b[1A  ", end='')
        else:
            print("  ", end='')

    print(f"\033[0m\x1b7\x1b[{whichLine(port)}F\x1b[{interface_level * 5}C{port}\x1b8", end='', flush=True)

#print legend
print("=" * 60)
print("""T: Mac address in description matches the address in the port's Mac table
F: Mac address in the desciption is different from the Mac table
X: port is down
!: port is not present but is listed in the switch as an interface
?: Port is not administratively down however both the Mac table and Description are empty""")
for ip_address in ip_addresses:
    device = {
        "host": ip_address,
        "auth_username": username,
        "auth_password": password,
        "auth_secondary" : password,
        "ssh_config_file": "~/.ssh/config",
        "auth_strict_key": False,
        "timeout_socket": 10,
        "timeout_transport": 30,
    }
    
    try:
        with IOSXEDriver(**device) as conn:
            # Get version info
            version_result = conn.send_command("show version | include interfaces")
            print("=" * 60)
            print(f"Switch: {ip_address}")
            print("=" * 60)
            print(version_result.result)
            
            # Initialize port tracking
            port_list = []
            interfaces = {} # the list of interfaces on the switch

            #sets the number of ports on each interface and the interface type ("GigabitEthernet")
            for line in version_result.result.strip().split('\n'):
                match = re.match(r'(\d+)\s+(.+?)\s+interfaces', line)
                if match:
                    num_ports = int(match.group(1))
                    interface_name = match.group(2).replace(' ', '')
                    interfaces[interface_name] = num_ports


            print(interfaces)
            print()
            #print("\x1b[10S\x1b[10T")#create enough room in the terminal to prevent the first port printout from being cut off
            c = 0
            for interface in interfaces:
                if "Virtual" in interface:
                    continue #skip virtual interfaces
                rows = 1 if "Ten" in interface else 2
                block_size = 6*rows

                ports = interfaces[interface]
                # Iterate through ports
                for port in range(1, ports + 1):
                    if interface == "TenGigabitEthernet" and interfaces[interface] > 10 and ports - port < 4: 
                        c = 1 #this is a hack to get the interface number incremeting properly for the C3850-12XS switch
                        port = port - 12
                    if "GigabitEthernet" in interfaces and interfaces["GigabitEthernet"] == 50:
                        c = 0 # hack to get interface number increasing properly for WS-C2960XR-48FPD-I


                    port_status = {
                        "port": f"{interface} 1/{c}/{port}",
                        "desc": "None",
                        "mac": "None",
                        "match": False,
                        "down": False
                    }
                    #is port down
                    cmd_down = f"show interface {interface} 1/{c}/{port} | include down | not present"
                    print_verbose(cmd_down)
                    down_result = conn.send_command(cmd_down)
                    down = down_result.result.strip()
                    #if the port's down then skip other checks
                    #print(down)
                    if "not present" in down or "Invalid input" in down:
                        print_ports("!", port,block_size=block_size, rows=rows, interface_level=c)
                        port_list.append(port_status)
                        continue
                    if "administratively down" in down:
                        port_status["down"] = True
                        print_ports("X", port,block_size=block_size, rows=rows, interface_level=c)
                        port_list.append(port_status)
                        continue

                    # Get interface description
                    cmd_description = f"show interface {interface} 1/{c}/{port} | include Description"
                    print_verbose(cmd_description)
                    desc_result = conn.send_command(cmd_description)
                    description = desc_result.result.strip()
                    
                    # Check if MAC address matches regex in description
                    desc_match = re.search(mac_pattern, description)
                    if desc_match:
                        port_status["desc"] = desc_match.group(0)
                    else:
                        port_status["desc"] = "None"
                    
                    # Get MAC address table for this port
                    cmd_mactable = f"show mac address-table interface {interface} 1/{c}/{port}"
                    print_verbose(cmd_mactable)
                    mac_result = conn.send_command(cmd_mactable)
                    mac_output = mac_result.result.strip()
                    
                    # Check if MAC address matches regex in MAC table
                    mac_match = re.findall(mac_pattern, mac_output)
                    if mac_match:
                        port_status["mac"] = mac_match
                    else:
                        port_status["mac"] = "None"
                    

                    desc_mac = re.sub(r'[:\-.]', '',port_status["desc"]).lower()
                    for mac in mac_match:
                        mac = re.sub(r'[:\-.]', '',mac).lower()
                        if desc_mac==mac:
                            port_status["match"] = desc_mac==mac # remove the symbols : - . from mac addresses for comparison

                    port_list.append(port_status)
                    
                    if port_status["match"]:
                        if port_status["desc"] == "None" and port_status["mac"] == "None":
                            print_ports("?", port,block_size=block_size, rows=rows, interface_level=c)
                        else:
                            print_ports("T", port,block_size=block_size, rows=rows, interface_level=c)
                    else:
                        print_ports("F", port,block_size=block_size, rows=rows, interface_level=c)
                c = c + 1
            print()
            print()

            for port in port_list:
                # Claude Haiku 4.5
                # Append to CSV
                file_exists = os.path.isfile(out_file)
                
                with open(out_file, "a", newline="") as csvfile:
                    fieldnames = ["IP Address", "Port", "Description", "MAC Address", "Match MAC Addresses", "Administratively Down"]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    # Write header only if file is new
                    if not file_exists:
                        writer.writeheader()
                    
                    # Write the row
                    writer.writerow({
                        "IP Address": ip_address,
                        "Port": port['port'],
                        "Description": port['desc'],
                        "MAC Address": port['mac'],
                        "Match MAC Addresses": port['match'],
                        "Administratively Down": port['down']
                    })
                #

    
    except Exception as e:
        print(f"Error connecting to {ip_address}: {e}")
        continue
    
print(f"\n=== Switch Summary | {out_file} ===")
print("All switches processed.")
