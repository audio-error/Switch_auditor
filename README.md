# Switch_auditor
This is a simple cli script that check the mac address in the description of a port matches the mac address in the MAC table of that port. Has a neat CLI too

## Usage
SwitchAuditor [-h] [-s IP_ADDRESSES [IP_ADDRESSES ...]] [-v]

Will conect to a list of switches and check if the MAC address in the description field of each port matches the MAC
address in the Mac table

options:
  -h, --help            show this help message and exit
  -s IP_ADDRESSES [IP_ADDRESSES ...]
                        a list of IP address that are CISCO switches
  -v, --verbose         Verbose mode will print the commands being sent for debugging.

## Example Usage
SSHtoSwich.py -s 10.11.22.33 10.44.55.66 10.77.88.99

Verbose mode will output the commands being sent to the switch in case your switch has od interface numbering.
Keep in mind that it takes longer because the script will delay to give you time to read the commands.
