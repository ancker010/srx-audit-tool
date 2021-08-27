# SMN SRX Firewall Audit Tool

A tool for auditing Juniper SRX Firewall Policies.
Use it to generate an excel spreadsheet for easier visual auditing OR specify a specific IPv4 or IPv6 address and see exactly what policies will match that address.

### Usage
1. Obtain the XML version of a Juniper SRX device configs `show configuration | display xml` and store it in a file.
2. Install the python requirements, preferrably into a venv. `pip install -r requirements.txt`
3. Run the script...
```shell
# There are two methods for providing the XML.
# Method 1: Via stored XML Config file
python3 srx-tool.py -f xml/srx-firewall-config.xml <options>
# Method 2: Connect to a live device and run `show configuration | display xml`.
python3 srx-tool.py -c <options>

# The script has two functions, generate spreadsheet for the entire device, or perform a lookup for an IP and print matching policies.
# Function 1, read the XML config, generate an Excel file with the relevant data.
python3 srx-tool.py -f xml/srx-firewall-config.xml -x
# Function 2, gather XML from a live device, find all Address Book entries and Policies that match a given IP address.
python3 srx-tool.py -c --ip 8.8.8.8
```

### Example Output

```shell
# Function 1
username@host:~/projects/srx-tool$ python3 srx-tool.py -f xml/srx-firewall-config.xml -x
Wrote: output/srx-firewall-config.xlsx

# Function 2
username@host$ python3 srx-tool.py -c --ip 8.8.8.8
Device hostname: <device-hostname>
Port: <port>
Username: <username>
Password: 
Results for: 8.8.8.8
DNS: dns.google
8.8.8.8 found in Address Book Entries:
 HOST_8.8.8.8
8.8.8.8 found in Address Book Entries:
 DNS_SERVERS_BOOK
8.8.8.8 found in Policies as SOURCE:
 MAIN-PERMIT-DNS-IN
 DC-PERMIT-DNS-IN
 SERVERS-PERMIT-DNS-IN
8.8.8.8 found in Policies as DESTINATION:
 MAIN-PERMIT-DNS-OUT
 DC-PERMIT-DNS-OUT
 SERVERS-PERMIT-DNS-OUT

```

### Command Flags
```shell
username@host:~/projects/srx-tool$ python3 srx-tool.py -h
usage: srx-tool.py [-h] [-v] [-x] [--ip IP] [-o OUTPUT] (-f FILE | -c)

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         More output than normal.
  -x, --excel           Generate Excel Output file.
  --ip IP               IP to Lookup
  -o OUTPUT, --output OUTPUT
                        Output Directory.
  -f FILE, --file FILE  XML Formatted Juniper SRX Configuration File
  -c, --connect         Connect to device given, execute 'show config | display xml'

```


##### Credits
A portion of this script is based on work here: https://github.com/mr-awk/juniper_fw_xml_to_xlsx
Thus this code is covered under GPL-3.0.