import json
import socket
import argparse
import ipaddress

from netmiko import ConnectHandler
from getpass import getpass
import pandas as pd
import xml.etree.ElementTree as ET

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="More output than normal.", action="store_true")
parser.add_argument("-x", "--excel", help="Generate Excel Output file.", action="store_true")
parser.add_argument("--ip", help="IP to Lookup", action="store")
parser.add_argument("-o", "--output", help="Output Directory.", default="output/", action="store")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-f", "--file", help="XML Formatted Juniper SRX Configuration File", action="store")
group.add_argument("-c", "--connect", help="Connect to device given, execute 'show config | display xml'", action="store_true")

args = parser.parse_args()

# Do stuff with arguments.
if args.file:
    file = args.file
    if "/" in file:
        device = f"{file.split('/')[-1].split('.')[0]}.{file.split('/')[-1].split('.')[1]}"
    else:
        device = f"{file.split('.')[0]}.{file.split('.')[1]}"

if args.ip:
    try:
        ip = ipaddress.ip_address(args.ip)
    except ValueError:
        print(f"{args.ip} is not a valid IPv4 or IPv6 address. Exiting.")
        exit()


def get_from_device():
    device = {
        "device_type": "juniper_junos",
        "host": input(f"SRX hostname: "),
        "port": input(f"SSH Port: "),
        "username": input(f"Username: "),
        "password": getpass(),
    }

    # Show command that we execute.
    command = "show configuration | display xml"
    # Connect and send the command
    with ConnectHandler(**device) as net_connect:
        output = net_connect.send_command(command)
    # Parse the output into XML
    root = ET.fromstring(output)
    return root


def print_tag_and_text(tag, text):
    print(tag + ": " + text + ', ', end='')


def parse_file(file):
    # Parser the file to XML
    try:
        tree = ET.parse(args.file)
    except:
        print(f"{args.file} is either not valid XML, empty, or doesn't exist. Exiting.")
        exit()
    # Create/Find XML root object
    root = tree.getroot()
    return root


def parse_xml(root):
    # Initialize a bunch of objects.
    addresses = []
    address_sets = []
    applications = []
    application_set = []
    policies = []
    addresses_in_set_list = []
    sub_match_app_list = []
    sub_match_source_addr_list = []
    sub_match_dest_addr_list = []

    addresses_dict = {}
    address_sets_dict = {}
    policies_dict = {}

    application_in_set = ''
    sub_match_source_addr = ''
    sub_match_dest_addr = ''
    sub_match_app = ''
    term_label = ''
    addresses_in_set = ''
    source_port = ''
    dest_port = ''
    protocol = ''

    # Set up the excelwriter based on CLI input.
    if args.excel:
        writer = pd.ExcelWriter(f"{args.output}{device}.xlsx", engine='xlsxwriter')

    # Iterate through the XML, stepping through each layer until we get to the relevant data.
    for root_item in root:
        if root_item.tag == 'configuration':
            for conf_item in root_item:
                if conf_item.tag == 'security':
                    for sec_item in conf_item:
                        if sec_item.tag == 'address-book':
                            # Finally made it to something interesting.
                            for address_book_item in sec_item:
                                if address_book_item.tag == 'address':
                                    for address in address_book_item:
                                        if address.tag == 'name':
                                            name = address.text
                                        # Set a description if it exists, if not, set it to "none".
                                        if address.tag == 'description':
                                            description = address.text
                                        else:
                                            description = 'none'

                                        if address.tag == 'ip-prefix':
                                            ip_prefix = address.text

                                    # When we've collected all address book entries, shove it into a dictionary, reset the objects, and if asked to, write it to excel
                                    addresses_dict[ip_prefix] = {}
                                    addresses_dict[ip_prefix] = {'description': description, 'name': name}
                                    addresses.append([name] + [description] + [ip_prefix])
                                    # If we're writing and excel file, make a panda dataframe, then convert it to a worksheet in the 'writer' object we set up above.
                                    if args.excel:
                                        df1 = pd.DataFrame(addresses, columns=['Name', 'Description', 'IP Address'])
                                        df1.to_excel(writer, index=False, sheet_name='Addresses')

                                if address_book_item.tag == 'address-set':
                                    for address_set in address_book_item:
                                        if address_set.tag == 'name':
                                            name = address_set.text

                                        if address_set.tag == 'description':
                                            description = address_set.text
                                        else:
                                            description = 'none'

                                        if address_set.tag == 'address':
                                            addresses_in_set = addresses_in_set + address_set[0].text + ':'
                                            addresses_in_set_list.append(address_set[0].text)

                                    # When we've collected all address-sets, shove it into a dictionary, reset the objects, and if asked to, write it to excel
                                    if args.verbose:
                                        print(json.dumps(addresses_in_set_list, indent=4))
                                    address_sets_dict[name] = {}
                                    address_sets_dict[name] = {'description': description, 'addresses': addresses_in_set_list}
                                    address_sets.append([name] + [description] + [addresses_in_set])
                                    addresses_in_set = ''
                                    addresses_in_set_list = []
                                    if args.excel:
                                        # If we're writing and excel file, make a panda dataframe, then convert it to a worksheet in the 'writer' object we set up above.
                                        df2 = pd.DataFrame(address_sets, columns=['Name', 'Description', 'Addresses'])
                                        df2.to_excel(writer, index=False, sheet_name='Address-sets')

                        # Iterate through the policies
                        if sec_item.tag == 'policies':
                            #print("Reading policies in policies")
                            for policy in sec_item:
                                if policy.tag == 'policy':
                                    for policy_item in policy:
                                        if policy_item.tag == 'from-zone-name':
                                            from_zone_name = policy_item.text
                                        if policy_item.tag == 'to-zone-name':
                                            to_zone_name = policy_item.text

                                        if policy_item.tag == 'policy':
                                            for subpolicy in policy_item:
                                                if subpolicy.tag == 'name':
                                                    subpol_name = subpolicy.text
                                                if subpolicy.tag == 'match':
                                                    for match in subpolicy:
                                                        if match.tag == 'source-address':
                                                            sub_match_source_addr = sub_match_source_addr + match.text + ':'
                                                            sub_match_source_addr_list.append(match.text)
                                                        if match.tag == 'destination-address':
                                                            sub_match_dest_addr = sub_match_dest_addr + match.text + ':'
                                                            sub_match_dest_addr_list.append(match.text)
                                                        if match.tag == 'application':
                                                            sub_match_app = sub_match_app + match.text + ':'
                                                            sub_match_app_list.append(match.text)
                                            policies.append([from_zone_name] + [to_zone_name] + [subpol_name] + [sub_match_source_addr] + [sub_match_dest_addr] + [sub_match_app])
                                            # Reset objects
                                            sub_match_app = ''
                                            sub_match_dest_addr = ''
                                            sub_match_source_addr = ''
                                            policies_dict[subpol_name] = {}
                                            policies_dict[subpol_name] = {'from-zone-name': from_zone_name, 'to-zone-name': to_zone_name, 'source-address': sub_match_source_addr_list, 'destination-address': sub_match_dest_addr_list, 'application': sub_match_app_list}

                                        # Reset Lists
                                        sub_match_app_list = []
                                        sub_match_source_addr_list = []
                                        sub_match_dest_addr_list = []

                                    if args.excel:
                                        # If we're writing and excel file, make a panda dataframe, then convert it to a worksheet in the 'writer' object we set up above.
                                        df3 = pd.DataFrame(policies, columns=['from-zone-name', 'to-zone-name', 'name',
                                                                              'source-address', 'destination-address',
                                                                              'application'])
                                        df3.to_excel(writer, index=False, sheet_name='Policies')

                # iterate through the applications
                if conf_item.tag == 'applications':
                    #print("Reading applications and applications-sets in configuration")
                    for application in conf_item:
                        if application.tag == 'application':
                            for application_item in application:
                                if application_item.tag == 'name':
                                    name = application_item.text
                                if application_item.tag == 'protocol':
                                    protocol = application_item.text
                                if application_item.tag == 'destination-port':
                                    dest_port = application_item.text
                                if application_item.tag == 'source-port':
                                    source_port = application_item.text
                                if application_item.tag == 'term':
                                    for term in application_item:
                                        if term.tag == 'destination-port':
                                            term_label_dest_port = term.text
                                        if term.tag == 'protocol':
                                            term_label_protocol = term.text

                                        if len(term_label_dest_port) > 0 and len(term_label_protocol) > 0:
                                            term_label = term_label + term_label_dest_port + '/' + term_label_protocol + '\n'
                                            term_label_dest_port = ''
                                            term_label_protocol = ''

                            # When collected all applications, save it to excel
                            applications.append([name] + [source_port] + [dest_port] + [protocol] + [term_label])
                            # reset objects
                            term_label = ''
                            protocol = ''
                            dest_port = ''
                            source_port = ''
                            term_label_dest_port = ''
                            term_label_protocol = ''

                            if args.excel:
                                # If we're writing and excel file, make a panda dataframe, then convert it to a worksheet in the 'writer' object we set up above.
                                df4 = pd.DataFrame(applications,
                                                   columns=['Name', 'Source port', 'Destination port', 'Protocol',
                                                            'Destination ports/protocol'])
                                df4.to_excel(writer, index=False, sheet_name='Applications')

                        if application.tag == 'application-set':
                            for app_set_item in application:
                                if app_set_item.tag == 'name':
                                    name = app_set_item.text
                                if app_set_item.tag == 'application':
                                    application_in_set = application_in_set + app_set_item[0].text + '\n'
                            application_set.append([name] + [application_in_set])
                            application_in_set = ''

                            if args.excel:
                                # If we're writing and excel file, make a panda dataframe, then convert it to a worksheet in the 'writer' object we set up above.
                                df5 = pd.DataFrame(application_set, columns=['Name', 'Applications'])
                                df5.to_excel(writer, index=False, sheet_name='Application-sets')

    if args.excel:
        writer.save()
        print(f"Wrote: {args.output}{device}.xlsx")
    return addresses_dict, address_sets_dict, policies_dict


def find_ip_in_addresses(ip, addresses_dict):
    found_addresses = []
    for addresses in addresses_dict.keys():
        if ipaddress.ip_address(ip) in ipaddress.ip_network(addresses):
            found_addresses.append(addresses_dict[addresses]['name'])
    if args.verbose:
        print(found_addresses)
    return found_addresses


def find_address_in_address_sets(found_addresses, address_sets_dict):
    found_address_sets = []
    for entry in found_addresses:
        for set in address_sets_dict.keys():
            if entry in address_sets_dict[set]['addresses']:
                found_address_sets.append(set)
    if args.verbose:
        print(found_address_sets)
    return found_address_sets


def find_ip_in_policies(found_addresses, policies_dict):
    found_src_ip_policies = []
    found_dst_ip_policies = []
    for policy in policies_dict.keys():
        for entry in found_addresses:
            if entry in policies_dict[policy]['source-address']:
                found_src_ip_policies.append(policy)
            if entry in policies_dict[policy]['destination-address']:
                found_dst_ip_policies.append(policy)
    if args.verbose:
        print(found_src_ip_policies)
        print(found_dst_ip_policies)
    return found_src_ip_policies, found_dst_ip_policies


def find_address_sets_in_policies(found_address_sets, policies_dict):
    found_src_policies = []
    found_dst_policies = []
    for policy in policies_dict.keys():
        for entry in found_address_sets:
            if entry in policies_dict[policy]['source-address']:
                found_src_policies.append(policy)
            if entry in policies_dict[policy]['destination-address']:
                found_dst_policies.append(policy)
    if args.verbose:
        print(found_src_policies)
        print(found_dst_policies)
    return found_src_policies, found_dst_policies


def main(root):
    # Run the parser
    global ip
    addresses_dict, address_sets_dict, policies_dict = parse_xml(root)
    if args.ip:
        found_addresses = find_ip_in_addresses(ip, addresses_dict)

        if len(found_addresses) == 0:
            ip_found = False
            ip = 'any'
            found_address_sets = ['any']
            print(f"!!! {args.ip} was not found in any Address Book Entries. Matching Policies for 'ANY' !!!")
        else:
            ip_found = True
            try:
                ptr = socket.gethostbyaddr(args.ip)[0]
            except:
                ptr = "Unknown"
            found_address_sets = find_address_in_address_sets(found_addresses, address_sets_dict)
        found_src_policies, found_dst_policies = find_address_sets_in_policies(found_address_sets, policies_dict)
        found_src_ip_policies, found_dst_ip_policies = find_ip_in_policies(found_addresses, policies_dict)

        if ip_found:
            print(f"Results for: {ip}\nDNS: {ptr}")
            print(f"{args.ip} found in Address Book Entries:")
            for a in found_addresses:
                print(f" {a}")
        print(f"{args.ip} found in Address Book Entries:")
        for set in found_address_sets:
            print(f" {set}")
        print(f"{args.ip} found in Policies as SOURCE:")
        for src in found_src_policies:
            print(f" {src}")
        for src in found_src_ip_policies:
            print(f" {src}")
        print(f"{args.ip} found in Policies as DESTINATION:")
        for dst in found_dst_policies:
            print(f" {dst}")
        for dst in found_dst_ip_policies:
            print(f" {dst}")


if __name__ == '__main__':
    if args.file:
        root = parse_file(file)
    elif args.connect:
        root = get_from_device()
    else:
        # This shouldn't be possible.
        print(f"Error. Neither -f nor -c passed. Exiting")
        exit()
    main(root)

