import re
from collections import defaultdict
import sys
import ipaddress


DEBUG = False

def debug_print(*args):
    if DEBUG:
        print(*args)
        

# Data structures to hold the configuration
object_groups = defaultdict(lambda: defaultdict(list))
access_lists = defaultdict(dict)
class_maps = defaultdict(dict)
policy_maps = defaultdict(dict)
zone_pairs = defaultdict(dict)
zones = defaultdict(dict)

# Regular expressions for matching configuration blocks
object_group_pattern = re.compile(
    r'^object-group (\S+)\s+(\S+)([\s\S]+?)\n!',
    re.DOTALL | re.MULTILINE
)
access_list_pattern = re.compile(
    r'^ip access-list extended (\S+)([\s\S]+?)\n',
    re.DOTALL | re.MULTILINE
)
class_map_pattern = re.compile(
    #r'class-map type (\S+) match-(all|any) (\S+)(?:\s|.*\n)+match access-group name (\S+)',
    r'^class-map type inspect match-(all|any) (\S+)(?:\s|.*\n)+?match access-group name (\S+)',
    re.DOTALL | re.MULTILINE
)
policy_map_pattern = re.compile(
    r'^policy-map type inspect (\S+)([\s\S]+?)(?=\npolicy-map type inspect|\n!$)',
    re.DOTALL | re.MULTILINE
)
zone_pair_pattern = re.compile(
    r'^zone-pair\s+security (\S+)\s+source (\S+) destination (\S+)(?:\s|.*\n)+?service-policy type inspect (\S+)',
    re.DOTALL | re.MULTILINE
)
zone_pattern = re.compile(
    r'^zone security (\S+)\s*\n+ vpn (\d+)',
    re.DOTALL | re.MULTILINE
)


# Function to parse object groups
def parse_object_groups(config):
    matches = object_group_pattern.findall(config)
    debug_print(f"###Parsing object-groups:\n {matches}") # Debugging statement
    for obj_type, name, block in matches:
        lines = block.strip().splitlines()
        for line in lines:
            if obj_type in ['service', 'network', 'fqdn'] and not line.startswith('object-group'):
                if obj_type == 'fqdn':
                    patterns = line.split(' ')[-1].strip()
                    for pattern in patterns:
                        object_groups[obj_type][name].append(pattern)
                else:
                    object_groups[obj_type][name].append(line)

def parse_access_lists(config):
    matches = access_list_pattern.findall(config)
    debug_print(f"###Parsing access-lists:\n {matches}")  
    for name, rule in matches:
        access_lists[name] = rule

# Function to parse class maps
def parse_class_maps(config):
    matches = class_map_pattern.findall(config) 
    debug_print(f"###Parsing class-maps:\n {matches}") 
    for match_type, name, access_list_name in matches:
        class_maps[name]['match_type'] = match_type
        class_maps[name]['access_list'] = access_list_name

# Function to parse policy maps
def parse_policy_maps(config):
    matches = policy_map_pattern.findall(config)
    debug_print(f"###Parsing policy-maps:\n {matches}") 
    for policy_map_name, block in matches:
        classes = re.findall(r'class type inspect (\S+)', block)
        policy_maps[policy_map_name] = {'class_maps': classes}
    #print(f"policy-maps matches: {policy_maps}") 

# Function to parse zone pairs
def parse_zone_pairs(config):
    matches = zone_pair_pattern.findall(config)
    debug_print(f"###Parsing zone-pairs\n: {matches}")
    for pair_name, source_zone, destination_zone, policy_name in matches:
        zone_pairs[pair_name] = {
            'source_zone': source_zone,
            'destination_zone': destination_zone,
            'policy_name': policy_name.strip()  # Remove potential leading/trailing whitespace
        }
# Function to parse zones
def parse_zones(config):
    matches = zone_pattern.findall(config)
    debug_print(f"###Parsing zones\n: {matches}") 
    for name, vpn_number in matches:
        zones[name] = vpn_number
        
# Function to parse the entire configuration
def parse_configuration(config_text):
    parse_zones(config_text)
    parse_zone_pairs(config_text)
    parse_policy_maps(config_text)
    parse_object_groups(config_text)
    parse_access_lists(config_text)
    parse_class_maps(config_text)

# Function to convert subnet mask to prefix length
def subnet_to_prefix(subnet):
    return sum(bin(int(x)).count('1') for x in subnet.split('.'))

# Function to check if an IP or domain matches an object group
def ip_in_object_group(ip_or_domain, object_group):
    # Check if the input is an IP address or a domain
    is_ip = True
    try:
        ipaddress.ip_address(ip_or_domain)
    except ValueError:
        is_ip = False

    # If the input is an IP address, check the network and host entries
    if is_ip:
        ip = ipaddress.ip_address(ip_or_domain)
        for entry in object_groups['network'].get(object_group, []):
            if 'any' in entry:
                return True
            if 'host' in entry:
                _, host_ip = entry.split()
                if ip == ipaddress.ip_address(host_ip):
                    return True
            else:
                address, subnet = entry.split()
                prefix =  subnet_to_prefix(subnet)
                network = ipaddress.ip_network(f'{address}/{prefix}')
                if ip in network:
                    return True
    # If the input is a domain, check the fqdn entries
    else:
        domain = ip_or_domain
        debug_print(f"Domain: {domain}")
        for entry in object_groups['fqdn'].get(object_group, []):
            pattern = entry.split(' ')[-1].strip()  # Get the pattern and strip whitespace
            debug_print(f"Pattern: {pattern}")
            if re.search(pattern, domain):
                debug_print(f"Found matching pattern: {pattern}")
                return True

    return False
    
# Function to check if a service matches an object group
def service_in_object_group(service, object_group):
    for entry in object_groups['service'][object_group]:
        service_regex = r'{}\s+\d+'.format(re.escape(service))  # Expect service followed by a port number
        if re.fullmatch(service_regex, entry.strip()):
            return True
    return False

# Function to find all access-lists referencing the matched object-groups
def find_access_lists(matching_groups_src,matching_groups_dst):
    matching_access_lists = []
    for access_list, rules in access_lists.items():
        debug_print("Checking access list: ", access_list)
        debug_print("Checking rules: ", rules)
        # Normalize rules to always be a list
        if isinstance(rules, str):
            rules = [rules]

        # Find ACLs with matching source objects in it
        for src_obj_type, src_group_list in matching_groups_src.items():
            for src_group_name in src_group_list:
                # Check for source group name in each rule
                for rule in rules:
                    if src_group_name in rule:
                        debug_print(f"Found matching (src) rule in acl: {rule}")

                        # Find ACLs with matching destination objects in the same rule
                        for dst_obj_type, dst_group_list in matching_groups_dst.items():
                            for dst_group_name in dst_group_list:
                                # Destination object is the last one in the rule
                                if rule.strip().endswith(dst_group_name):
                                    debug_print(f"Found matching (dst) rule in acl: {rule}")
                                    # Append the access list name and the rule that matches both src and dst, no need to return tuple (())
                                    #matching_access_lists.append((access_list, rule))
                                    matching_access_lists.append(access_list)
                  
    print(f"### All matching src group-objects: {matching_groups_src}")  
    print(f"### All matching dst group-objects: {matching_groups_dst}")  
    print(f"### All matching access lists: {matching_access_lists}") 
    return matching_access_lists

# Function to find all class-maps referencing the matched access-lists
def find_class_maps(matching_access_lists):
    matching_class_maps = []
    for class_map, details in class_maps.items():
        debug_print("Checking class-map: ", class_map)
        debug_print("Checking details: ", details)
        if details['access_list'] in matching_access_lists:
            matching_class_maps.append(class_map) 
    debug_print(f"### Matching class maps: {matching_class_maps}") 
    return matching_class_maps

def find_zone(vpn_number):
    for zone_name, vpn in zones.items():
        if vpn == vpn_number:
            return zone_name
    return None
    
def find_zone_pair(source_zone, destination_zone):
    for pair_name, details in zone_pairs.items():
        if details['source_zone'] == source_zone and details['destination_zone'] == destination_zone:
            print(f"### Zone-pair: {pair_name}")
            return details
    return None
    
def find_policy_map(zone_pair):
    policy_name = zone_pair['policy_name']
    print(f"### Policy-name: {policy_name}")
    return policy_maps.get(policy_name)
    
# Function to display only the class-maps referenced in the policy-map
def display_relevant_class_maps(policy_map, matching_class_maps):
    # Debug print to check what's in policy_map
    debug_print("###Policy Map Content:", policy_map)
    # Assuming policy_map is a dictionary with a 'class_maps' key mapping to a list of class map names
    policy_class_map_names = policy_map.get('class_maps', [])    
    # Filter the class maps present in the policy_map against the matching_class_maps
    relevant_class_maps = [cm for cm in matching_class_maps if cm in policy_class_map_names]    
    print("### Relevant class-maps:")
    for class_map in relevant_class_maps:
        print(f"{class_map}")   

# Main execution function
def main(config_file, source_vpn, destination_vpn, source_ip, destination_ip):
    try:
        with open(config_file, 'r') as file:
            config_text = file.read()
    except FileNotFoundError:
        print(f"Error: The file {config_file} was not found.")
        sys.exit(1)
    except IOError as e:
        print(f"Error: An I/O error occurred while reading the file: {e}")
        sys.exit(1)

    parse_configuration(config_text)

    
    source_zone = find_zone(source_vpn)
    destination_zone = find_zone(destination_vpn)
    
    #source_vpn = zones.get(source_zone)
    #destination_vpn = zones.get(destination_zone)
    
    if not source_zone or not destination_zone:
        print("Invalid source or destination zone.")
        sys.exit(1)

    zone_pair = find_zone_pair(source_zone, destination_zone)
    if zone_pair is None:
        print("No zone-pair found for the given zones.")
        sys.exit(1)
    else:
	    debug_print(f"Zone-pair details: {zone_pair}")   	

    policy_map = find_policy_map(zone_pair)
    if not policy_map:
        print("No policy-map found for the given zone-pair.")
        sys.exit(1)
    else:
	    debug_print(f"Policy-map details: {policy_map}")  
	    
    #matching_groups = {'service': [], 'network': [], 'fqdn': []}
    matching_groups_src = {'network': [], 'fqdn': []}
    matching_groups_dst = {'network': [], 'fqdn': []}
    
    # Check source IP/domain
    if source_ip != 'any':
        for group_name in object_groups['network']:
            if ip_in_object_group(source_ip, group_name):
                if "-src_" in group_name:
                    matching_groups_src['network'].append(group_name)
        for group_name in object_groups['fqdn']:
            if ip_in_object_group(source_ip, group_name):
                matching_groups_src['fqdn'].append(group_name)
    else:
        matching_groups_src['network'].append('any')
    
    # Check destination IP/domain
    if destination_ip != 'any':
        for group_name in object_groups['network']:
            if ip_in_object_group(destination_ip, group_name):
                if "-dstn_" in group_name:
                    matching_groups_dst['network'].append(group_name)
        for group_name in object_groups['fqdn']:
            if ip_in_object_group(destination_ip, group_name):
                matching_groups_dst['fqdn'].append(group_name)
    else:
        matching_groups_dst['network'].append('any')
        
    matching_access_lists = find_access_lists(matching_groups_src,matching_groups_dst)
    matching_class_maps = find_class_maps(matching_access_lists)
    display_relevant_class_maps(policy_map, matching_class_maps)

if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python script.py <config_file> <source VPN> <destination VPN> <source IP/FQDN> <destination IP/FQDN>")
        sys.exit(1)

    config_file = sys.argv[1]
    source_vpn = sys.argv[2]
    destination_vpn = sys.argv[3]
    source_ip = sys.argv[4]
    destination_ip = sys.argv[5]

    main(config_file, source_vpn, destination_vpn, source_ip, destination_ip)
