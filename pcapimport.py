import os
import socket
import urllib.request
import json

# dictionary to hold all results
records = {}

def parsing(badSites, response):
    """
    Open up the results of the tshark on the PCAP.
    Extract the hostnames from the DNS lookups then use them to find IPs
    and locations. Locations are the latitude and longitude associated with
    the IP. Increments the entry visit counter if the hostname already exists.
    :return: Dictionary of all of the hosts visited, the relevant information,
    and the number of times visited.
    """
    long = []
    lati = []
    for url in response:
        hostName = url.strip()
        # get the IP using the host name - used for location
        ip = getIP(hostName)[0]
        # list of all associated ips
        # url of the API to grab the location using IP
        locationCheck = 'http://freegeoip.net/json/'
        # query the API
        try:
            with urllib.request.urlopen(locationCheck+ip) as res:
                location = json.loads(res.read().decode())
                # get wanted information from json
                lat = location["latitude"]
                lon = location["longitude"]
        except:
            # if location is unknown
            continue
        if hostName in records.keys():
            pass
        else:
            # if not, create entry and set visits to 1
            records[hostName] = {}
            records[hostName]["svgPath"] = "targetSVG"
            records[hostName]["zoomLevel"] = "5"
            records[hostName]["scale"] = ".5"
            records[hostName]["title"] = hostName
            records[hostName]["Latitude"] = lat
            records[hostName]["Longitude"] = lon
            records[hostName]["IP"] = []
            records[hostName]["KnownBad"] = 0
            records[hostName]["NumPackets"] = 0
            records[hostName]["TotalSize"] = 0
            if hostName in badSites:
                records[hostName]["KnownBad"]  = 1
    return records

def getServers(records):
    cmd = 'tshark -r web1.pcap -T fields -e dns.qry.name -e dns.a -Y "dns.flags == 0x8180"'
    dnsRes = os.popen(cmd).read()
    dnsRes = dnsRes.splitlines()
    for line in dnsRes:
        line = line.split()
        strs = line[1]
        strs = strs.split(",")
        ips = []
        for i in strs:
            ips.append(i)
        hostName = line[0].strip()

        try:
            records[hostName]["IP"] = ips
        except:
            continue
    return records


def packetInfo(records):
    """
    Get the number of packets and total size for each host.
    :return: Dictionary with all results
    TODO Change title field to be proper
    """
    cmd = "tshark -r web1.pcap -T fields -e ip.src -e ip.dst -e frame.len"
    traffic = os.popen(cmd).read()
    traffic = traffic.splitlines()
    # make scope a list of all IPs in records
    scope = []
    # map ip to hostname for later use
    mapping = {}
    for host in records.keys():
        ips = records[host]["IP"]
        for ip in ips:
            scope.append(ip)
            mapping[ip] = host

    for line in traffic:
        line = line.strip().split()
        # some packets did not have source, dest, and size. Ignore these.
        if len(line) != 3:
            continue
        if line[0] == "151.101.20.193":
            print("here")
        if line[0] in scope:
            records[mapping[line[0]]]["NumPackets"] += 1
            records[mapping[line[0]]]["TotalSize"] += int(line[2])
        elif line[1].strip() in scope:
            records[mapping[line[1]]]["NumPackets"] += 1
            records[mapping[line[1]]]["TotalSize"] += int(line[2])
        else:
            continue
    return records

def getIP(hostName):
    """
    Get the IP from the hostname
    :param hostName: hostname of site visited
    :return: IP of target
    """
    try:
        ip = socket.gethostbyname_ex(hostName.strip())
        return ip[2]
    except:
        return "Not Found"

def knownBad(level):
    if level == "high":
        badSites = open("high.txt").readlines()
    elif level == "medium":
        badSites = open("medium.txt").readlines()
    else:
        badSites = open("low.txt").readlines()
    return badSites

if __name__ == '__main__':
    # Create an inteactive way to choose the PCAP and level of comparison (bad list)

    # Low sensitivity has more false positives
    # High has less flase positives
    level = input("Choose level (low,medium,high): ")
    badSites = knownBad(level)
    response = os.popen('tshark -r web1.pcap -T fields -e dns.qry.name -Y "dns.flags.response eq 0" | grep .com').read()
    response = response.splitlines()
    records = parsing(badSites,response)
    records = getServers(records)
    info = packetInfo(records)
    with open('result.json', 'w') as fp:
            json.dump(info, fp)
