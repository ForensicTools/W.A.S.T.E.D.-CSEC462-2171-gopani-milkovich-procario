import os
import socket
import urllib
from contextlib import closing
import json

# dictionary to hold all results
records = {}

def parsingFile(badSites):
    """
    Open up the results of the tshark on the PCAP.
    Extract the hostnames from the DNS lookups then use them to find IPs
    and locations. Locations are the latitude and longitude associated with
    the IP. Increments the entry visit counter if the hostname already exists.
    :return: Dictionary of all of the hosts visited, the relevant information,
    and the number of times visited.
    """
    with open("web.txt") as file:
        for line in file:
            line = line.split()
            hostName = line[1]
            # get the IP using the host name
            ip = getIP(hostName)
            # url of the API to grab the location using IP
            url = 'http://freegeoip.net/json/'
            # query the API
            with closing(urllib.urlopen(url+ip)) as response:
                location = json.loads(response.read())
                # get wanted information from json
                lat = location["latitude"]
                lon = location["longitude"]

            if hostName in records.keys():
                # if host exists, increment counter
                records[hostName]["NumVisit"] += 1
            else:
                # if not, create entry and set visits to 1
                records[hostName] = {}
                records[hostName]["NumVisit"] = 1
                records[hostName]["Latitude"] = lat
                records[hostName]["Longitude"] = lon
                records[hostName]["IP"] = ip
                records[hostName]["KnownBad"] = 0
                if hostName in badSites:
                    records[hostName]["KnownBad"]  = 1
        return records

def getIP(hostName):
    """
    Get the IP from the hostname
    :param hostName: hostname of site visited
    :return: IP of target
    """
    ip = socket.gethostbyname(hostName.strip())
    return ip

def knownBad(level):
    if level == "high":
        badSites = open("high.txt").readlines()
    elif level == "medium":
        badSites = open("medium.txt").readlines()
    else:
        badSites = open("low.txt").readlines()
    return badSites

if __name__ == '__main__':
    # need to fix hardcoded pcap file
    # need to come up with way to not create file from output and just read command output instead

    # Create an inteactive way to choose the PCAP and level of comparison (bad list)
    # Low sensitivity has more false positives
    # High has less flase positives
    level = raw_input("Choose level (low,medium,high): ")
    badSites = knownBad(level)
    os.system('tshark -r web.pcap -T fields -e ip.src -e dns.qry.name -Y "dns.flags.response eq 0" | grep .com > web.txt')
    results = parsingFile(badSites)
    print(results)
