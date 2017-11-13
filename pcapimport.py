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
    for url in response:
        hostName = url.strip()
        # get the IP using the host name
        ip = getIP(hostName)[0]
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
            lat = "unknown"
            lon = "unknown"
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
    response = os.popen('tshark -r web.pcap -T fields -e dns.qry.name -Y "dns.flags.response eq 0" | grep .com').read()
    response = response.splitlines()
    results = parsing(badSites,response)
    with open('result.json', 'w') as fp:
            json.dump(results, fp)
