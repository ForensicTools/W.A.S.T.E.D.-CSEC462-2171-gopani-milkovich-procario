import os
import sys
import json
import time
import socket
import urllib.request
from collections import defaultdict

# dictionary to hold all results
records = {}

###
#   FUNCTION: parsing
#   ARGS:     badSites, response (list, list)
#   RETURN:   records (dictionary)
#
#   ABOUT:    parsing function
#             open up the results of the tshark on the PCAP
#             extract the hostnames from the DNS lookups, use them to find 
#             IPs and locations. Locations are the latitude and longitude 
#             associated with the IP. Increments the entry visit counter if
#             the hostname already exists. Returns a dictionary of all the
#             hosts visited, the information, and number of page visits
###
def parsing(badSites, response, capfile):
    print("Gathering URLs")
    for url in response:
        hostName = url.strip()
        # get the IP using the host name - used for location
        # ip = getIP(hostName)[0]
        # list of all associated ips
        # url of the API to grab the location using IP
        # query the API
        if url in records.keys():
            pass
        else:
            records[hostName] = {}
            records[hostName]["svgPath"] = "targetSVG"
            records[hostName]["zoomLevel"] = "5"
            records[hostName]["scale"] = ".5"
            records[hostName]["title"] = hostName
            records[hostName]["IP"] = []
            records[hostName]["NumPackets"] = 0
            records[hostName]["TotalSize"] = 0
            records[hostName]["color"] = "yellow"
            records[hostName]["selectedColor"] = "green"
            getServers(records, capfile)
            if badSites[hostName] is not None:
                records[hostName]["color"] = "red"
                records[hostName]["selectedColor"] = "red"
    print("Iinitial Dictionry Created")
    locationCheck = 'http://freegeoip.net/json/'
    getServers(records, capfile)
    print("IPs Collected")
    hosts = records.keys()
    remove = []
    for host in hosts:
        try:
            ip = records[host]["IP"][0]
            with urllib.request.urlopen(locationCheck+ip) as res:
                # get wanted information from json
                location = json.loads(res.read().decode())
                lat = location["latitude"]
                lon = location["longitude"]
                records[host]["Latitude"] = lat
                records[host]["Longitude"] = lon
        except:
            remove.append(host)
    for entry in remove:
            print("Host no longer online:")
            print(records[entry])
            del records[entry]
    return records

###
#   FUNCTION: getServers
#   ARGS:     records
#   RETURN:   records (dictionary)
#
#   ABOUT:    getServers function
#             get the IPs associated with each DNS entry
### 
def getServers(records, capfile):
    cmd = "tshark -r" + capfile + " -T fields -e dns.qry.name -e dns.a -Y \"dns.flags == 0x8180\""
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

###
#   FUNCTION: packetInfo
#   ARGS:     records
#   RETURN:   records (dictionary)
#
#   ABOUT:    packetInfo function
#             get the number of packets and total size for each
#             host
#
#TODO: change title field to proper formatting
###
def packetInfo(records):
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
        if line[0] in scope:
            records[mapping[line[0]]]["NumPackets"] += 1
            records[mapping[line[0]]]["TotalSize"] += int(line[2])
        elif line[1].strip() in scope:
            records[mapping[line[1]]]["NumPackets"] += 1
            records[mapping[line[1]]]["TotalSize"] += int(line[2])
        else:
            continue
    return records

###
#   FUNCTION: getIP
#   ARGS:     hostname
#   RETURN:   array or string
#
#   ABOUT:    getIP function
#             get the IP From the hostname
###
def getIP(hostName):
    try:
        ip = socket.gethostbyname_ex(hostName.strip())
        return ip[2]
    except:
        return "Not Found"

###
#   FUNCTION: knownBad
#   ARGS:     level
#   RETURN:   badSites
#
#   ABOUT:    knownBad function
#             takes user input from sensitivity
#             reads lines from (high|medium|low).txt
#             which contain known malicious webpages
###
def knownBad(level):
    badSites = defaultdict(lambda: None)
    if level == "high":
        if os.path.isfile("./Resources/high.txt"):
            with open("./Resources/high.txt") as file:
                for line in file:
                    badSites[line.strip()] = 1
        else:
            print("high.txt does not exist, please move it into Resources directory")
            sys.exit(1)

    elif level == "medium":
        if os.path.isfile("./Resources/medium.txt"):
            with open("./Resources/medium.txt") as file:
                for line in file:
                    badSites[line.strip()] = 1
        else:
            print("medium.txt does not exist, please move it into Resources directory")
            sys.exit(1)

    elif level == "low":
        if os.path.isfile("./Resources/low.txt"):
            with open("./Resources/low.txt") as file:
                for line in file:
                    badSites[line.strip()] = 1
        else:
            print("low.txt does not exist, please move it into Resources directory")
            sys.exit(1)

    else:
        print("Please enter a valid sensitivity level")
        sys.exit(1)
    return badSites

###
#   FUNCTION: makeMap
#   ARGS:     info
#   RETURN:   none
#
#   ABOUT:    makeMap function
#             utilizes the 'info' dictionary to construct
#             javascript objects, pushes the objects into
#             a webpage.html template, finalizes the webpage
#             by opening a new file, mapper.html which pinpoints 
#             IPs by geolocation
###
def makeMap(info):

    file = open("./Resources/webpage.html", "r")
    contents = file.readlines()
    file.close()

    imagesStart = "    \"images\": ["
    imagesEnd = "]\n  },\n"

    webpage_info = []
    for key,value in info.items():
        svgpath = value['svgPath']
        zoomlevel = value['zoomLevel']
        scale = value['scale']
        title = value['title']
        latitude = value['Latitude']
        longitude = value['Longitude']
        color = value['color']
        selectedcolor = value['selectedColor']
        count = value['NumPackets']

        string = "{\n      \"svgPath\": %s,\n      \"zoomLevel\": %s,\n      \"scale\": %s,\n      \"title\": \"Title: %s, Count: %s\",\n      \"latitude\": %s,\n      \"longitude\": %s,\n      \"color\": \"%s\",\n      \"selectedColor\": \"%s\"\n    }, " % (svgpath,zoomlevel,scale,title,count,latitude,longitude,color,selectedcolor)

        webpage_info.append(string)

    webpage_object = "".join(webpage_info)
    webpage_string = imagesStart + webpage_object + imagesEnd

    contents.insert(98,webpage_string)

    file2 = open("mapper.html", "w")
    contents = "".join(contents)
    file2.write(contents)
    file2.close()

    time.sleep(2)
    os.system('/usr/bin/firefox ./mapper.html')

if __name__ == '__main__':
    # Create an inteactive way to choose the PCAP and level of comparison (bad list)

    # Low sensitivity has more false positives
    # High has less flase positives
    level = input("Choose sensitivity (low,medium,high): ")
    capfile = input("Input .pcap file to analyze: ")
    #if the file isnt a pcap, exit
    if ('.pcap' or '.pcapng') not in capfile:
        print("Not a valid .pcap file, please input a proper file")
        sys.exit(1)
    #if the mapper.html webpage exists, delete old version
    if os.path.isfile("mapper.html"):
        os.system('rm -f mapper.html')
    #if the pcap exists in the directory, continue 
    if os.path.isfile(capfile):
        badSites = knownBad(level)
        response = os.popen("tshark -r" + capfile + " -T fields -e dns.qry.name -Y \"dns.flags.response eq 0\" | grep .com$").read()
        response = response.splitlines()
        records = parsing(badSites,response,capfile)
        info = packetInfo(records)

        #create the map
        makeMap(info)
    #if the pcap file doesn't exist, exit
    else:
        print("The file \"%s\" does not exist. Are you using the full path?" % capfile)
        sys.exit(1)
