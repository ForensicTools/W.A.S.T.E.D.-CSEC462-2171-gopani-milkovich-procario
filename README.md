# W.A.S.T.E.D.

-----

### Web Alert Security Tap and Event Detailer
##### CSEC462-2171

_Michael Milkovich: mjm1276@g.rit.edu, Priya Gopani: pxg1622@g.rit.edu, Chris Procario: cxp2714@g.rit.edu_

Please contact Chris Procario for updates, modification requests, or bug reports.

-----

### PREREQUISITES:

Linux based operating system with FireFox

Tshark

Python 3 (!)

------

### To use this tool

Please follow the directions in "instructions.txt"

------

### Description

This will be a web traffic monitor to verify safety of sites visited by users on an enterprise network. The tool’s main purpose is to verify the safety of the sites being visited by the users, as well as comparing the visited sites to lists of known-bad to trigger security alerts in the event a known-bad site is visited.

This is particularly important in discovery attempts at attacks such as phishing, where threat actors attempt to get users to visit malicious sites or download malicious files from their servers. The goal of this tool is to allow network traffic monitors to have a real time display of where their traffic is going and quick, efficient alerts in the event a threat is introduced to their environment.

A secondary use for this tool is ensuring proper use of company resources and time. This is not intended as a “big brother” tool for enterprises, but more dedicated to making sure employees do not misuse servers or other company assets for personal gain.

-----

Source of bad sites: https://isc.sans.edu/suspicious_domains.html

Source of map template: https://www.amcharts.com/

Updated: 11/18/17
