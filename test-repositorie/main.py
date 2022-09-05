from readOutput import readOutput  # Module for reading specific output
from writeOutput import writeOutput  # Module for writing results
from nmapper import nmapper  # Nmap module for scanning ports and services
from datetime import date  # Module for datetime
import re  # Module for the regex that needs to be checked
from glob import glob  # Module for global
import time  # Module time
import os  # Os module
import xml.etree.ElementTree as ET
import sys
import argparse

# TODO: Is Host up function (scan 2 to 3 ports first: 139, 445, 80)


# Function to create the date for the folder name
def todaysDate():
    day = date.today().day
    month = date.today().month
    year = date.today().year

    time = str(day) + "-" + str(month) + "-" + str(year)

    return time


# Main program
def main():
    arguments = sys.argv
    print("Give me some arguments" % (arguments))

    parser = argparse.ArgumentParser(prog="main.py")
    parser.add_argument("-s", "--subnet",  action='store_true', dest="subnetScan",
                        help="Scan subnet, insert the subnet in the following file: ./host-list/subnet-file.txt")
    parser.add_argument("-hl", "--hostlist", action='store_true', dest="hostlistScan",
                        help="Scan hostlist, insert the subnet in the following file: ./host-list/host-list.txt")
    parser.add_argument("-ht", "--host", action='store_true', dest="hostScan",
                        help="Scan host, insert the subnet in the following file: ./host-list/single-host.txt")
    parser.add_argument("-http", "--httpscan", action="store_true", dest="httpScan", help="Scan HTTP service")
    parser.add_argument("-ftp", "--ftpscan", action='store_true', dest="ftpScan", help="Scan FTP service")
    parser.add_argument("-smb", "--smbscan", action='store_true', dest="smbScan", help="Scan SMB service")
    parser.add_argument("-smtp", "--smtpscan", action='store_true', dest="smtpScan", help="Scan SMTP service")
    parser.add_argument("-ssh", "--sshbf", action='store_true', dest="sshScan", help="Bruteforce SSH")
    parser.add_argument("-telnet", "--telnetscan", action='store_true', dest="telnetScan", help="Scan Telnet service")

    if len(sys.argv) == 1:
        parser.print_help()
        return

    args = parser.parse_args()

    subnetScan = args.subnetScan
    hostlistScan = args.hostlistScan
    hostScan = args.hostScan

    serviceScanOptions = [args.httpScan, args.ftpScan, args.smbScan, args.smtpScan, args.sshScan, args.telnetScan]

    oneScan = True

    # if two or more scanoption are selected
    if (subnetScan and hostlistScan) or (subnetScan and hostScan) or (hostlistScan and hostScan):
        print("Please select one of three scans")
        oneScan = False
        exit()

    if oneScan:
        if subnetScan:
            print("Subnetscan")
            subnetRegex = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)')  # Subnet regex

            with open("./host-list/subnet-file.txt") as subnetFile:
                subnet = subnetFile.readline()  # Read only first line in subnet file

            subnet = subnet.rstrip("\n")  # Strip newline from string

            if subnetRegex.search(subnet):  # If subnet is equal to the regex, start subnet scan
                # folder name change because of / errors to new subfolder
                foldername = subnet.replace("/", "-")
                try:
                    filewriter = writeOutput("./scans/", "nmap-scan.txt", "", foldername)
                    print(filewriter.createdDirectoies())

                    fpingNetwork = nmapper("", "", subnet, "", pnFlag="-Pn")  # Create object for subnet scan
                    fpingfile = fpingNetwork.scanWithfping()
                except NameError:
                    pass  # XML error in library/ module that needs to be fixed

                reading = open(fpingfile[1], "r")  # Open the host list
                lines = reading.readlines()  # Read the host list

                for line in lines:  # Scan each IP (system) in the list
                    line = line.rstrip("\n")  # Strip the newline from the IP address
                    try:
                        filewriter = writeOutput("./scans/", "nmap-scan.txt", "", line)
                        print(filewriter.createdDirectoies())

                        mapNetwork = nmapper("", "", "", line)
                        result = mapNetwork.mapNetwork()

                    except NameError:
                        pass  # XML error in library/ module that needs to be fixed

                results = ["hostlist", todaysDate(), "", serviceScanOptions, fpingfile[0]]
        elif hostlistScan:
            print("Host list scan")
            file = "./host-list/host-list.txt"  # specify the list for the hosts
            reading = open(file, "r")  # Open the host list
            lines = reading.readlines()  # Read the host list

            for line in lines:  # Scan each IP (system) in the list
                line = line.rstrip("\n")  # Strip the newline from the IP address
                try:
                    filewriter = writeOutput("./scans/", "nmap-scan.txt", "", line)
                    print(filewriter.createdDirectoies())

                    mapNetwork = nmapper("", "", "", line)
                    result = mapNetwork.mapNetwork()

                except NameError:
                    pass  # XML error in library/ module that needs to be fixed

            results = ["hostlist", todaysDate(), "", serviceScanOptions]
        elif hostScan:
            print("Host scan")

            with open("./host-list/single-host.txt") as singleHostFile:
                ipAddr = singleHostFile.readline()  # Read only first line in subnet file

            ipAddr = ipAddr.rstrip("\n")  # Strip newline from string

            try:
                filewriter = writeOutput("./scans/", "nmap-scan.txt", "", ipAddr)
                print(filewriter.createdDirectoies())

                mapNetwork = nmapper(ipAddr, "", "", "")
                result = mapNetwork.mapNetwork()
            except NameError:
                pass  # XML error in library/ module that needs to be fixed

            results = [ipAddr, todaysDate(), "", serviceScanOptions]

    return results


# Function for scanning specific service(s)
def mapServices(file, subnetFolder="", serviceScanOptions=[]):
    outputReader = readOutput(file, "nmap")
    ipAddr = outputReader.readIpAddr()
    services = outputReader.readServices()

    if ipAddr == "":
        serviceScanner = []
    else:

        if len(services) <= 1:  # Start Nmap -Pn scan to skip host detection if no services have been detected
            print("Second scan started for the host " + ipAddr + " without host discovery")
            mapNetwork = nmapper(ipAddr, "", "", "", pnFlag="-Pn", serviceScanOptions=serviceScanOptions)

            #time.sleep(10)  # Wait for network scan to be completed

            # If subnet folder
            if subnetFolder != "":
                for file in glob("./scans/" + todaysDate() + "/" + subnetFolder + "/" + ipAddr + "/*.nmap"):
                    outputReader = readOutput(file, "nmap")  # Create output reader with the file that just has been created

                services = outputReader.readServices()  # Read all the open/ filtered services
                # Instantiate service mapper
                serviceMapper = nmapper(ipAddr, services, "", "", pnFlag="-Pn", subnetFolder=subnetFolder,
                                        serviceScanOptions=serviceScanOptions)
                serviceScanner = serviceMapper.mapService()  # Scan each service
            else:
                mapNetwork.mapNetwork()

                time.sleep(5)

                for file in glob("./scans/" + todaysDate() + "/" + ipAddr + "/*.nmap"):
                    outputReader = readOutput(file, "nmap")  # Create output reader with the file that just has been created

                services = outputReader.readServices()  # Read all the open/ filtered services
                serviceMapper = nmapper(ipAddr, services, "", "", pnFlag="-Pn",
                                        serviceScanOptions=serviceScanOptions)  # Instantiate service mapper
                serviceScanner = serviceMapper.mapService()  # Scan each service

        else:  # Start normal services scan
            if subnetFolder != "":
                serviceMapper = nmapper(ipAddr, services, "", "", subnetFolder=subnetFolder,
                                        serviceScanOptions=serviceScanOptions)
                serviceScanner = serviceMapper.mapService()
            else:
                serviceMapper = nmapper(ipAddr, services, "", "", serviceScanOptions=serviceScanOptions)
                serviceScanner = serviceMapper.mapService()

    return serviceScanner


def writeSubnetToXML(xmlOutputFile, rDirectory):
    tree = ET.parse(xmlOutputFile)  # Get the whole xmltree
    root = tree.getroot()  # Get root
    directory = rDirectory  # set directory

    for item in root.findall('host'):  # Find each host in the XML
        for child in item.findall("address"):  # Get each IP address
            ipAddr = child.attrib['addr']  # Get the IP address
            path = os.path.join(directory, ipAddr)  # Create output directory

            if os.path.isdir(directory + ipAddr) == False:  # If folder of host if does not excist
                os.mkdir(path)  # Create directory

            file = open(path + "/nmap-scan.xml", "w")  # Open file for specific host
            file.write(ET.tostring(item, encoding='unicode'))  # Write specific data for host


def writeSubnetToGnmap(gnmapOutputFile, rDirectory):
    directory = rDirectory  # Directory

    with open(gnmapOutputFile, "r") as outfile:  # Open the Subnet scan file
        lines = outfile.readlines()  # Read all the lines
        ipList = []  # Create list with unique IP addresses
        for line in lines:
            ipAddr = line.split()[1]  # Get IP address
            if ipAddr not in ipList:  # Append unique IP address and add to the list
                ipList.append(ipAddr)

        for ip in ipList:
            path = os.path.join(directory, ip)  # Create path
            if os.path.isdir(directory + ip) == False:  # If folder of host if does not excist
                os.mkdir(path)  # Create directory

            file = open(path + "/nmap-scan.gnmap", "w")  # Create/ open file

            for line in lines:
                if ip in line.split()[1]:  # Add line to specific file with the same IP address
                    file.write(line.strip("\n"))


def writeSubnetToNmap(nmapOutputFile, rDirectory, subnet):
    directory = rDirectory
    IPRegex = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')  # Regex to check for IP address

    with open(nmapOutputFile, "r") as outfile:  # Read the nmap file
        lines = outfile.readlines()  # Read all the lines
        ipList = []  # Create list with unique IP addresses
        ipAddr = IPRegex.findall(str(lines))  # Find all IP addresses

        for ip in ipAddr:
            if ip not in ipList:
                ipList.append(ip)  # Append unique IP address to list

        size = len(subnet)  # Get the length from the subnet
        findSubnet = subnet.find("/")  # Get the / position in the subnet string
        subnetLength = size - findSubnet  # Calculate the subnet length in the string

        for ip in ipList:
            path = os.path.join(directory, str(ip))  # Create path

            if os.path.isdir(directory + str(ip)) == False:  # If folder of host if does not excist
                os.mkdir(path)  # Create directory

            file = open(path + "/nmap-scan.nmap", "a")  # Create/ open file
            outputLine = False  # Define value for in the loop

            for line in lines:  # loop for each line
                if ip == subnet[:size - subnetLength]:  # If the IP equals to the subnet IP
                    break  # Skip the subnet IP
                # Get each block of data for specific host
                elif outputLine or str("Nmap scan report for " + ip) in line.rstrip("\n"):
                    file.write(line)
                    outputLine = True

                    if not line.strip():  # If the specific data block ends
                        break  # Break loop en continue to next IP (host)


def subnetDevider(todaysDate, subnetFoldername, ipAddr=""):
    directory = "./scans/" + todaysDate + "/" + subnetFoldername.replace("/", "-") + "/"
    listFiles = os.listdir(directory)
    xmlOutputFile = directory + listFiles[0]
    gnmapOutputFile = directory + listFiles[1]
    nmapOutputFile = directory + listFiles[2]

    writeSubnetToXML(xmlOutputFile, directory)
    writeSubnetToGnmap(gnmapOutputFile, directory)
    writeSubnetToNmap(nmapOutputFile, directory, subnetFoldername)


if __name__ == "__main__":
    IPRegex = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')  # Regex to check for IP address
    firstScan = main()  # Runs the main part of the tool
    serviceScanOptions = firstScan[3]

    if firstScan[0] == "hostlist":  # Scan en output services for each host in host list
        print("read full folder")
        subnet = ""

        with open("./host-list/subnet-file.txt", "r") as exclusionFile:
            for line in exclusionFile:
                subnet = line
                break

            subnet = subnet.replace("/", "-")

        for directory in os.listdir("./scans/" + firstScan[1] + "/"):
            if directory.rstrip("\n") == subnet:
                print("Skip subnet folder")
            else:
                fdirectory = "./scans/" + firstScan[1] + "/" + directory
                for file in glob(fdirectory + "/*.nmap"):
                    print(mapServices(file, serviceScanOptions=serviceScanOptions))

    elif IPRegex.search(firstScan[0]):  # Scan each service for specific host
        print("Read specific host")
        for file in glob("./scans/" + firstScan[1] + "/" + firstScan[0] + "/*.nmap"):
            print(file)
            print(mapServices(file, serviceScanOptions=serviceScanOptions))
    elif firstScan[0] == "subnet":
        print("Read subnet folder")
        subnetDevider(firstScan[1], firstScan[2], ipAddr=firstScan[0])

        time.sleep(5)

        directory = "./scans/" + todaysDate() + "/" + firstScan[2].replace("/", "-")

        globDirectory = glob(directory + "/*/")

        for file in glob(directory + "/*/" + "*.nmap"):
            print(mapServices(file, subnetFolder=firstScan[2].replace("/", "-"), serviceScanOptions=serviceScanOptions))
    else:
        print("No host list, subnet or IP address defined")

    if len(firstScan) > 4:
        if firstScan[4]:
            if os.path.exists(firstScan[4] + "/fping-subnet-scan.txt"):
                os.remove(firstScan[4] + "/fping-subnet-scan.txt")
            if os.path.exists(firstScan[4] + "/fping-subnet-scan-unfiltered.txt"):
                os.remove(firstScan[4] + "/fping-subnet-scan-unfiltered.txt")
            if os.path.isdir(firstScan[4]):
                os.rmdir(firstScan[4])
