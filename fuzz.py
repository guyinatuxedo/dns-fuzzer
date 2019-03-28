# Libraries to be imported, all standard python libraries
import socket
import random
import getopt
import pickle
import time
import sys
import os

# Lists where we will store our dns records
fileRecordsA = []
fileRecordsMX = []
fileRecordsNS = []
fileRecordsMB = []
fileRecordsMG = []
fileRecordsMR = []
fileRecordsRP = []
fileRecordsKX = []
fileRecordsDS = []
fileRecordsTXT = []
fileRecordsSOA = []
fileRecordsWKS = []
fileRecordsPTR = []
fileRecordsLOC = []
fileRecordsSRV = []
fileRecordsURI = []
fileRecordsCAA = []
fileRecordsNULL = []
fileRecordsAAAA = []
fileRecordsNSEC = []
fileRecordsZone = []
fileRecordsCNAME = []
fileRecordsDNAME = []
fileRecordsHINFO = []
fileRecordsMINFO = []
fileRecordsAFSDB = []
fileRecordsNAPTR = []
fileRecordsSSHFP = []
fileRecordsDHCID = []
fileRecordsEUI48 = []
fileRecordsEUI64 = []

# Keep track of what zones we are given
fileRecordsZones = []

# A dictionary to map record types to their corresponding lists
fileRecordsDict = {
        "A":    fileRecordsA,   
        "MX":   fileRecordsMX,
        "NS":   fileRecordsNS,
        "MB":   fileRecordsMB,
        "MG":   fileRecordsMG,
        "MR":   fileRecordsMR,
        "RP":   fileRecordsRP,
        "KX":   fileRecordsKX,
        "DS":   fileRecordsDS,
        "TXT":  fileRecordsTXT,
        "SOA":  fileRecordsSOA,
        "WKS":  fileRecordsWKS,
        "PTR":  fileRecordsPTR,
        "LOC":  fileRecordsLOC,
        "SRV":  fileRecordsSRV,
        "URI":  fileRecordsURI,
        "CAA":  fileRecordsCAA,
        "NULL": fileRecordsNULL,
        "AAAA": fileRecordsAAAA,
        "NSEC": fileRecordsNSEC,
        "ZONE": fileRecordsZone,
        "CNAME":    fileRecordsCNAME,
        "DNAME":    fileRecordsDNAME,
        "HINFO":    fileRecordsHINFO,
        "MINFO":    fileRecordsMINFO,
        "AFSDB":    fileRecordsAFSDB,
        "NAPTR":    fileRecordsNAPTR,
        "SSHFP":    fileRecordsSSHFP,
        "DHCID":    fileRecordsDHCID,
        "EUI48":    fileRecordsEUI48,
        "EUI64":    fileRecordsEUI64
        }

# A dictionary to map DNS records to their integer equivalent
typeDict = {
        "A":        1,
        "NS":       2,
        "MD":       3,
        "MF":       4,
        "CNAME":    5,
        "SOA":      6,
        "MB":       7,
        "MG":       8,
        "MR":       9,
        "NULL":     10,
        "WKS":      11,
        "PTR":      12,
        "HINFO":    13,
        "MINFO":    14,
        "MX":       15,
        "TXT":      16,
        "RP":       17,
        "AFSDB":    18,
        "KX":       25,
        "AAAA":     28,
        "LOC":      29,
        "SRV":      33,
        "NAPTR":    35,
        "DNAME":    39,
        "DS":       43,
        "SSHFP":    44,
        "NSEC":     47,
        "DHCID":    49,
        "EUI48":    108,
        "EUI64":    109,
        "IXFR":     251,
        "AXFR":     252,
        "ANY":      255,
        "URI":      256,
        "CAA":      257
        }

# A dictionary to map record classes to their integer equivalent
classDict = {
        "IN":       1,
        "CH":       3,
        "HS":       4
        }

# A List of reverse records, which will be sent with IQUERY op code
reverseRecords = ["PTR"]

# Keep track of how many records, and record types we have
fileRecordsTypeCount = 0
fileRecordsCount = 0

# A dictionary to keep track of what record types we have
fileRecordsType = []

# Keep track of the corresponding lists for the record types we have
fileRecordsCountDict = {}

# Global variables to keep track of the target ip / port / protocol
ip = '127.0.0.1'
port = 53
udp = True

# Global variables to keep track of seeds, and how many seeds
seeds = []
maxseeds = 20

# Keep track of the percentage of data to send fuzzed versus normal
fuzzedData = 50
savedArgs = []

# Global variables to keep track of which crash check mechanism to use
checkPid = False
checkTcp = False
checkConn = False

# Variables to keep track of how many failed recv attempts for the udp recv "check-conn" mechanism
maxFailedRecvs = 20
failedRecvs = 0

# Keep track of the pid for the pid check and pname check crash detection mechanisms
pid = 0

# A variable to keep track if we are replaying a file
replaying = False

# A list of formats to use
fmtStrings = ["%n", "%N"]

# A list of possible delimeters
delimiters = ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', '\x20']

# Function to connect to a server
def serverConnect():
    global udp
    global ip
    global port
    try:
        # Check if we're using udp or tcp, then make the corresponding socket
        if udp == True:
            conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    except:
        badArg("Could not create socket: " + str(socket))
    # Try to connect with given ip / port and catach the exception 
    try:
        conn.connect((ip, port))
    except socket.error as error:
        badArg("Connection attempt failed: " + str(error))
    except:
        badArg("Could not establish connection.\nIP: " + ip + "\nPort: " + str(port))


    # Set the socket timeout
    conn.settimeout(.1)
    return conn

# Prints the help menu
def helpMenu():
    print "Help Menu: "
    print "-i <ip> or --remoteIP <ip>\t\t: Specify that <ip> is the IP address being fuzzed. Default 127.0.0.1"
    print "-p <port> or --port <port>\t\t: Specify that <port> is the port being fuzzed. Default 53"
    print "-f <x> or --fuzzed-data <x>\t\t: Specify that <x> prercent (out of 100) of packets sent are fuzzed. Default 50"
    print "-r <file> or --replay <file>\t\t: Specify to replay the file <file>."
    print "-m <seeds> or --max-seeds <seeds>\t: Specify that the max number of seeds to be saved in crash file is <seeds>. Default 20"
    print "-t or --tcp\t\t\t\t: Specify to use tcp instead of udp."
    print "-h or --help\t\t\t\t: Print the help menu."  
    print "\nCrash Detection: Must pick one\n"
    print "-n <name> or --pname <name>\t\t: Specify that the pid associated with the process name <name> is to be used."  
    print "-d <pid> or --pid <pid>\t\t\t: Specify that the pid <pid> is to be used."
    print "-c <x> or --conn-check <x>\t\t: Specify that <x> number of queries without response are to be used."
    print "-e or --tcp-check\t\t\t: Specify that a tcp handshake is to be used. Must be with a tcp connection."
    exit()

# A helper function for when a cmd arg is bad
def badArg(error):
    print error
    exit()

# A helper function to set the pid
def setPid(arg):
    global pid
    global checkPid
    try:
        pid = int(arg)
        checkPid = True
    except ValueError:
        badArg("Pid is not an integer.")

# This function parses argument list passed in
def parseArgs(argsRaw):
    # Declare all of the long / short cmd args we take
    longArgList = ['remoteIP=', 'port=', 'help', 'tcp', 'pid=', 'tcp-check', 'conn-check=', 'pname=', 'replay=', 'max-seeds=', 'fuzzed-data=']
    shortArgs = 'i:p:thd:ec:n:r:m:f:'
    # Parse out the arguments

    try:
        argList, leftover = getopt.getopt(argsRaw, shortArgs, longArgList)
    except getopt.GetoptError as error:
        badArg("Invalid arguments: " + str(error))

    global savedArgs
    global checkPid
    global pid
    global port
    global replaying

    # Save the arguments, so they can be stored in crash output file
    savedArgs = argsRaw
    for option, arg in argList:
        if option in ('-i', '--remoteIP'):
            global ip
            ip = arg
        elif option in ('-p', "--port"):
            try:
                port = int(arg)
            except ValueError:
                badArg("Port number is not an integer.")
        elif option in ('-t', '--tcp'):
            global udp
            udp = False
        elif option in ('-h' ,"--help"):
            helpMenu()
        elif option in ('-d', '--pid'):
            if replaying == False:
                setPid(arg)
            else:
                newPid = raw_input("What is the new pid? ")
                setPid(newPid)
        elif option in ('-e', '--tcp-check'):
            global checkTcp
            checkTcp = True
        elif option in ('-c', '--conn-check'):
            global checkConn
            global maxFailedRecvs
            failedRecvs = 0
            checkConn = True
            try:
                maxFailedRecvs = int(arg)
                checkConn = True
            except ValueError:
                badArg("Max failed recvs is not an integer.")
        elif option in ('-n', '--pname'):
            checkPid = True
            pid = int(getPid(arg))
        elif option in ('-r', '--replay'):
            replayCrash(arg)
        elif option in ('-m', '--max-seeds'):
            global maxseeds
            try:
                maxseeds = int(arg)
            except ValueError:
                    badArg("Max seeds argument not an integer.")
        elif option in ('-f', '--fuzzed-data'):
            global fuzzedData
            try:
                fuzzedData = int(arg)
                if fuzzedData < 0 or fuzzedData > 100:
                    badArg("Fuzzed data value must be between 0 - 100")
            except ValueError:
                badArg("Fuzzed data argument is not an integer.")
        else:
            print "Invalid arg found. Here's the help menu: "
            helpMenu()        

# Function which we use to send data
def serverSend(conn, packet):
    try:
        conn.send(packet)
    except socket.error as error:
        print "Could not send packet: " + str(error)
    except:
        print "Could not send packet"
    if checkConn == True:
        recvCheck(conn)

# A function which runs the pid/tcp checks if specified
def checkCrash():
    global checkPid
    global checkTcp
    if checkPid == True:
        pidCheck()
    if checkTcp == True:
        tcpCheck()

# The recv check, essentially looks for x times in a row output was expected but not seen
def recvCheck(conn):
    failed = 0
    global failedRecvs
    try:
        conn.recv(1)
    except socket.error:
        failed = 1
        global maxFailedRecvs
        if failedRecvs < maxFailedRecvs:
            failedRecvs += 1
        else:
            reportCrash()
    if failed == 0:
        failedRecvs = 0

# The tcp check, just sees if it can do the tcp handshake
def tcpCheck():
    global ip
    global port
    connCheck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connCheck.connect((ip, port))
    except socket.error as error:
        reportCrash()

# The function to get the pid of process name using pidof
def getPid(process):
    x = os.popen('pidof ' + process).read()
    try:
        y = int(x)
        return y
    except ValueError:
        badArg("Pid for the process name could not be found.")

# Check if a pid is alive
def pidCheck():
    try:
        os.kill(pid, 0)
    except OSError:
        reportCrash()

# This function is executed when there is a crash, and outputs replay file
def reportCrash():
    global replaying
    if replaying == False:
        print "Crash detected"
        outputFile = "outputFile.txt"
        x = 1
        while os.path.isfile(outputFile) == True:
            outputFile = "outputFile-" + str(x) + ".txt"
            x += 1
        outputFile = openWrite(outputFile)
        try:
            global seeds
            global savedArgs
            pickle.dump(seeds, outputFile)
            pickle.dump(savedArgs, outputFile)
            print "Crashed seeds are: " + str(len(seeds))
        except:
            badArg("Could not write replay file's data.")
    exit()

# The function which handles replaying crash files
def replayCrash(filename):
    replayFile = openRead(filename)
    try:
        seeds = pickle.load(replayFile)
        args = pickle.load(replayFile)
    except:
        badArg("Could not read replay file's data.")

    # Set the replaying variable, so we don't generate another crash file
    global replaying
    replaying = True

    parseArgs(args)
    scanRecordFile("records")

    conn = serverConnect()
    print "read seeds are: " + str(len(seeds))
    for i in xrange(len(seeds)):
        print "replaing seed number: " + str(i)
        random.seed(seeds[i])
        print "using seed: " + seeds[i]
        fuzzing(conn)
        time.sleep(.1)
    badArg("Finished replaying file.")

# This function handles generating questions for queries
def genQuestion(name, qtype, qclass):
    question = ""
    parts = name.split(".")
    quant = len(parts)
    for i in xrange(quant):
        question += chr(len(parts[i])) 
        question += parts[i]
    question += "\x00"
    qtype = twoByteChr(qtype)
    qclass = twoByteChr(qclass)    
    question = question + qtype + qclass
    return question

# A function to generate size ascii characters
def generateAsciiString(size):
    string = ""
    for i in xrange(size):
        string += chr(random.randint(0x20, 0x7e))
    return string

# A function to generate size amount of bytes
def generateString(size):
    string = ""
    for i in xrange(size):
        string += chr(random.randint(0x00, 0xff))
    return string

# Either generates size ascii characters or bytes
def generateData(size):
    if random.randint(0, 1) == 0:
        return generateAsciiString(random.randint(0, size))
    else:
        return generateString(random.randint(0, size))      

# This will insert data into other data, at a random spot
def insertData(data, insertData, size):
    index = random.randint(0, size)
    string = ''
    string = data[0:index] + insertData + data[index:]
    return string

# Generates a random combination of items from a list
def genRanCombo(dataList):
    choice = random.randint(0, 2)
    if choice == 0:
        returnData = ''
        for i in xrange(random.randint(0, len(dataList))):
            returnData += random.choice(dataList)
        return returnData
    elif choice == 1:
        # 1 out of 50 times, we return a massive list with respect to input
        returnData = ''
        for i in xrange(random.randint(0, len(dataList) * 100)):
            returnData += random.choice(dataList)
        return returnData
    else:  
        returnData = ''
        while True:
            returnData += random.choice(dataList)
            if random.randint(0, 1) == 0:
                return returnData

# This is the corrupter I use to corrupt data to look for bugs
def corrupter(data): 
    choice = random.randint(0, 10)
    global fmtStrings
    if choice == 0:
        return ''
    # Check for buffer overflows
    elif choice == 1:
        return generateData(random.randint(0, 100))        
    elif choice == 2:
        return generateData(random.randint(0, 10000))
    elif choice == 3:
        size = random.randint(0, 100)
        return insertData(generateData(size), data, size)        
    elif choice == 4:
        size = random.randint(0, 10000)
        return insertData(generateData(random.randint(0, 10000)), data, size)
    # Check for parsing errors  
    elif choice == 5:
        x = random.randint(2, 5)
        return data * x
    # Flip bits
    elif choice == 6:
        returnData = ''
        for i in xrange(len(data)):
            returnData += chr(~ord(data[i]) & 0xff)
        return returnData  
    elif choice == 7:
        returnData = ''
        returnData = genRanChrs(len(data))
        return returnData  
    # Check for format string bugs
    elif choice == 8:
        global fmtStrings
        fmtStrList = genRanCombo(fmtStrings)
        insertData(data, fmtStrList, len(data))
        return data
    # Insert delimiters, check for parsing errors
    elif choice == 9:
        global delimiters
        delimList = genRanCombo(delimiters)
        insertData(data, delimList, len(data))
        return data
    else:
        length = len(data)
        if length > 0:
            while True:
                i = random.randint(0, length - 1)
                data = data[:i] + genRanChrs(2) + data[i + 1:]
                if random.randint(0, 1) == 0:
                    return data
        else:
            return ''



# This handles generating fuzzed/corrupted questions
def genQuestionCorrupt(name, qtype, qclass, corruption):
    if corruption >= 40:
        corruptionChoice = random.randint(0, 5)
        question = ""
        parts = name.split(".")
        quant = len(parts)
        # Corrupt individual portions of the dns name
        if corruptionChoice == 4: 
            for i in xrange(quant):
                if random.randint(0, 1) == 0:
                    question += chr(len(parts[i])) 
                    question += parts[i]
                else:
                    question += corrupter(chr(len(parts[i]))) 
                    question += corrupter(parts[i])                   
        elif corruptionChoice == 5:
            # Corrupt a single portion of the dns name
            corruptIndex = random.randint(0, quant - 1)
            for i in xrange(quant):
                if i != corruptIndex:
                    question += chr(len(parts[i])) 
                    question += parts[i]
                else:
                    question += corrupter(chr(len(parts[i]))) 
                    question += corrupter(parts[i])                
        else:
            for i in xrange(quant):
                question += chr(len(parts[i])) 
                question += parts[i]
        question += "\x00"
        qtype = twoByteChr(qtype)
        qclass = twoByteChr(qclass)

        # Construct the rest of the question
        if corruptionChoice == 0:
            question = corrupter(question) + qtype + qclass            
        if corruptionChoice == 1:    
            question = question + corrupter(qtype) + qclass 
        if corruptionChoice == 2:
            question = question + qtype + corrupter(qclass)             
        if corruptionChoice == 3:  
            question = corrupter(question + qtype + qclass)
        else:
            question = question + qtype + qclass
        return question      
    else:
        return genQuestion(name, qtype, qclass)


# Send a server status request
def serverStatusRequest():
    if random.randint(0, 1) == 0 or fileRecordsZone == []:
        packet = makeQueryHeader(2, 0, 0, 0, 0, 0, 0)
        return packet
    else:
        # Send status request for particular zone
        packet = makeQueryHeader(2, 0, 0, 1, 0, 0, 0)
        x = random.choice(typeDict.values())
        i = random.randint(0, (fileRecordsCountDict["ZONE"] - 1))    
        packet += genQuestion(fileRecordsZone[i], 0, x)
        return packet

def serverStatusRequestCorrupt():
    if random.randint(0, 1) == 0 or fileRecordsZone == []:
        packet = makeQueryHeaderCorrupt(2, 0, 0, 0, 0, 0, 0, 49)
        return packet
    else:
        # Send status request for particular zone
        choice = random.randint(0, 2)
        if choice == 0 or choice == 1:
            packet = makeQueryHeaderCorrupt(2, 0, 0, 0, 0, 0, 0, 49)            
        else:
            packet = makeQueryHeader(2, 0, 0, 1, 0, 0, 0)
        x = random.choice(typeDict.values())
        i = random.randint(0, (fileRecordsCountDict["ZONE"] - 1))
        if choice == 0 or choice == 2:
            packet += genQuestion(fileRecordsZone[i], 0, x)
        else:       
            packet += genQuestionCorrupt(fileRecordsZone[i], 0, x, 50)
        return packet

# Send a server Iquery request
def serverIqueryRequest():
    packet = makeQueryHeader(1, 0, 0, 0, 0, 0, 0)
    return packet

# Send a fuzzed server Iquery request
def serverIqueryRequestCorrupt():
    packet = makeQueryHeaderCorrupt(1, 0, 0, 0, 0, 0, 0, 49)
    return packet

def genRanChrs(i):
    string = ''
    for i in xrange(i):
        string += chr(random.randint(0, 0xff))      
    return string

def genCookieCorrupt():
    if random.randint(0, 9) == 1:
        corruption = random.randint(0, 10)
        record = genCookie()
        cookie = record[-8:]
        rr = record[:-8]

        if corruption > 5:
            rr = corrupter(rr) 
        elif corruption > 10:
            cookie = corrupter(cookie)
        else:
            rr = corrupter(rr)
            cookie = corrupter(cookie)             
        record = rr + cookie
        return record
    else:
        return genCookie()

def genCookie():
    '''
    checkout these rfc for more info
    https://tools.ietf.org/html/rfc7873#page-8
    https://tools.ietf.org/html/rfc6891

    The cookie will be the RDATA segment of 
    an opt resource record
    Zone:   0x00
    Type:   0x00 0x41
    Class:  two random bytes
    TTL:    0x00 0x00 0x00 0x00
    RDLEN:  0x00 0x0c
    RDATA = cookie

    cookie:
    option code: 0x00 0x0a
    option length: 0x00 0x08
    client cookie: eight random bytes
    '''
    rr = "\x00"
    rr += "\x00\x29"
    rr += genRanChrs(2)
    rr += "\x00\x00\x00\x00"
    rr += "\x00\x0c" 

    cookie = "\x00\x0a"
    cookie += "\x00\x08"
    cookie += genRanChrs(8)

    rr += cookie
    return rr

def prepTcp():
    global udp
    udpStored = udp
    udp = False
    tcpConnect = serverConnect()
    udp = udpStored
    return tcpConnect

def tcpSend(question, tcpConnect):
    question = twoByteChr(len(question)) + question
    serverSend(tcpConnect, question)
    tcpConnect.recv(1000)

def sendAxfrCorrupt():
    if fileRecordsZone != []:
        corruption = random.randint(0, 100)

        # Make the query header
        question = makeQueryHeaderCorrupt(0, 0, 0, 1, 0, 0, 1, corruption)

        # Make the query question
        i = random.randint(0, (fileRecordsCountDict["ZONE"] - 1))
        question += genQuestionCorrupt(fileRecordsZone[i], typeDict["AXFR"], fileRecordsZone[i + 1], corruption)
        question += genCookieCorrupt()

        # Make the tcp connection
        tcpConnect = prepTcp()

        # Prepend the len of the query to the query
        tcpSend(question, tcpConnect)

def sendAxfr():
    if fileRecordsZone != []:
        # Make the query header
        question = makeQueryHeader(0, 0, 0, 1, 0, 0, 1)

        # Make the query question
        i = random.randint(0, (fileRecordsCountDict["ZONE"] - 1))
        question += genQuestion(fileRecordsZone[i], typeDict["AXFR"], fileRecordsZone[i + 1])
        question += genCookie()

        # Make the tcp connection
        tcpConnect = prepTcp()

        # Prepend the len of the query to the query
        tcpSend(question, tcpConnect)

def sendAnyCorrupt():
    if fileRecordsZone != []:
        corruption = random.randint(0, 100)

        question = makeQueryHeaderCorrupt(0, 0, 0, 1, 0, 0, 1, corruption)

        i = random.randint(0, (fileRecordsCountDict["ZONE"] - 1))
        question += genQuestionCorrupt(fileRecordsZone[i], 255, fileRecordsZone[i + 1], corruption)

        question += genCookieCorrupt()

        tcpConnect = prepTcp()

        tcpSend(question, tcpConnect)

def sendAny():
    if fileRecordsZone != []:
        # Make the query header
        question = makeQueryHeader(0, 0, 0, 1, 0, 0, 1)

        # Make the query question
        i = random.randint(0, (fileRecordsCountDict["ZONE"] - 1))
        question += genQuestion(fileRecordsZone[i], 255, fileRecordsZone[i + 1])
        question += genCookie()

        # Make the tcp connection
        tcpConnect = prepTcp()

        # Prepend the len of the query to the query
        tcpSend(question, tcpConnect)

# Helper function to open a file for reading, with exception handling
def openRead(filename):
    try:
        file = open(filename, "r")
    except IOError as error:
        badArg("Could not open up file: " + str(error))
    except:
        badArg("Could not open up file")
    return file

# Helper function to open a file for writing, with exception handling
def openWrite(filename):
    try:
        file = open(filename, "wb")
    except IOError as error:
        badArg("Could not open up file: " + str(error))
    except:
        badArg("Could not open up file")
    return file

def scanLineExc(filehandle):
    try:
        line = filehandle.readline()
    except:
        badArg("Could not read line from file.")
    return line

# Functiont that scans in dns records from file
def scanRecordFile(filename):
    recordFile = openRead(filename)
    line = scanLineExc(recordFile)
    recordType = ''
    global fileRecordsTypeCount
    global fileRecordsCount
    fileRecordsCount = 0
    while line:
        try:
            lineSplit = line.split(",")
            recordType = lineSplit[0]

            # Deal with new record types
            if recordType not in fileRecordsType:
                fileRecordsTypeCount += 1
                fileRecordsType.append(recordType)
                fileRecordsCountDict[recordType] = 1

            # Deal with record types previously established
            else:            
                fileRecordsCountDict[recordType] += 1
            fileRecordsDict[recordType].append(lineSplit[1])
            lineSplit[2] = lineSplit[2].strip("\n")
            if (lineSplit[2].isdigit() == True):           
                fileRecordsDict[recordType].append(lineSplit[2])
            else:
                fileRecordsDict[recordType].append(classDict[lineSplit[2]])
            fileRecordsCount += 1
            line = scanLineExc(recordFile)
        except:
            badArg("Could not parse input records file.")

# Function to make dns query headers
def makeQueryHeader(op, tc, rd, QD, AN, NS, AR):
    ID = chr(random.randint(0, 0xff)) + chr(random.randint(0, 0xff))
    '''
    flags
    QR -> 0
    OPCODE -> variable
    AA -> 0
    TC -> variable
    RD -> variable
    RA -> 0
    z -> 0
    rcode -> 0
    '''
    Flags = op << 1
    if tc != 0:
        Flags = Flags | 0x200
    if rd != 0:
        Flags = Flags | 0x100
    header = ID + twoByteChr(Flags) + twoByteChr(QD) + twoByteChr(AN) + twoByteChr(NS) + twoByteChr(AR)
    return header

# A function to make a corrupted/fuzzed dns query headers
def makeQueryHeaderCorrupt(op, tc, rd, QD, AN, NS, AR, corruption):
    if corruption < 60:
        ID = genRanChrs(2)
        corruptionChoice = random.randint(0, 7)
        if corruptionChoice == 7:
            op = random.randint(0, 0xf)       
        Flags = op << 1
        if tc != 0:
            Flags = Flags | 0x200
        if rd != 0:
            Flags = Flags | 0x100
        # Decide what part of the dns query header we corrupt
        corruptionChoice = random.randint(0, 8)
        if corruptionChoice == 0:
            header = corrupter(ID) + twoByteChr(Flags) + twoByteChr(QD) + twoByteChr(AN) + twoByteChr(NS) + twoByteChr(AR)
        elif corruptionChoice == 1:
            header = ID + corrupter(twoByteChr(Flags)) + twoByteChr(QD) + twoByteChr(AN) + twoByteChr(NS) + twoByteChr(AR)
        elif corruptionChoice == 2:
            header = ID + twoByteChr(Flags) + corrupter(twoByteChr(QD)) + twoByteChr(AN) + twoByteChr(NS) + twoByteChr(AR)
        elif corruptionChoice == 3:
            header = ID + twoByteChr(Flags) + twoByteChr(QD) + corrupter(twoByteChr(AN)) + twoByteChr(NS) + twoByteChr(AR)
        elif corruptionChoice == 4:
            header = ID + twoByteChr(Flags) + twoByteChr(QD) + twoByteChr(AN) + corrupter(twoByteChr(NS)) + twoByteChr(AR)
        elif corruptionChoice == 5:
            header = ID + twoByteChr(Flags) + twoByteChr(QD) + twoByteChr(AN) + twoByteChr(NS) + corrupter(twoByteChr(AR))
        elif corruptionChoice == 6:          
            header = corrupter(ID + twoByteChr(Flags) + twoByteChr(QD) + twoByteChr(AN) + twoByteChr(NS) + twoByteChr(AR))
        elif corruptionChoice == 7:
            header = ID + twoByteChr(Flags) + twoByteChr(QD) + twoByteChr(AN) + twoByteChr(NS) + twoByteChr(AR) 
        else:
            header = ID + genRanChrs(2) + twoByteChr(QD) + twoByteChr(AN) + twoByteChr(NS) + twoByteChr(AR)          
        return header
    else:
        return makeQueryHeader(op, tc, rd, QD, AN, NS, AR)

# A helper function which packs a two byte int
def twoByteChr(inp):
    value = ''
    if (inp & 0xff00) != 0:
        value += chr((inp >> 8))
        value += chr((inp & 0xff))
    else:
        value  = "\x00" + chr(inp)
    return value

# A function which just crafts the suffix for the dns query
def makeQuerySuffix(qtype, qclass):
    qtype = twoByteChr(qtype)
    qclass = twoByteChr(qclass)
    suffix = qtype + qclass
    return suffix

# Function responsible for generating / storing seeds
def rngSeed():
    global seeds
    seed = os.urandom(20)
    random.seed(seed)
    if len(seeds) > (maxseeds - 1):
        seeds.pop(0)
    seeds.append(seed)

# A function to insert data into other data at random spot with unknown length
def insert(data, insertData):
    length = len(data)
    if length == 0:
        return insertData
    index = random.randint(0, (length) - 1)
    data = data[:index] + insertData + data[index:]
    return data

# The function which handles the setup, and then loops fuzzing
def setup():
    print "Initializing fuzzer"
    parseArgs(sys.argv[1:])
    conn = serverConnect()
    scanRecordFile("records")
    print "Beginning fuzzing"
    while True:
        rngSeed()        
        fuzzing(conn)
        time.sleep(.1)

def fuzzing(conn):
    sendAny()
    global reverseRecords
    checkCrash()
    global fuzzedData
    x = random.randint(0, 100)
    if x >= fuzzedData:
        print "Sending Non-Corrupted Data:"
        # Packet is not being fuzzed
        y = random.randint(0, 21)        
        if y < 18:
            cookie = random.randint(0, 1)
            # Generate dns query with single question                
            i = random.randint(0, (fileRecordsTypeCount - 1))
            recordType = fileRecordsType[i]
            if recordType == "ZONE":
                return
            i = random.randint(0, (fileRecordsCountDict[recordType] - 1))
            recordName = fileRecordsDict[recordType][i * 2]
            recordClass = fileRecordsDict[recordType][(i * 2) + 1]
            op = 0
            if recordType in reverseRecords:
                op = 1
            if cookie == 0:
                packet = makeQueryHeader(op, 0, random.randint(0, 1), 1, 0, 0, 0)
                packet += genQuestion(recordName, typeDict[recordType], recordClass)
            else:
                packet = makeQueryHeader(op, 0, random.randint(0, 1), 1, 0, 0, 1)
                packet += genQuestion(recordName, typeDict[recordType], recordClass)
                packet += genCookie()             
        elif y == 18:
            sendAxfr()
            return
        elif y == 19:
            sendAny()
            return
        elif y == 20:
            packet = serverStatusRequest()
        else:
            # Generate dns query with multiple questions  
            numRecords = random.randint(1, fileRecordsCount)
            op = random.randint(0, 1)
            if op == 0:
                packet = makeQueryHeader(0, 0, random.randint(0, 1), numRecords, 0, 0, 0)
            else:
                packet = makeQueryHeader(0, 0, random.randint(0, 1), numRecords, 0, 0, 1)                
            for i in xrange(numRecords):
                i = random.randint(0, (fileRecordsTypeCount - 1))
                recordType = fileRecordsType[i]
                if recordType == "ZONE":
                    if random.randint(0, 1) == 0:
                        sendAny()
                        return
                    else:
                        sendAxfr()
                        return
                i = random.randint(0, (fileRecordsCountDict[recordType] - 1))
                recordName = fileRecordsDict[recordType][i * 2]
                recordClass = fileRecordsDict[recordType][(i * 2) + 1]
                packet += genQuestion(recordName, typeDict[recordType], recordClass)
            if op == 1:
                packet += genCookie()                    

    else:
        print "Sending Corrupted Data:"
        # Packet is being fuzzed
        y = random.randint(0, 21)        
        if y < 18: 
            # Generate fuzzed dns query with single question     
            corruption = random.randint(0, 100)
            i = random.randint(0, (fileRecordsTypeCount - 1))
            recordType = fileRecordsType[i]
            if recordType == "ZONE":
                if random.randint(0, 1) == 0:
                    sendAnyCorrupt()
                    return
                else:
                    sendAxfrCorrupt()
                    return
            i = random.randint(0, (fileRecordsCountDict[recordType] - 1))
            recordName = fileRecordsDict[recordType][i * 2]
            recordClass = fileRecordsDict[recordType][(i * 2) + 1]
            op = 0
            if recordType in reverseRecords:
                op = 1
            cookie = random.randint(0, 1)
            if cookie == 0:
                packet = makeQueryHeaderCorrupt(op, 0, 1, 1, 0, 0, 0, corruption)
                packet += genQuestionCorrupt(recordName, typeDict[recordType], recordClass, corruption)
            else:
                packet = makeQueryHeaderCorrupt(op, 0, 1, 1, 0, 0, 1, corruption)
                packet += genQuestionCorrupt(recordName, typeDict[recordType], recordClass, corruption)
                packet += genCookieCorrupt()
        elif y == 18:
            packet = serverStatusRequestCorrupt()
        elif y == 19:
            sendAnyCorrupt()
            return
        elif y == 20:
            sendAxfrCorrupt()
            return
        else:
            # Generate fuzzed dns query with multiple questions  
            corruptionChoice = random.randint(0, 2)
            numRecords = random.randint(1, fileRecordsCount)
            op = random.randint(0, 1)
            if corruptionChoice == 0 or corruptionChoice == 1:
                packet = makeQueryHeaderCorrupt(1, 1, 1, numRecords, 0, 0, op, 50)
            else:
                packet = makeQueryHeader(1, 1, 1, numRecords, 0, 0, op)
            for i in xrange(numRecords):
                i = random.randint(0, (fileRecordsTypeCount - 1))
                recordType = fileRecordsType[i]
                if recordType == "ZONE":
                    continue
                i = random.randint(0, (fileRecordsCountDict[recordType] - 1))
                recordName = fileRecordsDict[recordType][i * 2]
                recordClass = fileRecordsDict[recordType][(i * 2) + 1]
                if (corruptionChoice == 0 or corruptionChoice == 2) and random.randint(0, 1) == 1:
                    packet += genQuestionCorrupt(recordName, typeDict[recordType], recordClass, 50) 
                else:
                    packet += genQuestion(recordName, typeDict[recordType], recordClass)
            if op == 1:
                packet += genCookie()

    # Send the query
    print "Length of Packet: " + str(len(packet))           
    serverSend(conn, packet)

if __name__ == "__main__":
    setup()
