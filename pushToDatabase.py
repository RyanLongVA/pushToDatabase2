from __future__ import division

# As of 4-3-2018 I'm removing certain packages to clean up code... they're included in the new modules to save space: MySQLdb

# Note: There are some statements that I ignored and kept in code // now they have to be included in that module

import os, sys, pdb, subprocess, re, random, string, argparse, smtplib, time, socket, dns.resolver, json
#Decorator for timing up functions
from lib.modules import timeout
#MySQL functions and database errors
from lib.modules.mysqlfunc import *
#All the variables for paths
from lib.modules.variables import *


###Defining paths ++ which I've typical not included the ending blackslash
scriptFolder = sys.path[0]
tempFolder = sys.path[0]+'/tempFiles'   
changesTXTFolder = sys.path[0]+'/lib/data'

###changes.txt is going to be in sys.path[0]+'/lib/data'
###Brutesub start script (brutesubs.sh) needs to be manual changed

###is the end slash necessary? I'd prefer if it wasn't and catered to the same style as scriptPath

#sys.argv[1] == databaseName
#sys.argv[2] == table

### MySQL functions

# Grab the value from the changes.txt
def findInOut(a, b):
    ###Returns one of the values with a ^ symbol. Picked/supplied by the b parameter (still needs to end in '^' e.g. 'Domain^')
    for item in a.split(' ; ')[2].split(' , '):
        if item.startswith(b):
            return item.split('^')[1]

def domainFound(conn): 
    subprocess.call('python '+scriptFolder+'/pushToDatabase.py -cc', shell=True)
    cur = conn.cursor()
    domainsList = []
    cfile = open(changesTXTFolder+'/changes.txt', 'r')
    for a in cfile.readlines():
        domain = findInOut(a, 'Domain^')
        program = a.split(' ; ')[1].split('_')[0]
        domainsList.append(program + ' , '+domain)
    cfile.close()
    if intrusiveStatus:
        for a in domainsList:
            a = a.split(' , ')
            program = a[0]
            domain = a[1]
            nmapScan = nmapOnDomain(domain, 'normal') ##So far I'm just going to do a normal scan until I can dynamically fluctuate the nmap timeout
            domainTitle = grabWebTitle(domain)
            dnsData = grabWebDNS(domain)
            statementKeys = []
            statementValues = []
            # textMessageFormat = []
            statementKeys.append('`Domain`')
            statementValues.append('\"'+domain+'\"')
            # textMessageFormat.append('\n'+'|Domain| '+domain)
            if domainTitle:
                statementKeys.append('`Title`')
                statementValues.append('\"'+domainTitle+'\"')
                # textMessageFormat.append('|Title|'+domainTitle)
            if nmapScan:
                statementKeys.append('`Ports`')
                statementValues.append('\"'+nmapScan+'\"')
                # textMessageFormat.append('|Ports|'+nmapScan)
            if dnsData:
                statementKeys.append('`DNS`')
                statementValues.append('\"'+dnsData+'\"')
                # textMessageFormat.append('|DNS|'+dnsData)
            fullKeys = ', '.join(statementKeys)
            fullValues = ', '.join(statementValues)
            # tempTextMessage = '\n'.join(textMessageFormat)

            #Send text notification
            # msg = """From: %s
            # To: %s
            # Subject:
            # %s"""%(textEmail, textToAddress, tempTextMessage)
            # s = smtplib.SMTP('smtp.gmail.com', 587)
            # s.starttls()
            # s.login(textEmail, textEmailPassword)
            # s.sendmail(textEmail, textToAddress, msg)
            # s.quit()
            #Insert into table
            try:
                statem = "INSERT INTO "+program+"_liveWebApp(%s) VALUES (%s)"%(fullKeys, fullValues)
                sqlExeCommit(conn, statem)
            except:
                pass
    cfile = open(changesTXTFolder+'/changes.txt', 'w')
    cfile.write('')
    cfile.close


    ###Need to change text notification so the data that get's sent is after nmap/resolving/title grab, etc
def removeByKey(providedKey):
    data = []
    cfile = open(changesTXTFolder+'/changes.txt', 'r')
    for a in cfile.readlines():
        if providedKey in a.split(' : ')[-1]:
            next
        else:
            data.append(a)
    with open(changesTXTFolder+'/changes.txt', 'w') as file:
        file.writelines(data)

def removeByDomain(domain):
    cfile = open(changesTXTFolder+'/changes.txt', 'r')
    keep = []
    for a in cfile.readlines():
        #Matching to the exact string 
        test = findInOut(a, 'Domain^')
        if findInOut(a, 'Domain^') == domain:
            next
        else: 
            keep.append(a)
    with open(changesTXTFolder+'/changes.txt', 'w') as file:
        file.writelines(keep)

def textNotification(gmail, password, toAddress):
        data = []
        s = smtplib.SMTP('smtp.gmail.com',587)
        s.starttls()
        s.login(gmail,password)
        cfile = open(changesTXTFolder+'/changes.txt', 'r')
        for a in cfile.readlines():
            if 'True' in a.split(' ; ')[3]:
                data.append(a)
                next
            else:
                domain = findInOut(a, 'Domain^')+'\n'
                program = a.split(' ; ')[1][:-11]+'\n'
                researchOnly = findInOut(a, 'Research Only^')+'\n'
                key = a.split(' ; ')[-1].rstrip()
                message = '\n|Domain| '+domain+'|Program| '+program+'|ResearchOnly| '+researchOnly+'|Key| '+key
                msg = """From: %s
                To: %s
                Subject: 
                %s"""%(gmail, toAddress,message)
                s.sendmail(gmail,toAddress,msg)
                cdata = a.split(' ; '); cdata[3] = 'True'; cdata = ' ; '.join(cdata)
                data.append(cdata)
        s.quit()
            # do some replacing thing the file
        with open(changesTXTFolder+'/changes.txt', 'w') as file:
            file.writelines(data)

# Sending changes.txt to the database based on 
def sendToDatabase(conn):
        cur = conn.cursor()
        cfile = open(changesTXTFolder+'/changes.txt', 'r')
        for a in cfile.readlines():
            a = a.rstrip()
            table = a.split(' ; ')[1]
            column = []
            values = []
            for b in a.split(' ; ')[2].split(' , '):
                column.append('`'+b.split('^')[0]+'`'   )
                values.append('\''+b.split('^')[1]+'\'')
            fcolumn = ', '.join(column)
            fvalues = ', '.join(values)
            statem = 'INSERT INTO '+table+'('+fcolumn+') VALUES ('+fvalues+')'
            try:
                sqlExe(cur, statem)
            except Exception as e:
                pass
        sqlCommit(conn)
        # Clearing changes after sending values
        cfile = open(changesTXTFolder+'/changes.txt', 'w')
        cfile.write('')
        cfile.close

def removeBasedOnDomain(pattern, program):
    cfile = open(changesTXTFolder+'/changes.txt', 'r')
    keep = []
    for a in cfile.readlines():
            if 'Domain^'+pattern in a:
                next
            else: 
                keep.append(a)
    with open(changesTXTFolder+'/changes.txt', 'w') as file:
        file.writelines(keep)

def removeBasedOnPattern(pattern, program):
    cfile = open(changesTXTFolder+'/changes.txt', 'r')
    keep = []
    for a in cfile.readlines():
        if program in a.split(' ; ')[1]:
            if 'Domain^'+pattern in a:
                next
            else: 
                keep.append(a)
    with open(changesTXTFolder+'/changes.txt', 'w') as file:
        file.writelines(keep)

@timeout.timeout(1000)
def nmapOnDomain(domain, ports):
    #nmap -sS -A example.com --> faster tcp with OS Grepping
    #nmap -sU example.com --> UDP ports
    FNULL = open(os.devnull, 'w')
    portDict = {"full" : "-p-", "fast" : "-F", "normal": "", "simple" : "-p80,8080,8880,2052,2082,2086,2095,443,2053,2083,2087,2096,8443"}
    #portDict['full']
    inputFile = tempFolder+'/nmap.out'
    print 'Starting Nmap on: \t',domain
    ##Try and Except to find where nmap is breaking out... need the function to really return {}
    try:
        startOutput = subprocess.call('nmap -sS -sV -oG %s %s %s'%(inputFile, portDict[ports], domain), shell=True, stdout=FNULL)
        nmapOut = subprocess.check_output(nmapFormatFolder+'/scanreport.sh -f %s'%(inputFile), shell=True)
        ports = []
        portsJSON = {}
        for index, a in enumerate(nmapOut.split('\n')):
            #If the line is empty continue
            if a == '':
                continue
            # Skip the first line "Host: {IP} {Resolved domain}"
            if index != 0:
                tempArray = filter(None, a.split('\t\t'))
                tempArray2 = []
                for b in tempArray:
                    if b == '\t':
                        next
                    else:
                        tempArray2.append(b)
                portData = tempArray2[0].split()
                portStatus = portData[1]
                #Check the status of the port
                if portStatus != 'open':
                    continue
                portNumber = portData[0]
                #Check if port number is int type 
                if not isinstance(int(portNumber), int):
                    continue
                #Port socket type and Fingerprint
                portType = portData[2]
                portFingerprint = ' - '.join(tempArray[1:]).strip('\t')
                #Moving the information to the JSON array
                portsJSON[portNumber] = [portType, portFingerprint]
        return portsJSON
    except Exception,e:
        print 'Line 246:'
        print e
        pdb.set_trace()

            

            # portFingerprint = tempArray2[1]
            # pdb.set_trace()
            # c = ' :: '.join(tempArray).replace('\t', ' ')
            # if c == '': 
            #     print c
            #     next
            # else: 
            #     ports.append(c)
            # pdb.set_trace()
    # return ' , '.join(ports)
    # Returns open ports

def grabWebTitle(domain):    
    command = "curl %s -sL -m 5 | tac | tac | awk -vRS=\"</title>\" \'/<title>/{gsub(/.*<title>|"%(domain)+r'\n'+"+/,\"\");print;exit}\'"
    return subprocess.check_output(command, shell=True)

def grabWebDNS(domain):
    try: 
        cdns = []
        b = socket.gethostbyname_ex(domain)
        if (b[0] == domain):
            ###Should be the same... so pretty much a 'A Record'
            cdns.append(b[0])
            d = []
            for c in b[2]:
                d.append(c)
            cdns.append(' , '.join(d))
        else: 
            for c in b[1]:
                cdns.append(c)
            d = []
            cdns.append(b[0])
            for c in b[2]:
                d.append(c)
            cdns.append(' , '.join(d))
        ##Add to the beginning... the domain
        cdns.insert(0, domain)
        data = ' : '.join(cdns)
        return data 
    except Exception,e:
        if e[0] == -2:
            print 'Failed: '+domain
        else: 
            print e
            # pdb.set_trace()
               

def cleanTempFolder():
    try:
        subprocess.call('rm -rf '+tempFolder+'/* &> /dev/null', shell=True)
    except Exception, e:
        print e
        exit()




def grabDomainsAndPortsAndDNS(conn, program):
    cur = conn.cursor()
    cur.execute('SELECT DISTINCT Domain, Ports, DNS FROM %s_liveWebApp'%(program))
    domainsSQL = cur.fetchall()
    domainsList = []
    for a in domainsSQL:
        domain = a[0]
        ports = a[1]
        DNS = a[2]
        if ports == None:
            ports = ''
        if DNS == None:
            DNS = ''
        data = str(domain + '\n' + ports + '\n' + DNS + '\n\n')
        domainsList.append(data)
    return domainsList

def select_webAppFromPrograms(conn, scope, cProgram):
    cur = conn.cursor()
    if scope:
        statem = "SELECT `In Scope Domains` FROM programs WHERE Name=\'%s\'" % cProgram
        cur.execute(statem)
        a = cur.fetchone()[0].split(', ')
        return a 
    else:
        statem = "SELECT `Out of Scope Domains` FROM programs WHERE Name=\'%s\'" % cProgram
        cur.execute(statem)
        a = cur.fetchone()[0].split(', ')
        return a

def callVirtualHost(domain, dnsLine):
    ipString = dnsLine.split(':')
    ipList = []
    for a in ipString[-1].split(' , '):
        a = a.strip()
        ipList.append(a)
    for a in ipList:
        print a
    os.system("gnome-terminal --working-directory=%s"%(virtualHostDiscoveryFolder))
    print 'Basic usage: ruby scan.rb --ip={IP ADDRESS} --host={TLD} (--port={port} >> When it\' not 80)'

def callWhatWeb(domain, port):
    try:
        if port == '80':
            whatwebOut = subprocess.check_output(whatWebPath + '/whatweb --color=NEVER -v %s'%('http://'+domain), shell=True)
        elif port == '443':
            whatwebOut = subprocess.check_output(whatWebPath + '/whatweb --color=NEVER -v %s'%('http://'+domain), shell=True)
        else:
            return None
        foundStatus = False
        statuscode = ''
        foundSummary = False
        summary = ''
        foundHeaderBegin = False
        foundHeaders = []
        foundHeaderEnd = False
        for line in whatwebOut.split('\n'):
            #Need to go through line by line and see why the .startswith() are turning false
            if not foundStatus:
                if line.startswith('Status'):
                    statuscode = line.split(' : ')[1].replace("\"", "").replace("\'", "")
                    foundStatus = True
                    continue
                else: 
                    continue
            if not foundSummary:
                if line.startswith('Summary'):
                    summary = line.split(' : ')[1].replace("'", "").replace('\"', '')
                    foundSummary = True
                    continue
                else:
                    continue
            if not foundHeaderBegin:
                if line.startswith('HTTP Headers:'):
                    foundHeaderBegin = True
                    continue
                else:
                    continue
            if line == '\t':
                foundHeaderEnd = True
            if not foundHeaderEnd:
                line2 = line.replace("\"", '').replace("'", "")
                foundHeaders.append(line2)
        foundHeaders = filter(None, foundHeaders)
        foundHeaders2 = []
        for cheader in foundHeaders:
            foundHeaders2.append(cheader.strip())
        foundHeaders = filter(None, foundHeaders2)

        fullOutput = [statuscode, summary, foundHeaders]
        # pdb.set_trace()
        return fullOutput
        #Both timeouts and non-http ports will error out

        #Just needs to return the formatted output ["StatusCode", "Summary", "Headers"]
    except Exception,e:
        print e
        if 'bad URI' in str(e):
            pdb.set_trace()
        return None
    ##Should return None or ['statuscode', 'summary', 'headers']


@timeout.timeout(20000)
def callBrutesubs(a):
    try:
        ###I've changed the flow and now it reads the final results from the brutesubs folder
        ###and then deletes it

        # subprocess.call('cd '+brutesubsFolder+' && docker-compose down', shell=True)
        #^^^ Stops the error, but also causes duplicates? Is it because of something close to a race condidtion?
        subprocess.call("rm -rd "+brutesubsFolder+'/myoutdir/temp_out',shell=True)
        subprocess.call("cd "+brutesubsFolder+" && sh brutesubs.sh "+a+" temp_out", shell=True)
        ###Getting weird results because of rare system setups. One automatically CNAMES with any '-' in the domain to a '.'
        ###Maybe I'll need a easier way to add to the out of scope column on the programs table
        b = subprocess.check_output('cat '+brutesubsFolder+'/myoutdir/temp_out/finalresult.txt', shell=True)
        ##See if there's some way to redirect the output to tempFiles
        b = filter(None, b.split('\n'))
        return b
    except Exception, e:
        print e
        exit()
    ###Needs to read the output of the temp_out directory and then delete it 

def returningStatuscode(prompt, domainListLength):
    a = []
    if prompt == 'next' or prompt.rstrip() == 'n':
        a.append(0)
        a.append(0)
    elif prompt.startswith('nc '):
        try:
            ### The line below is so the status code gets appended only after the port is verified as a number
            port = int(prompt[3:])
            a.append(1)
            a.append(int(prompt[3:]))
        except Exception,e:
            a.append(-1)
            a.append(prompt)
            print e
            pass
    elif prompt == 'info':
        a.append(2)
        a.append(2)
    elif prompt == 'checkInt':
        a.append(3)
        a.append(3)
    elif prompt.startswith('go '):
        try: 
            ### Same concept as for startswith('nc ')
            value = int(prompt[3:])
            if value > domainListLength-1:
                raise ValueError('[-] The Value(%s) was bigger than the domain list(%s)'%(value, domainListLength-1))
            a.append(4)
            a.append(int(prompt[3:]))
        except Exception,e: 
            a.append(-1)
            a.append(prompt)
            print e 
            pass
    elif prompt == 'goohak':
        a.append(5)
        a.append(5)
    elif prompt == 'virtualHost':
        a.append(6)
        a.append(6)
    else: 
        a.append(-1)
        a.append(prompt)
    return a

def checkLiveWebApp(conn, tableName):
    cur = conn.cursor()
    cur.execute("SHOW TABLES;")
    a = re.search(tableName, str(cur.fetchall()))
    if a:
        return True
    else:
        try:
            statem = "CREATE TABLE "+tableName+"(IP VARCHAR(125), Domain VARCHAR(125), `Research Only` TEXT, DNS TEXT, Endpoints TEXT, NS TEXT, Ports TEXT, BuiltWith TEXT, `Content-Security-Policy` TEXT, `X-Frame-Options` TEXT, `X-Xss-Protection` TEXT, `X-Content-Type-Options` TEXT, `Title` TEXT, PRIMARY KEY (IP))"
            cur.execute(statem)
            cur.execute("SELECT `Tables` FROM programs WHERE `Name`=\'"+tableName.split('_')[0]+"\'")
            startName = cur.fetchone()[0]
            cur.execute("UPDATE `programs` SET `Tables` = \'"+startname+' , '+tableName+"\' WHERE `Name` LIKE \'"+sys.argv[1]+'\'')
            ####### Table tab isn't updating 
            conn.commit()
        except Exception,e:
            print e
            pdb.set_trace()
            pass
    # Seems tables are automatically saved i.e. don't need to be .commit()'d 

def callGobuster(domain, wordlistPath):
    try:
        test = "gobuster -fw -m dns -u "+domain+" -t 100 -w "+wordlistPath+" | sed -n -e 's/^Found: //p' > "+tempFolder+'/gobuster.temp'
        subprocess.call(test, shell=True)
        # Because of some weird CNAME results
        #if (a == 'algolia.net'):
            #subprocess.call("grep -v '-' ~/arsenal/tempFiles/gobuster.temp > ~/arsenal/tempFiles/gobuster.temp2", shell=True)
            #subprocess.call("cp ~/arsenal/tempFiles/gobuster.temp2 ~/arsenal/tempFiles/gobuster.temp")
        # Code for program specific code e.g. Algolia.net needs to have all '-' s stripped b/c they results in random CNAMES
        b = subprocess.check_output('cat '+tempFolder+'/gobuster.temp', shell=True)
        c = filter(None, b.split('\n'))
        #check what the out of c is... should be a array of new domains
        return c
    except Exception, e:
        print 'Something went wrong with Gobuster'
        pdb.set_trace()
        print e

def mainGobuster(program, filename, conn):
    inScope = select_webAppFromPrograms(conn, True, program)
    outScope = select_webAppFromPrograms(conn, False, program)
    checkLiveWebApp(conn, program+'_liveWebApp')
    for a in inScope:
        cleanTempFolder()
        if (a[:2] == '*.'):
            a = a[2:]
            b = callGobuster(a, filename)
            checkLiveWebApp_Domains(conn, program+'_liveWebApp', b, outScope)
        else:
            try: 
                cur = conn.cursor()
                statem = "INSERT INTO "+program+"_liveWebApp(`Domain`, `Research Only`) VALUES ('"+a+"','False')"''
                cur.execute(statem)
            except Exception, e:
                if e[0] == 1062:
                    pass
                else:
                    print e
                    pdb.set_trace()

def returnChangesDomains():
    cfile = open(changesTXTFolder+'/changes.txt', 'r') 
    content = cfile.read()
    domains = []
    if len(content) == 0:
        return domains  
    for line in filter(None, content.split('\n')):
        aline = line.split(' ; ')[2].split(' , ')
        for cdata in aline:
            cdata = cdata.split('^')
            if cdata[0] == 'Domain':
                domains.append(cdata[1])
    return domains

def checkLiveWebApp_Domains(conn, tableName, domainArray, outScope):
    ## Revamp // Output is successfully filtered of outScope
    try:
        domainArray = filter(None, domainArray)
    except:
        pass
    if domainArray == None:
        a = []
    else:
        a = domainArray
    changesDomains = returnChangesDomains()
    
    for b in outScope:
        #Check outScope value

        ###cleaning up output and removing things that are out of scope
        ###used to be a boolean, but it was changed because I do not care for repetitive Code
        if (b[:2] == '*.'):
            b = b[2:]
            for integer, c in reversed(list(enumerate(a))):
                # pdb.set_trace() 
                if c.find(c) != -1:
                    a.pop(integer)
        else:
            for integer, c in reversed(list(enumerate(a))):
                if c == b:
                    a.pop(integer)

    cfile = open(changesTXTFolder+'/changes.txt', 'a')
    for b in a:
        cur = conn.cursor()
        statem = "SELECT * FROM "+tableName+" WHERE Domain=\'"+b+"\'"
        cur.execute(statem)
        if cur.fetchone():
            next
        else:
            if b not in changesDomains:
                print "[+] New Domain Found :",b
                key = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(5)])
                cfile.write('bounties ; '+tableName+' ; '+'Domain^'+b+' , Research Only^False ; False ; '+key+'\n')
    cfile.close()

def main(): 
    parser = argparse.ArgumentParser(description='databaseActions')
    parser.add_argument('-ap', action='store_true', help='Add new program')
    # parser.add_argument('-aos', help='"Program" Interface to add to out of scope' )
    parser.add_argument('-ce', help='"Program Domain fileOfEndpoints" This will try to update the provided domain with any new endpoints found use `output >> ~/firstEndpointLocation` to update the list accordingly')
    parser.add_argument('-b', help='"Program" Search Using Brutesubs')
    # parser.add_argument('--whatWeb', help='"Program" whatWeb on every sites port value')
    parser.add_argument('-g', help='"Program File" Search Using Gobuster... Provide the program name, spaces and a file or directory ending in /')
    parser.add_argument('-dl', help='"Program File" File of domains to database')
    parser.add_argument('-c', help='"Program" Attempt to find new domains based on the other domains Certs')
    parser.add_argument('--fullRecon', help='"Program GobusterFileOrDirectory" Combines all domain recon in a automated fashion')
    parser.add_argument('--dns', help='"Program" Updates the data on DNS records of a program')
    # parser.add_argument('--title', help='"Program:{check all or just empty}AllOrEmpty')
    parser.add_argument('-r', action='store_true', help='Read Changes.txt')
    parser.add_argument('-cd', help='"Program" Checks and rechecks domains from the program for DNS Records and deletes those that have disappeared')
    # parser.add_argument('-cc', action='store_true', help='Checks changes.txt\'s domains for DNS Records')
    # parser.add_argument('-rd', help='"Domain" Remove, based on domain, from changes.txt')
    parser.add_argument('-rk', help='"5CharacterKey" Remove based on key')
    parser.add_argument('-rcp', help='"WordOrPattern:Program" Remove based on a character/ s in domain by program')
    parser.add_argument('-t', action="store_true", help='Send text notifications')
    parser.add_argument('-td', help='"Program" Emails domains')
    parser.add_argument('-skd', help='show key by domain') 
    parser.add_argument('-n', help='program:{subdomain range specific?}domainOrBlank:{Port Range}Full/Normal/Fast/Simple:{Current Database Status}AllOrEmpty <-- The last value is speaking of the ports status in the database. Run nmap on domains e.g. CompanyOrProgram:test.com:Full:All , CompanyOrProgram::Normal:Empty')
    parser.add_argument('-nr', help='program:{IP Range}:Full/Normal/Fast/Simple Run nmap on IP range e.g. CompanyOrProgram:{Range}:Full , CompanyOrProgram::Normal:Empty')
    parser.add_argument('--startBrowsers', help='"Program", start enumerating through domains from a programs database')
    parser.add_argument('-p', action='store_true', help='purge changes.txt')
    parser.add_argument('-s', action='store_true', help='Send to database')
    parser.add_argument('-e', help='"Program" Print all domains')
    parser.add_argument('-ep', help='"Program" Print all domains with ports')
    parser.add_argument('--printMe', help='"Program" Print all domains in database for program')
    args = parser.parse_args()
    conn = create_dbConnection()

    #Quick testcase
    # try:
    #     b = nmapOnDomain('360.yahoo.com', 'simple')
    #     cur = conn.cursor()
    #     cur.execute("SELECT `Ports` FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\'"%('Yahoo', '360.yahoo.com'))
    #     cPorts = cur.fetchone()[0]
    #     # if cPorts != '{}':
    #     #     print 'ports exist\n'
    #     #     loadedPorts = json.loads(cPorts)
    #     #     for lPort
    #     #         pdb.set_trace()
    #     # else: 
    #     #     print 'ports do not exist'
    #     cur.execute("UPDATE %s_liveWebApp SET `Ports` = \""%(program)+json.dumps(b)+"\" WHERE `Domain` LIKE \'%s\'"%(a))
    #     conn.commit()
    # except Exception,e:
    #     print 'Line 1292:\n'
    #     print e 
    #     pdb.set_trace()
    #Functional code that shouldn't be run again... it'll take all the json starting with '{' and return None // deleting all the ports data'
    # cur = conn.cursor()
    # cur.execute('SELECT Domain FROM Yahoo_liveWebApp') 
    # domainsSQL = list(cur.fetchall())
    # domainList = []

    # def returnJSON(cPorts):
    #     #Define JSONData 
    #     JSONData = {}
    #     #Null in the database
    #     if cPorts == None:
    #         return JSONData
    #     #Empty string 
    #     elif cPorts.strip() == '':
    #         return JSONData
    #     elif cPorts.startswith('{'):
    #         return JSONData
    #     else: 
    #         portsArray = cPorts.split(' , ')
    #         for b in portsArray: 
    #             try:
    #                 portData = b.split()
    #                 #Check the status of the port
    #                 portStatus = portData[1]
    #                 if portStatus != 'open':
    #                     continue
    #                 portNumber = portData[0]
    #                 #Check if port number is int type
    #                 if not isinstance(int(portNumber), int):
    #                     continue
    #                 #Port socket type
    #                 portType = portData[2]
    #                 portFingerprint = b.split(' :: ')[1]
    #                 JSONData[portNumber] = [portType, portFingerprint]
    #             except Exception,e:
    #                 pdb.set_trace()
    #         return JSONData



    # for a in domainsSQL:
    #     # a = re.findall(r"['](.*?)[']", str(x))
    #     domainList.append(str(a).split("'")[1])
    # for a in domainList:

    #     cur.execute('SELECT `Ports` FROM Yahoo_liveWebApp WHERE `Domain` LIKE \'%s\''%(a))
    #     cPorts = cur.fetchone()[0]
    #     if cPorts == None:
    #         cPorts = '{}'
    #     JSONData = returnJSON(cPorts)
    #     ##Here wouldbe a check for new/changed ports
    #     statem = 'UPDATE Yahoo_liveWebApp SET `Ports` = \''+json.dumps(JSONData)+'\' WHERE `Domain` LIKE \'%s\''%(a)
    #     sqlExeCommit(conn, statem)


    # if args.whatWeb:
    #     try: 
    #         socket.gethostbyname('google.com')
    #     except:
    #         print 'Internet connect failed'
    #         exit()
    #     program = args.whatWeb
    #     cur = conn.cursor()
    #     cur.execute('SELECT DISTINCT Domain, Ports FROM %s_liveWebApp'%(program))
    #     domainsSQL = cur.fetchall()
    #     domainsList = []
    #     for sqlValue in domainsSQL:
    #         domain = sqlValue[0]
    #         portsData = sqlValue[1]
    #         if portsData == None or portsData.strip() == '':
    #             domainsList.append([domain])
    #             continue
    #         else:
    #             domainAndPorts = [domain]
    #             for cport in portsData.split(' , '):
    #                 try:
    #                     domainAndPorts.append(cport.split()[0])
    #                 except Exception,e:
    #                     print e
    #                     # pdb.set_trace()
    #             domainsList.append(domainAndPorts)
    #             ##Should be [domain, port, port]
    #     for domain in domainsList:
    #         if len(domain)>1:
    #             webPortDict = {}
    #             cDomain = domain[0]
    #             iterPorts = iter(domain)
    #             next(iterPorts)
    #             for port in iterPorts:
    #                 portWebResponswe = callWhatWeb(cDomain, port)
    #                 if filter(None, portWebResponse) == []:
    #                     continue
    #                 else:
    #                     webPortDict[port] = portWebResponse
    #             # pdb.set_trace()
    #             webPortJSON = json.dumps(webPortDict)
    #             # pdb.set_trace()
    #             if webPortJSON == '[]':
    #                 continue
    #             else:
    #                 try: 
    #                     statem = 'UPDATE %s_liveWebApp SET `BuiltWith` = \''%(program)+webPortJSON+'\' WHERE `Domain` LIKE \'%s\''%(cDomain)
    #                     sqlExeCommit(conn, statem)
    #                     print cDomain,': updated'
    #                 except Exception,e:
    #                     print e 
    #                     pdb.set_trace()
    #             #Only if it has a port open do we update
    #             #cur.execute('UPDATE... ') >> So we won't have to wait for the whole cycle
    # if args.aos:
    #     cur = conn.cursor()
    #     cur.execute("SHOW TABLES;")
    #     a = re.search(args.aos(args.aos+'_liveWebApp', str(cur.fetchall())))
    #     if a:
    #         print "Table Found!"
    #     else:
    #         print "Table Not Found!"
        

    # if args.title:
    #     valueArgs = ['all', 'empty']
    #     titleArgs = args.title.split(':')
    #     if not len(titleArgs) == 2:
    #         print "Incorrect Format Check --help"
    #         exit()
    #     program = titleArgs[0]
    #     value = titleArgs[1]
    #     if not any(x in titleArgs[1].lower() for x in valueArgs):
    #         print '\nThe value Argument was not understandable...'
    #         exit()
    #     #We have the program and the value 
    #     domainsList = filter(None, grabDomains(conn, program))
    #     if titleArgs[1] == 'all':
    #      for a in domainsList:
    #         b = grabWebTitle(a)
    #         ##Curl the domain in 443 and 80 :',a
    #         if b:
    #             print a+':'+b
    #             statem = 'UPDATE %s_liveWebApp SET `Title` = \"'%(program)+b+'\" WHERE `Domain` LIKE \'%s\''%(a)
    #             sqlExeCommit(conn, statem)
    #     elif titleArgs[1] == 'empty':
    #         emptyDomains = [] 
    #         for a in domainsList:
    #             cur = conn.cursor()
    #             cur.execute('SELECT Title FROM %s_liveWebApp WHERE Domain=\"%s\"'%(program,a))
    #             if cur.fetchone()[0] == None:
    #                 emptyDomains.append(a)
    #         for a in emptyDomains:
    #             command = "curl %s -sL -m 5 | tac | tac | awk -vRS=\"</title>\" \'/<title>/{gsub(/.*<title>|"%(a)+r'\n'+"+/,\"\");print;exit}\'"
    #             b = subprocess.check_output(command, shell=True).strip()
    #             if b:
    #                 print a+':'+b
    #                 statem = 'UPDATE %s_liveWebApp SET `Title` = \"'%(program)+b+'\" WHERE `Domain` LIKE \'%s\''%(a)
    #                 sqlExeCommit(conn, statem)
    #         #Grab only of the value null 
    # if args.cc:
    #     domainsList2 = []
    #     fails2 = []
    #     cfile = open(changesTXTFolder+'/changes.txt', 'r')
    #     for a in cfile.readlines():
    #         domain = findInOut(a, 'Domain^')
    #         domainsList2.append(domain)
    #     cfile.close()
    #     try: 
    #         socket.gethostbyname('google.com')
    #     except:
    #         print 'Internet connect failed'
    #         exit()
    #     for a in domainsList2: 
    #         try: 
    #             b = socket.gethostbyname(a)
    #         except Exception,e:
    #             if e[0] == -2:
    #                 fails2.append(a)
    #                 print 'Failed: '+a
    #                 continue
    #             else:
    #                 print e
    #                 exit()
    #         if b == '192.168.0.1':
    #             print 'Failed (locally?): '+a
    #             fails2.append(a)
    #         else:
    #             pass
    #     ### Now we have a list of changes.txt domains that have failed
    #     for a in fails2:
    #         subprocess.call('python '+scriptFolder+'/pushToDatabase.py -rd '+a,shell=True)

    # if args.rd:
    #     removeByDomain(args.rd)
    #     print 'Removed:',args.rd

    # if args.td:
    #     domainsList = filter(None, grabDomainsAndPortsAndDNS(conn, args.td))
    #     b = open(tempFolder+'/email.temp', 'w')
    #     for a in domainsList:
    #         b.writelines(a +'\n')
    #     b.close()
    #     subprocess.call('python '+textNotesFolder+'/textNotes.py '+tempFolder+'/email.temp', shell=True)
        
    #     # subprocess.call('python /root/arsenal/personal/textNotes.py', shell=Tru
    
    if args.fullRecon:        
        ##Prompt to send to database 
        ##Should be safe to just call of ton of instances of the same script

        if len(args.fullRecon.split()) != 2:
            print '"File(Or directory) Program" is the format'
            exit()
        else:
            program = args.fullRecon.split()[0]
            cfile = args.fullRecon.split()[1]
            ##Brutesubs 
            subprocess.call('python ./pushToDatabase.py -b %s'%(program), shell=True)
            subprocess.call('python ./pushToDatabase.py -cc %s'%(program), shell=True)
            subprocess.call('python ./pushToDatabase.py -t', shell=True)
            ##Gobuster
            subprocess.call('python ./pushToDatabase.py -g \"%s %s\"'%(program, cfile), shell=True)
            subprocess.call('python ./pushToDatabase.py -cc %s'%(program), shell=True)
            subprocess.call('python ./pushToDatabase.py -t', shell=True)
            ##Domains by certs
            subprocess.call('python ./pushToDatabase.py -c %s'%(program), shell=True)
            subprocess.call('python ./pushToDatabase.py -cc %s'%(program), shell=True)
            subprocess.call('python ./pushToDatabase.py -t', shell=True)
            ##DNS / NS Check
            subprocess.call('python ./pushToDatabase.py --dns %s'%(program), shell=True)
            ##Prompt to send to database 
            while True:
                print 'Send over to the database?'
                g = raw_input('(seriouslyYes/no) ')
                if g == 'seriouslyYes':
                    subprocess.call('python ./pushToDatabase.py -s', shell=True)
                    break
                elif g == 'no':
                    exit()
                else: 
                    print "Input was not understood"

    # if args.dns:
    #     domainsList = filter(None, grabDomains(conn, args.dns))
    #     fails = []
    #     cur = conn.cursor()
    #     #Check connectivity
    #     try:
    #         socket.gethostbyname('google.com')
    #     except:
    #         print 'Internet connect failed'
    #         exit()
    #     for a in domainsList:
    #         grabWebDNS(a)
    #         try: 
    #             cdns = []
    #             b = socket.gethostbyname_ex(a)
    #             if (b[0] == a):
    #                 ###Should be the same... so pretty much a 'A Record'
    #                 cdns.append(b[0])
    #                 d = []
    #                 for c in b[2]:
    #                     d.append(c)
    #                 cdns.append(' , '.join(d))
    #             else: 
    #                 for c in b[1]:
    #                     cdns.append(c)
    #                 d = []
    #                 cdns.append(b[0])
    #                 for c in b[2]:
    #                     d.append(c)
    #                 cdns.append(' , '.join(d))
    #             data = ' : '.join(cdns)
    #             statem = 'UPDATE %s_liveWebApp SET `DNS` = \"'%(args.dns)+data+'\" WHERE `Domain` LIKE \'%s\''%(a)
    #             sqlExeCommit(conn, statem)
    #         except Exception,e:
    #             if e[0] == -2:
    #                 fails.append(a)
    #                 print 'Failed: '+a
    #                 continue
    #             else: 
    #                 print e 
    #                 exit()

    #         try: 
    #             f = dns.resolver.Resolver()
    #             g = f.query(a, 'NS')
    #             h = []
    #             for i in g:
    #                 h.append(str(i)[:-1])
    #             j = ' , '.join(h)
    #             statem = 'UPDATE %s_liveWebApp SET `NS` = \"'%(args.dns)+j+'\" WHERE `Domain` LIKE \'%s\''%(a)
    #             sqlExeCommit(conn, statem)
    #             #NS resolving
    #         except Exception,e:
    #             pass

        
    if args.ap:
        cur = conn.cursor()
        program = raw_input("Program: ").strip()
        platform = raw_input("Platform: ").strip()
        inScope = raw_input("In Scope Domains(*.test.com, test2.com): ").strip()
        outScope = raw_input("Out of Scope Domains(test.com, test2.com): ").strip()
        statem = "INSERT INTO programs(`Name`, `Platform`, `In Scope Domains`, `Out of Scope Domains`) VALUES (\'%s\',\'%s\',\'%s\',\'%s\')"%(program, platform, inScope, outScope)
        sqlExeCommit(conn, statem)

    if args.cd:
        cur = conn.cursor()
        domainsList = filter(None, grabDomains(conn, args.cd))         
        fails1 = []
        try:
            socket.gethostbyname('google.com')
        except:
            print 'Internet connect failed'
            exit()
        for a in domainsList:
            try: 
                b = socket.gethostbyname(a)
            except Exception,e:
                if e[0] == -2:
                    fails1.append(a)
                    print 'Failed: '+a
                    continue
                else: 
                    print e 
                    exit()
            if b == '192.168.0.1':
                print 'Failed (locally?): '+a
                fails1.append(a)
            else:
                pass
        c = int(str(len(fails1)) + '00')
        d = len(domainsList)
        e = c / d 
        f = 5
        if e > f:
            for a in fails1:
                print a
            print '\nPercentage: '+str(e)+'%'
            print 'Fails Length: '+str(c)
            print 'Total Length: '+str(d)
            print 'More than '+str(f)+' percent failed\n\nDo you wish to continue?'
            while True:
                g = raw_input('(seriouslyYes/no) ')
                if g == 'seriouslyYes':
                    break
                elif g == 'no':
                    exit()
                else: 
                    print "Input was not understood"
        for a in fails1:
            try:
                statem = 'DELETE FROM '+'`'+args.cd+'_liveWebApp'+'`'+'WHERE `Domain` = \''+a+'\''
                sqlExe(cur, statem)
            except Exception,e:
                print 'Failed?\n\n'+str(e)
        sqlCommit(conn)
        
        domainsList2 = []
        fails2 = []
        cfile = open(changesTXTFolder+'/changes.txt', 'r')
        for a in cfile.readlines():
            domain = findInOut(a, 'Domain^')
            domainsList2.append(domain)
        cfile.close()
        try: 
            socket.gethostbyname('google.com')
        except:
            print 'Internet connect failed'
            exit()
        for a in domainsList2: 
            try: 
                b = socket.gethostbyname(a)
            except Exception,e:
                if e[0] == -2:
                    fails2.append(a)
                    print 'Failed: '+a
                    continue
                else:
                    print e
                    exit()
            if b == '192.168.0.1':
                print 'Failed (locally?): '+a
                fails2.append(a)
            else:
                pass
        ### Now we have a list of changes.txt domains that have failed
        for a in fails2:
            subprocess.call('python '+scriptFolder+'/pushToDatabase.py -rd '+a,shell=True)
        # tempfile = open('/root/arsenal/tempFiles/current.domains.temp', 'w+')
        # for item in domainsList:
        #     tempfile.write("%s\n" % item)
        # tempfile.close()
        # subprocess.call("/root/arsenal/recon/DNS\ Discovery/massdns/bin/massdns -r resolvers.txt -a -o -w /root/arsenal/tempFiles/mass.temp /root/arsenal/tempFiles/current.domains.temp /root/arsenal/tempFiles/current.domains.temp > /dev/null 2>&1 && cat /root/arsenal/tempFiles/current.domains.temp", shell=True)


    if args.startBrowsers: 
        cur = conn.cursor()
        program = args.startBrowsers
        tempList = grabDomains(conn, program)
        domainList = []
        for a in tempList:
            cur.execute('SELECT Ports FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\''%(program, a))
            cPorts = cur.fetchone()[0]
            if cPorts:
                domainList.append(a)
        domainListLength = len(domainList)
        count = 0
        # for index2, a in enumerate(domainList):
        while count < domainListLength:
            a = domainList[count]
            if a == '':
                count += 1
                continue
            else:
                cur.execute('SELECT * FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\''%(args.startBrowsers, a))
                data = list(cur.fetchone())
                for index, b in enumerate(data):
                    if b == None:
                        data[index] = 'Not Done'
                researchBoolean = data[1]
                dnsLine = data[2]
                endpointsFile = data[3]
                nsLine = data[4]
                ports = '\n\t'.join(data[5].split(' :: '))
                builtWith = json.loads(data[6])
                contentSecurityLine = data[7]
                xframesLine = data[8]
                xssProtectionLine = data[9]
                contentTypeLine = data[10]
                title = data[11]
                infoPrint = True
                openWindow = True
                while True:
                    if openWindow:
                        openWindow = False
                        # subprocess.call(browserFile+' http://' + a, shell=True)
                        # subprocess.call(browserFile+' https://' + a, shell=True)
                    if infoPrint:
                        infoPrint = False
                        print '%s/%s'%(count,domainListLength-1)
                        print 'Domain: '+a
                        print 'Title: '+title
                        print 'Research Only: '+researchBoolean
                        print 'DNS: '+dnsLine
                        print 'NS: '+nsLine
                        print 'Ports: '+ports
                        print 'Built-With:'
                        for data in builtWith:
                            print '\tPort:'+data
                            print builtWith[data][1]
                        print 'Content-Security-Policy: '+contentSecurityLine
                        print 'X-Frames-Options: '+xframesLine
                        print 'X-Xss-Protection: '+xssProtectionLine
                        print 'X-Content-Type-Options: '+contentTypeLine+'\n'
                        print 'Headers:'
                        for data in builtWith:
                            print '\t Port:'+data
                            for header in builtWith[data][2]:
                                print '\t\t'+header
                        print ''

                    prompt = returningStatuscode(raw_input('next(n)/info/nc {integer}/go {integer}/checkInt/goohak/virtualHost/Dirsearch (quick): '), domainListLength)
                    if prompt[0] == 0: 
                        ###Continue 
                        print(chr(27) + "[2J")
                        count += 1
                        break
                    if prompt[0] == 1:
                        ###Starts netcat
                        host = a
                        port = prompt[1]

                        print 'Connecting... ',
                        try:
                            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            c.connect((host, port))
                            try:
                                print 'Success!'
                                while 1: 
                                    d = raw_input("(tcp-shell) $ ")
                                    c.send(d + "\n");
                                    result = c.recv(1024).strip();
                                    if not len(result):
                                        print "[-] Response Empty"
                                        c.close()
                                        break
                                    print result
                            except KeyboardInterrupt:
                                print "\n[-] ^C Received, closing connection"
                                c.close()
                            except EOFError:
                                print "\n[-] ^D Recieved, closing connection"
                                c.close()
                        except KeyboardInterrupt:
                            print '\n[-] ^C Received, closing connection' 
                            c.close()
                        except socket.error: 
                            print 'Fail'

                    if prompt[0] == 2:
                        ###Prints info 
                        print(chr(27) + "[2J")
                        infoPrint = True

                    if prompt[0] == 3:
                        ###Checks internet
                        print '    Checking internet...',
                        try: 
                            host = socket.gethostbyname('www.google.com')
                            c = socket.create_connection((host, 80), 2)
                            print 'Success!'
                        except Exception,e: 
                            print 'Failed'
                            print '    '+str(e)
                    if prompt[0] == 4:
                        ###Go to a specific number 
                        count = prompt[1]
                        break
                    if prompt[0] == 5:
                        ###Start goohak on domain
                        subprocess.call(goohakPath+'/goohak '+a,shell=True)
                    if prompt[0] == 6:
                        ##Start Virtual Host Discovery
                        ## a = theDomain
                        callVirtualHost(a, dnsLine) 
                    # if prompt[0] = 7:
                    #     ##Start dirsearch with large directory 
                    #
                    if prompt[0] == -1:
                        print '[-] Provided: '+prompt[1]
                        print '[-] Format wasn\'t understandable --- e.g. nc 8080, info, next'
                        ###Input was not understood

    if args.dl:
        if not len(args.dl.split()) == 2:
            print '[-] -dl "datbaseProgram FileLocation"'
            exit()
        else:
            program = args.dl.split()[0]
            cur = conn.cursor()
            with open(args.dl.split()[1]) as file:
                for line in file:
                    try:
                        statem = "INSERT INTO "+program+"_liveWebApp(`Domain`, `Research Only`) VALUES ('"+line[:-1]+"','False')"
                        sqlExe(cur, statem)
                    except Exception,e:
                        pass
            conn.commit()
    if args.printMe: 
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(args.printMe))
        domainsSQL = list(cur.fetchall())
        domainList = []
        for a in domainsSQL:
            # a = re.findall(r"['](.*?)[']", str(x))
            domainList.append(str(a).split("'")[1])
        for a in domainList:
            print a
                ### This is my playground for making quick changes to the database
                # cur.execute('UPDATE %s_liveWebApp SET `Research Only` = "True" WHERE `Domain` LIKE \'%s\''%(args.printMe, a)) 

                # print a
                # try:
                    # cur.execute('DELETE FROM `'+args.printMe+'_liveWebApp` WHERE `Domain` = \''+a+'\'')
                # except Exception,e:
                    # print e
                    # pass
            # conn.commit()
    if args.e:
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(args.e))
        domainsSQL = list(cur.fetchall())
        domainList = []
        for a in domainsSQL:
            # a = re.findall(r"['](.*?)[']", str(x))
            domainList.append(str(a).split("'")[1])
        for a in domainList:
            print a 
    if args.ep:
        cur = conn.cursor()
        program = args.ep
        tempList = grabDomains(conn, program)
        domainList = []
        for a in tempList:
            cur.execute('SELECT Ports FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\''%(program, a))
            cPorts = cur.fetchone()[0]
            if cPorts:
                domainList.append(a+":"+cPorts)
        for a in domainList:
            print a 

    if args.c:
        FNULL = open(os.devnull, 'w')
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(args.c)) 
        domainsSQL = list(cur.fetchall())
        domainList = []
        inScope = []
        for a in select_webAppFromPrograms(conn, True, args.c):
            if a[:2] == '*.':
                inScope.append(a[2:])
        for a in domainsSQL:
            # a = re.findall(r"['](.*?)[']", str(x))
            domainList.append(str(a).split("'")[1])
        for a in domainList:
            subprocess.call(crtshPath+'/crt.sh %s %s'%(a, tempFolder+'/crt.temp'), shell=True, stdout=FNULL)
            data = subprocess.check_output('cat '+tempFolder+'/crt.temp', shell=True)
            for b in filter(None, data.split('\n')):
                if b[:2] == '*.':
                    next
                else:
                    info = b.split('.')
                    try: 
                        if info[-2]+'.'+info[-1] in inScope:
                            cur.execute("INSERT INTO "+args.c+"_liveWebApp(`Domain`, `Research Only`) VALUES ('"+b+"','False')")
                            print "Found new inScope domain: "+b
                    except Exception,e:
                        pass


    if args.n:
        portArgs = ['full', 'normal', 'fast', 'simple']
        valueArgs = ['all', 'empty']
        a = args.n.split(':')
        if not len(a) == 4:
            print "Incorrect Format Check --help"
            exit()
        program = a[0]
        domain = a[1]
        if not any(x in a[2].lower() for x in portArgs):
            print '\nThe Port Argument was not understandable... "Full", "Normal", "Fast", "Simple"'
            exit()
        ports = a[2].lower()
        if not any(x in a[3].lower() for x in valueArgs):
            print '\nThe Current Value argument was not understandable... "All", "Empty"'
            exit()
        currentValue = a[3].lower() 
        ### Checking input
        ### Begin 
        cur = conn.cursor()
        cur.execute('SELECT Domain FROM %s_liveWebApp'%(program)) 
        domainsSQL = list(cur.fetchall())
        domainList = []
        if currentValue == 'all':
            for a in domainsSQL:
                # a = re.findall(r"['](.*?)[']", str(x))
                domainList.append(str(a).split("'")[1])
        elif currentValue == 'empty':
            tempList = []
            for a in domainsSQL:
                tempList.append(str(a).split("'")[1])
            for a in tempList:
                # This is for the 'empty' parameter
                # Needs to be Null or '' because {} may be a ton of 
                #   servers with no open ports
                cur = conn.cursor()
                cur.execute('SELECT Ports FROM %s_liveWebApp WHERE Domain=\"%s\"'%(program,a))
                if cur.fetchone()[0] == None:
                    domainList.append(a)
        if domain != '':
            domainList2 = [a for a in domainList if domain in a]
            domainList = domainList2
        for a in domainList: 
            try:
                b = nmapOnDomain(a, ports)
                cur.execute("UPDATE %s_liveWebApp SET `Ports` = \""%(program)+json.dumps(b)+"\" WHERE `Domain` LIKE \'%s\'"%(a))
                conn.commit()
            except Exception,e:
                print 'Line 1292:\n'
                print e 
                pdb.set_trace()
        

    #     # nmapOnDomain(conn, program, domain, currentValue);
    # if args.nr:
    #     # -sP on domains :: problem with ranges giving a variable range for the response
    #     # take the domains and check which ones are inscope, then log the outscope variables 
    #     print 'test'

    if args.r:
        with open(changesTXTFolder+'/changes.txt', 'r') as file:
            print file.readlines()

    if args.rk:
        if len(args.rk) != 5:
            print "\n 5 Character key not provided"
            exit()
        else: 
            removeByKey(args.rk)
    if args.ce:
        if len(args.ce.split()) != 3:
            print '\n -ce "program Domain fileOfEndpoints" is the correct format'
            exit()
        else:
            a = args.ce.split()
            program = a[0]
            domain = a[1]
            fileOfEndpoints = a[2]
            try: 
                cur = conn.cursor()
                statem = "SELECT `Endpoints` FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\'"%(program,domain)
                cur.execute("SELECT `Endpoints` FROM %s_liveWebApp WHERE `Domain` LIKE \'%s\'"%(program,domain))
                result = cur.fetchone()[0]
                if result == None:
                    if os.path.isfile(fileOfEndpoints):
                        cur.execute("UPDATE %s_liveWebApp SET `Endpoints` = \'"%(program)+fileOfEndpoints+"\' WHERE `Domain` LIKE \'%s\'"%(domain))
                        conn.commit()
                    else:
                        print 'The file provided did not work properly'
                else:
                    if os.path.isfile(fileOfEndpoints) & os.path.isfile(result):
                        b = open(result, 'r').readlines()
                        c = open(fileOfEndpoints, 'r').readlines()
                        for e in c:
                            if e not in b:
                                print e
                    else:
                        print '\nOne of the paths failed:\n%s\n%s'%(result,fileOfEndpoints)
                        exit()

            except Exception,e:
                print e
                exit()

    if args.p:
        cfile = open(changesTXTFolder+'/changes.txt', 'w')
        cfile.write('')
        cfile.close()

    if args.rcp:
        word = args.rcp.split(':')[0]
        program = args.rcp.split(':')[1]
        removeBasedOnPattern(word, program)

    if args.g:
        if len(args.g.split()) != 2:
            print '"Program File(Or directory)" is the format'
            exit()
        else:
            program = args.g.split()[0]
            bruteList = args.g.split()[1]
            if bruteList[-1] == '/':
                base = bruteList[-1]
                for filename in os.listdir(base):
                    ##Call gobuster
                    mainGobuster(program, base+filename, conn)
            else: 
                #Call gobuster
                mainGobuster(program, bruteList, conn)

    if args.b:
        inScope = select_webAppFromPrograms(conn, True, args.b)
        outScope = select_webAppFromPrograms(conn, False, args.b)
        checkLiveWebApp(conn, args.b+'_liveWebApp')
        pdb.set_trace()
        for a in inScope:
            cleanTempFolder()   
            #try:
            if (a[:2] == '*.'):
                a = a[2:]
                b = callBrutesubs(a)
                # Return a array of domains
                ## eventually add a dig dig cert call 
                checkLiveWebApp_Domains(conn, args.b+'_liveWebApp', b, outScope)
            else:
                try:
                    cur = conn.cursor()
                    statem = "INSERT INTO "+args.b+"_liveWebApp(`Domain`, `Research Only`) VALUES ('"+a+"','False')"''
                    cur.execute(statem)
                    conn.commit()
                except Exception, e:
                    pass
            # except Exception, e:
            #     print '[-]',a,'something went wrong:',e
            #     exit()
        # for a in outScope:
        #     cleanTempFolder()
        #     if (a[:2] == '*.'):
        #         a = a[2:]
        #         b = callBrutesubs(a)
        #         checkLiveWebApp_Domains(conn, sys.argv[1]+'_liveWebApp', b)

    if args.s:
        domainFound(conn)

    if args.t:
            subprocess.call('python '+textNotesFolder+'/textNotes.py text '+changesTXTFolder+'/changes.txt', shell=True)

# random = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(5)])
# 
main()
