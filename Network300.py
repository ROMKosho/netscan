import os, sys
import socket
import threading
import datetime, time



class PortScan_Main(threading.Thread):
    def __init__(self, host, port, senddata, timeout):
        super(PortScan_Main, self).__init__()             
        self.senddata   = senddata # Set Send Data
        self.port    = port # Set Port
        self.host    = host # Set Host (Must IP Address)
        self.timeout = timeout
        try:
           self.serv = socket.getservbyport(self.port, "tcp") # Service Name
        except:
           self.serv = "Unknown"
           if (self.port == 25565):
               self.serv = "Minecraft"

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            if (self.senddata != ""): sock.send(self.senddata) # Send
            print("  [*] ["+ self.host +"/"+ str(self.port) +"]: TCP/IP Open | "+ self.serv)
            recvdata = sock.recv(1024 * 1024)
            print("      [Data]:"+ str(recvdata))
        except:
            pass

class ScannerOption():
    def __init__(self, iphost, portnum, timeout):
      self.iphost  = iphost
      self.portnum = portnum 
      self.msg     = "" # Error msg
      try:
          self.timeout = float(timeout)
      except:
          try:
              self.timeout = int(timeout)
          except:
              self.timeout = 1
      try:
         hostaddr = socket.gethostbyaddr(self.iphost)
         self.hostname = hostaddr[0]
      except:
         self.hostname = "Unknown-Host" 
      try:
         self.host = socket.gethostbyname(self.iphost) # Get IP add
      except:
         self.host = self.iphost
           
    def option(self):
       try:
           self.startport = int(self.portnum[0]) # Port
       except:
           self.startport = 0
      
       try: # Port Scan Number
           self.endport = int(self.portnum[1]) # Error Point
           if (self.endport >= 65535): self.endport = 65535 # flood endport number?
           self.mode = "Nomal-Scan"
       except:
          try:
              mode = self.portnum[1].lower()
              if (mode == "service"): # -service
                 self.mode = "Service-Scan"
                 self.startport = 0 
                 self.endport   = 65535
  
              elif (mode == "one"): # ___-one
                 self.mode     = "One-Scan"
                 self.port     = self.startport # Port Number              
                 self.endport  = port + 1

              elif (mode == "host"):
                 self.mode    = "Host-Scan"
                 self.port    = self.startport
                 self.endport = 256
              
              elif (mode == "ping"):
                 self.mode    = "Host-Ping"
                 self.port    = self.startport
                 self.endport = 5000
                 if (scan.timeout == 1): scan.timeout = 5
                 
              else: # None Select
                 self.mode    = "All-Scan"
                 self.endport = 65535
          except:
              self.mode    = "All-Scan"
              self.endport = 65535

      #return self.scanmode, self.startport, self.endport, port

    def gettime(self):
       now = datetime.datetime.now()
       return now.strftime("%Y/%m/%d %H:%M:%S")
  
    def getservice(self):
        try:
           self.serv = socket.getservbyport(self.port, "tcp") # Service Name
        except:
           if (self.port == 25565):
               self.serv = "Minecraft"
           else:
               self.serv = "Unknown"
        return self.serv
  
    def inerror(self, msg = ""):
        self.msg = msg

    def outerror(self):
        if (self.msg != ""): 
            return "["+ str(self.msg) +"]"
        else:    
            return ""

# -------------------------------------------------------------------------
os.system("cls")
os.system("title [Network Scanner v3.20 -Multi Kosho-Runrom (Free License)]")
print("""
    +-------------------[  Network v3.20  ]--------------------+
    |       ssss                                               |
    |      s             aaaa                                  |
    |       sss    ccc  a    a   nnnn  nnnn    eeee   rrr      |
    |          s  c     aaaaaa   n   n n   n  eeeeee  rr       |
    |      ssss    ccc       aaa n   n n   n   eeee   r        |
    |                                            (Free Mode)   |
    +----------------------------------------------------------+
""")


while True:
   iphost  =  raw_input(" [Host, IP ]: ")
   portmode = raw_input(" [Port Mode]: ")
   timeout  = 0.1
   senddata = "Test"
   portnum = portmode.translate(None, ' ').split("-")

   try: # Port Scan Send Data
       with open(senddata, "rb") as f:
          senddata = f.read()
   except:
       senddata = senddata.encode("utf-8")
   
   scan = ScannerOption(iphost, portnum, timeout)
   scan.option() # Class of Scan Option
   start = time.time() # Start Timer
   msg = "" # C^ print error msg

   print("\n [*] Started Network Scanning... (Ctrl+C to Stop)")   
   print(" [+] Mode: ["+ scan.mode +" - "+ str(scan.startport) +".."+ str(scan.endport) +" : "+ str(scan.timeout) +"s]")
   print(" [+] Time: ["+ scan.gettime() +"]")
   print(" [+] Host: ["+ scan.iphost +" - "+ scan.host +"]")
   print("           ["+ scan.hostname +"]")

   print("\n +-------------------------------------------------------------+")

   try:
      if (scan.mode == "Nomal-Scan"):
         for port in range(scan.startport, scan.endport + 1):
            thscan = PortScan_Main(scan.host, port, senddata, scan.timeout)
            thscan.start()
       
      elif (scan.mode == "Service-Scan"):
         for port in range(scan.startport, 9754):
            try:
               socket.getservbyport(port, "tcp") # Error Point
               thscan = PortScan_Main(scan.host, port, senddata, scan.timeout)
               thscan.start()
            except:
               pass
            thscan = PortScan_Main(scan.host, 11320, senddata, scan.timeout)
            thscan.start()
            thscan = PortScan_Main(scan.host, 47624, senddata, scan.timeout)
            thscan.start()

      elif (scan.mode == "All-Scan"):
         for port in xrange(65536):
            thscan = PortScan_Main(scan.host, port, senddata, scan.timeout)
            thscan.start()

      elif (scan.mode == "One-Scan"):
          thscan = PortScan_Main(scan.host, scan.port, senddata, scan.timeout)
          thscan.start()
          time.sleep(0.1)
          
      elif (scan.mode == "Host-Scan"):
          hscan_sp = scan.host.split(".")
          hscan = hscan_sp[0] +"."+ hscan_sp[1] +"."+ hscan_sp[2] +"." # 255.255.255.xxx
          for ipnum in xrange(256):
             time.sleep(0.1)
             thscan = PortScan_Main(hscan + str(ipnum), scan.port, senddata, scan.timeout)
             thscan.start()
          time.sleep(0.1)               

   except: # Input key: Ctrl+C
      time.sleep(0.1)
      print("\n  [-] Network Scan Stopped "+ scan.outerror())

   ti = scan.gettime()
   endtime = time.time() - start
   print("\n  [*] Scanning End: ["+ ti +" | "+ str(round(endtime, 3)) +"s]")
   print(" +-------------------------------------------------------------+\n \n")

