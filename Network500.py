#vim:fileencoding=cp932
# -*- coding: cp932 -*-
import os, sys
import socket
import threading
import datetime, time
import urllib, urllib2

ver = "v5.10"

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
           self.serv = u"不明"
           if (self.port == 25565):
               self.serv = "Minecraft"

    def run(self):
        try:
            pingstart = time.time() # Start Timer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            if (self.senddata != ""): sock.send(self.senddata) # Send
            pingend = time.time() - pingstart # Stop Timer
            print("  [+] ["+ self.host +"/"+ str(self.port) +" - "+ str(round(pingend, 4)*1000) +u"ミリ秒]: TCP/IP Open | "+ self.serv)
            print("      [Data]:"+ sock.recv(1024 * 1024))
        except:
            pass

class ScannerOption():
    def __init__(self, iphost, portnum, timeout):
      self.iphost  = iphost
      self.portnum = portnum
      self.msg     = "" # Error msg
      try: # str -> int Timeout
          self.timeout = float(timeout)
      except:
          try:
              self.timeout = int(timeout)
          except:
              self.timeout = 1
      try: # Get Start Port Number
           self.startport = int(self.portnum[0]) # Port
      except:
           self.startport = 0
      try: # Get IP -> Host-Name
         hostaddr = socket.gethostbyaddr(self.iphost)
         self.hostname = hostaddr[0]
      except:
         self.hostname = "Unknown-Host"
      try: # Get IP addr
         self.host = socket.gethostbyname(self.iphost)
      except:
         self.host = self.iphost

    def option(self):
       try: # Port Scan Number and Get Scan Mode
           self.endport = int(self.portnum[1]) # Error Point
           if (self.endport >= 65535): self.endport = 65535 # flood endport number?
           self.mode = "Nomal-Scan"
       except:
          try: # Select Mode
              mode = self.portnum[1].lower()
              if (mode == "service"): # -service
                 self.mode = "Service-Scan"
                 self.startport = 0
                 self.endport   = 65535
              elif (mode == "all"):
                 self.mode    = "All-Scan"
                 self.endport = 65535                 

              elif (mode == "one"): # ___-one
                 self.mode     = "One-Scan"
                 self.port     = self.startport # Port Number
                 self.endport  = port + 1

              elif (mode == "host"):
                 self.mode    = "Host-Scan"
                 self.port    = self.startport
                 self.endport = 256

              elif (mode == "allhost"):
                 self.mode    = "All-HostScan"
                 self.port    = self.startport
                 self.endport = 256

              elif (mode == "ping"):
                 self.mode    = "Host-Ping"
                 self.port    = self.startport
                 self.endport = 5000
                 if (scan.timeout == 1): scan.timeout = 5

              elif (mode == "icmp"):
                 self.mode    = "ICMP-Ping"
                 self.port    = 0
                 self.endport = "ICMP"
                 if (scan.timeout == 1): scan.timeout = 5

              elif (mode == "icmpscan" or mode == "icmphost"):
                 self.mode    = "ICMP-Scan"
                 self.port    = 0
                 self.endport = "ICMP"             

              else: # None Select
                 self.mode    = "All-Scan"
                 self.endport = 65535
          except:
              self.mode    = "All-Scan"
              self.endport = 65535

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
               self.serv = u"不明"
        return self.serv

    def inerror(self, msg = ""):
        self.msg = msg

    def outerror(self):
        if (self.msg != ""):
            return "["+ self.msg +"]"
        else:
            return ""

# -------------------------------------------------------------------------
try: # Setting Argv
   iphost   = sys.argv[1] # Host
   portmode = sys.argv[2] # Port
   try:
      timeout  = sys.argv[3] # Timeout
      senddata = sys.argv[4] # Send Data
   except:
      timeout  = "1"
      senddata = ""
   print(u"\n [*] [ホスト: "+ iphost +u" | モード: "+ portmode +u" | 時間: "+ timeout +u"秒 | 送信: "+ senddata +"]")
   argv = True
except:
   argv = False

if (argv != True):
   os.system("cls")
   try:
      os.system("title [ Network Scanner "+ ver +" -Multi Thread Kosho-Runrom] - "+ socket.gethostbyname(socket.gethostname()))
   except:
      os.system("title [ Network Scanner "+ ver +" -Multi Thread Kosho-Runrom]")
   print("""
    +-------------------[  Network """+ ver +"""  ]--------------------+
    |       ssss                                               |
    |      s             aaaa                                  |
    |       sss    ccc  a    a   nnnn  nnnn    eeee   rrr      |
    |          s  c     aaaaaa   n   n n   n  eeeeee  rr       |
    |      ssss    ccc       aaa n   n n   n   eeee   r        |
    |                                                          |
    +----------------------------------------------------------+
    """)

while True:
    try: # Cheack Connect to Internet
        activeNet = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        activeNet.settimeout(5)
        activeNet.connect(("www.google.com", 80))
        break
    except: # Failed
        if (argv): sys.exit(u" [-] インターネットに接続できません。接続されているか確認してください...")
        print(u" [-] インターネットに接続できません。接続されているか確認してください...")
        raw_input()

while True:
   if (argv != True):
       iphost  =  raw_input(" [IP, ホスト名]: ") # Input Host or IP
       if (iphost == ""): continue
       portmode = raw_input(" [ポート設定  ]: ") # Setting Mode
       timeout  = raw_input(" [時間設定(秒)]: ") # Setting Timeout
       senddata = raw_input(" [送信データ  ]: ") # Send data (or file path)
   portnum = portmode.translate(None, ' ').split("-") # Get mode and Port Number

   try: # Port Scan Send Data
       with open(senddata, "rb") as f:
          senddata = f.read()
   except:
       senddata = senddata.encode("utf-8")

   scan = ScannerOption(iphost, portnum, timeout) # Class of Scan Setting
   scan.option() # Class of Scan Option
   start = time.time() # Start Timer
   msg = "" # C^ print error msg

   # Show Scan Mode -------------------------------------------------------------------
   print(u"\n [*] ネットワークスキャンを開始しました (Ctrl+C -> 停止)")
   print(u" [+] モード: ["+ scan.mode +" - "+ str(scan.startport) +".."+ str(scan.endport) +" : "+ str(scan.timeout) +u"秒]")
   print(u" [+] 時間  : ["+ scan.gettime() +" - "+ ver +"]")
   print(u" [+] ホスト: ["+ socket.gethostbyname(socket.gethostname()) +" -> "+ scan.iphost +" - "+ scan.host +"]")
   if (scan.hostname != "Unknown-Host" or scan.hostname != "."): print(u"             ["+ scan.hostname +"]")
   scan.inerror("Ctrl+C")
   print("\n +------------------------------------------------------------------+")

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
         for port in xrange(65535):
            thscan = PortScan_Main(scan.host, port, senddata, scan.timeout)
            thscan.start()
         try: # ICMP -> T/F
            pingstart = time.time() # Start Timer
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(scan.timeout)
            sock.sendto("\x08\x00\xf5\xfc\x01\x01\x01\x02", (scan.host, 0))
            sock.recv(1024)
            pingend = time.time() - pingstart # Stop Timer
         except socket.error, error:
            try:
               print(u"  [-] ["+ scan.host +"/ICMP]: "+ str(error))
            except:
               pass
         else:
            print(u"  [+] ["+ scan.host +"/ICMP - "+ str(round(pingend, 4)*1000) +u"ミリ秒]: ICMP/Open ")      

      elif (scan.mode == "One-Scan"):
          thscan = PortScan_Main(scan.host, scan.port, senddata, scan.timeout)
          thscan.start()
          time.sleep(scan.timeout)

      elif (scan.mode == "Host-Scan"):
          hscan_sp = scan.host.split(".")
          hscan = hscan_sp[0] +"."+ hscan_sp[1] +"."+ hscan_sp[2] +"." # 255.255.255.xxx
          for ipnum in xrange(256):
             time.sleep(0.001)
             thscan = PortScan_Main(hscan + str(ipnum), scan.port, senddata, scan.timeout)
             thscan.start()
          time.sleep(0.1)

      elif (scan.mode == "All-HostScan"):
          hsplit = scan.host.split(".")
          for ipnum2 in xrange(256):
             print(u"\n  [*] スキャン中: ["+ str(hsplit[0]) +"."+ str(ipnum2) +".xxx.xxx/"+ str(scan.port) +"] (xxx < 255)")
             for ipnum3 in xrange(256):
                for ipnum4 in xrange(256):
                    time.sleep(0.001) # IP -> [76.xxx.xxx.xxx]
                    ip = str(hsplit[0]) +"."+ str(ipnum2) +"."+ str(ipnum3) +"."+ str(ipnum4)
                    thscan = PortScan_Main(ip, scan.port, senddata, scan.timeout)
                    thscan.start()
          time.sleep(0.1)

      elif (scan.mode == "Host-Ping"):
          errornum = 0
          connum   = 0
          while True:
              try:
                  pingstart = time.time() # Start Timer
                  # --------------------------------------------------------------
                  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                  sock.settimeout(scan.timeout)
                  sock.connect((scan.host, scan.port))
                  if (senddata != ""): sock.send(senddata)
                  # --------------------------------------------------------------
                  connum += 1
                  pingend = time.time() - pingstart # Stop Timer
                  print("  [+] ["+ scan.host +"/"+ str(scan.port) +" ("+ scan.getservice() +") - "+ str(scan.timeout*1000) +u"ミリ秒]: "+ str(round(pingend, 4)*1000) +u"ミリ秒")
              except socket.error, error:
                  print("  [-] ["+ scan.host +"/"+ str(scan.port) +" ("+ scan.getservice() +") - "+ str(scan.timeout*1000) +u"ミリ秒]: "+ str(error))
                  errornum += 1
              finally:
                  pingend   = 0
                  time.sleep(1)
                  scan.inerror(u"成功: "+ str(connum) +u" | 失敗: "+ str(errornum)) # Error and Connected info

      elif (scan.mode == "ICMP-Scan"):
          hscan_sp = scan.host.split(".")
          hscan = hscan_sp[0] +"."+ hscan_sp[1] +"."+ hscan_sp[2] +"." # 255.255.255.xxx
          scan.inerror(u"管理者権限で実行してください")
          sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) # root Error Point
          scan.inerror() # reset error msg
          for ipnum in xrange(256):
              try:
                  pingstart = time.time() # Start Timer
                  # -------------------------------------------------------------------------
                  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                  sock.settimeout(scan.timeout)
                  sock.sendto("\x08\x00\xf5\xfc\x01\x01\x01\x02", (hscan + str(ipnum), scan.port))
                  sock.recv(1024)
                  # -------------------------------------------------------------------------
                  pingend = time.time() - pingstart # Stop Timer
                  print("  [+] ["+ hscan + str(ipnum) +"/ICMP - "+ str(scan.timeout*1000) +u"ミリ秒]: "+ str(round(pingend, 4)*1000)+ u"ミリ秒")
              except socket.error, error:
                  pass

      elif (scan.mode == "ICMP-Ping"):
          errornum = 0
          connum   = 0
          while True:
              try:
                  pingstart = time.time() # Start Timer
                  # --------------------------------------------------------------
                  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                  sock.settimeout(scan.timeout)
                  sock.sendto("\x08\x00\xf5\xfc\x01\x01\x01\x02", (scan.host, scan.port))
                  sock.recv(1024)
                  # --------------------------------------------------------------
                  connum += 1
                  pingend = time.time() - pingstart # Stop Timer
                  print("  [+] ["+ scan.host +"/ICMP - "+ str(scan.timeout*1000) +u"ミリ秒]: "+ str(round(pingend, 4)*1000) +u"ミリ秒")
              except socket.error, error:
                  print("  [-] ["+ scan.host +"/ICMP - "+ str(scan.timeout*1000) +u"ミリ秒]: "+ str(error))
                  errornum += 1
              finally:
                  pingend = 0
                  time.sleep(1)
                  if (errornum == 0 and connum == 0):
                      scan.inerror(u"管理者権限で実行してください")
                  else:
                      scan.inerror(u"成功: "+ str(connum) +u" | 失敗: "+ str(errornum)) # Error and Connected info


   except: # Input key: Ctrl+C or an error
      time.sleep(0.1)
      print(u"\n  [-] スキャンを終了しました "+ scan.outerror())

   ti = scan.gettime()
   endtime = time.time() - start
   print(u"\n  [*] スキャン情報: ["+ ti +" | "+ str(round(endtime, 3)) +u"秒]")
   print(u" +------------------------------------------------------------------+\n")
   if (argv): break
   else: print("")

