#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
logging.getLogger("scapy").setLevel(1)

import subprocess
from scapy.all import *

__author__ = "Coyote"

class pkgTest():
    '''
	totallen = 16bit total length = len
	headerlen = 4 bit header length = ihl
	sizeof = all bit IP header length
    '''
    SIP="192.168.1.10"
    DIP="192.168.1.20"
    d_MAC="FF:FF:FF:FF:FF:FF"
    s_MAC="00:00:00:00:00:00"
    eth_lay=Ether(dst=d_MAC,src=s_MAC,type=2048)
    #ip_lay=IP(ihl=5,len=40,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=DIP)
    #upd_lay=UDP(sport=12345,dport=2222,chksum=2222)
    #tcp_lay=TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=4,flags=24,chksum=1234)/"testdata"
    #icmp_lay=ICMP(id=1,seq=1)/"abcdefghijklmnopqrstuvwabcdefghi"
    #pay_load="ASDF123"


    ######################################----DEFINE PACKAGE----#####################################
    #------------------------------------###--IP_HEADER--###----------------------------------------#
    # 1. totallen < sizeof
    IP_1=eth_lay/IP(ihl=5,len=40,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=DIP)/\
            UDP(sport=12345,dport=2222,chksum=2222)/"ASDF123"
    # 2. totallen < headerlen
    IP_2=eth_lay/IP(ihl=5,len=19,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=DIP)/\
            UDP(sport=12345,dport=2222,chksum=2222)/"ASDF123"
    # 3. headerlen  < sizeof
    IP_3=eth_lay/IP(ihl=4,len=49,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=DIP)/\
            UDP(sport=12345,dport=2222,chksum=2222)/"ASDF123"
    # 4. headerlen < 5
    IP_4=eth_lay/IP(ihl=3,len=49,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=DIP)/\
            UDP(sport=12345,dport=2222,chksum=2222)/"ASDF123"
    # 5. version != 5
    IP_5=eth_lay/IP(version=5,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=DIP)/\
            UDP(sport=12345,dport=2222,chksum=2222)/"ASDF123"
    # 6. TCP : totallen < headerlen + TCP(dataofs)
    IP_6=eth_lay/IP(ihl=5,len=35,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=DIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags=24,chksum=1234)/"testdata"
    # 7. TCP : TCP(dataofs) < sizeof(TCP)
    IP_7=eth_lay/IP(ihl=5,len=35,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=DIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=4,flags=24,chksum=1234)/"testdata"
    # 8. UDP : totallen < headerlen + UDP(len)
    IP_8=eth_lay/IP(ihl=5,len=30,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=DIP)/\
            UDP(sport=12345,dport=2222,chksum=2222,len=15)/"ASDF123"
    # 9. ICMP : totallen < headerlen + ICMP(8位)
    IP_9=eth_lay/IP(ihl=5,len=25,id=22222,flags="DF",frag=0,proto=1,chksum=2222,src=SIP,dst=DIP)/\
            ICMP(id=1,seq=1)/"abcdefghijklmnopqrstuvwabcdefghi"
    # 10 srcip = desip
    IP_10=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=SIP)/\
            UDP(sport=12345,dport=2222,chksum=2222)/"ASDF123"
    # 11 totallen > 65535
    IP_11=eth_lay/IP(ihl=5,len=65535,id=22222,flags="DF",frag=0,proto=1,chksum=2222,src=SIP,dst=DIP)/\
            UDP(sport=12345,dport=2222,chksum=2222)/"ASDF123"

    #------------------------------------###--IP_OPTION--###----------------------------------------#
    # 1. IPOPT_LSRR(3):"loose_source_route"
    opt1=IPOption_LSRR(length=3)
    IPOPT_1=eth_lay/IP(ihl=6,len=52,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=DIP,options=opt1)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags=24,chksum=1234)/"testdata"
    # 2. IPOPT_SSRR(9):"strict_source_route"
    opt2=IPOption_SSRR(length=3)
    IPOPT_2=eth_lay/IP(ihl=6,len=52,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=DIP,options=opt2)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags=24,chksum=1234)/"testdata"
    # 3. IPOPT_RR(7)
    opt3=IPOption_RR(length=3)
    IPOPT_3=eth_lay/IP(ihl=6,len=52,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=DIP,options=opt3)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags=24,chksum=1234)/"testdata"
    
    #------------------------------------###--TCP_HEADER--###----------------------------------------#
    # 1. sport=0
    TCP_1=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=0,dport=2222,seq=100,ack=241235,dataofs=5,flags=24,chksum=1234)/"testdata"
    # 2.dport=0
    TCP_2=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=0,seq=100,ack=241235,dataofs=5,flags=24,chksum=1234)/"testdata"
    # 3.dport=139,flags have TH_URG
    TCP_3=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags=56,chksum=1234)/"testdata"
    # 4.flags have SYN,RST,ACK,FIN,PUSH,URG
    TCP_4=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="SRAFPU",chksum=1234)/"testdata"
    # 5.SYN,PSH,ACK,URG
    TCP_5=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="SPAU",chksum=1234)/"testdata"
    # 6.FIN
    TCP_6=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="F",chksum=1234)/"testdata"
    # 7.SYN,FIN
    TCP_7=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="SF",chksum=1234)/"testdata"
    # 8.flags=0
    TCP_8=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags=0,chksum=1234)/"testdata"
    # 9.FIN,PSH,URG
    TCP_9=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="FPU",chksum=1234)/"testdata"
    # 10.URG,FIN
    TCP_10=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="UF",chksum=1234)/"testdata"
    # 11.PUSH,FIN
    TCP_11=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="PF",chksum=1234)/"testdata"
    # 12.URG,PUSH
    TCP_12=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="UP",chksum=1234)/"testdata"
    # 13.SYN,FIN,PSH,URG
    TCP_13=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=6,chksum=2222,src=SIP,dst=SIP)/\
            TCP(sport=12345,dport=2222,seq=100,ack=241235,dataofs=5,flags="SFPU",chksum=1234)/"testdata"
    #------------------------------------###--TCP_OPTION--###----------------------------------------#
    # 1. tcp an option len less than 2
    # 2. tcp an option len more than tcpend   
    #------------------------------------###--UDP_HEADER--###----------------------------------------#
    # 1. UDP sport = 0
    UDP_1=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=SIP)/\
            UDP(sport=0,dport=2222,chksum=2222)/"ASDF123"
    # 2. UDP dport = 0
    UDP_2=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=17,chksum=2222,src=SIP,dst=SIP)/\
            UDP(sport=12345,dport=0,chksum=2222)/"ASDF123"
    #------------------------------------###--ICMP_HEADER--###----------------------------------------#
    # 1.icmp echo is 8 and ipaddr is brocast
    ICMP_1=eth_lay/IP(ihl=5,id=22222,flags="DF",frag=0,proto=1,chksum=2222,src=SIP,dst="255.255.255.255")/\
            ICMP(id=1,seq=1)/"abcdefghijklmnopqrstuvwabcdefghi"

    #------------------------------------###--BASE_DICT--###-----------------------------------------#
    BASEDICT = {"ip1":IP_1,"ip2":IP_2,"ip3":IP_3,"ip4":IP_4,"ip5":IP_5,"ip6":IP_6,"ip7":IP_7,"ip8":IP_8,"ip9":IP_9,"ip10":IP_10,"ip11":IP_11,
		"opt1":IPOPT_1,"opt2":IPOPT_2,"opt3":IPOPT_3,"tcp1":TCP_1,"tcp2":TCP_2,"tcp3":TCP_3,"tcp4":TCP_4,
		"tcp5":TCP_5,"tcp6":TCP_6,"tcp7":TCP_7,"tcp8":TCP_8,"tcp9":TCP_9,"tcp10":TCP_10,"tcp11":TCP_11,
		"tcp12":TCP_12,"tcp13":TCP_13,"udp1":UDP_1,"udp2":UDP_2,"icmp1":ICMP_1}

    def mkpcap(self,file_path,pkg,intf="lo",intv=1,coun=10):
	if not os.path.exists(file_path):
	    f=open(file_path,"w")
	    f.close()
        cmd = "tcpdump -i %s -w "%(intf) + file_path + " > /dev/null 2> /dev/null & "
        subprocess.call(cmd,shell=True,stdout=subprocess.PIPE)
	sendp(self.BASEDICT[pkg],iface=intf,inter=intv,count=coun)
	#time.sleep(intv*coun)
	cmd = "killall tcpdump"
	subprocess.call(cmd,shell=True,stdout=subprocess.PIPE)

    def showpak(self,pkg):
	return self.BASEDICT[pkg]

    def showinfo(self,pkg):
	return ls(self.BASEDICT[pkg])

    def showhex(self,pkg):
	return hexdump(self.BASEDICT[pkg])

    def sendall(self,file_path,intf="lo",intv=1,coun=10):
	if not os.path.exists(file_path):
            f=open(file_path,"w")
            f.close()
        cmd = "tcpdump -i %s -w "%(intf) + file_path + " > /dev/null 2> /dev/null & "
	subprocess.call(cmd,shell=True,stdout=subprocess.PIPE)
	for i in self.BASEDICT:
	    sendp(self.BASEDICT[i],iface=intf,inter=intv,count=coun)
	cmd = "killall tcpdump"
        subprocess.call(cmd,shell=True,stdout=subprocess.PIPE)

if __name__ == "__main__" :
	interact(mydict=globals(),mybanner="Error Packets Test v1.0")
