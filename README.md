ErrorPacketAttack
=================

畸形数据包演示程序，可用于测试，学习，分析
Error packets demo, can be used to test, study and analysis

使用scapy
Used scapy module

Usage
=================
    python error_make.py

    Welcome to Scapy (2.1.0)
    Error Packets Test v1.0
    >>>pt = pkgTest()

    >>>pt.showpak("ip1")
    <Ether  dst=FF:FF:FF:FF:FF:FF src=00:00:00:00:00:00 type=0x800 |<IP  ihl=5 len=40 id=22222 flags=DF frag=0 proto=udp chksum=0x8ae src=192.168.1.10 dst=192.168.1.20 |<UDP  sport=italk dport=rockwell_csp2 chksum=0x8ae |<Raw  load='ASDF123' |>>>>

    >>> pt.showhex("ip1")
    0000   FF FF FF FF FF FF 00 00  00 00 00 00 08 00 45 00   ..............E.
    0010   00 28 56 CE 40 00 40 11  08 AE C0 A8 01 0A C0 A8   .(V.@.@.........
    0020   01 14 30 39 08 AE 00 0F  08 AE 41 53 44 46 31 32   ..09......ASDF12
    0030   33

    >>> pt.showinfo("ip1")
    dst        : DestMACField         = 'FF:FF:FF:FF:FF:FF' (None)
    src        : SourceMACField       = '00:00:00:00:00:00' (None)
    type       : XShortEnumField      = 2048            (0)
    --
    version    : BitField             = 4               (4)
    ihl        : BitField             = 5               (None)
    tos        : XByteField           = 0               (0)
    len        : ShortField           = 40              (None)
    id         : ShortField           = 22222           (1)
    flags      : FlagsField           = 2               (0)
    frag       : BitField             = 0               (0)
    ttl        : ByteField            = 64              (64)
    proto      : ByteEnumField        = 17              (0)
    chksum     : XShortField          = 2222            (None)
    src        : Emph                 = '192.168.1.10'  (None)
    dst        : Emph                 = '192.168.1.20'  ('127.0.0.1')
    options    : PacketListField      = []              ([])
    --
    sport      : ShortEnumField       = 12345           (53)
    dport      : ShortEnumField       = 2222            (53)
    len        : ShortField           = None            (None)
    chksum     : XShortField          = 2222            (None)
    --
    load       : StrField             = 'ASDF123'       ('')

    >>>pt.SIP = "127.0.0.1"
    >>>pt.DIP = "192.168.1.2"
    >>>pt.s_MAC = ""
    >>>pt.d_MAC = ""
    >>>a.mkpcap(file_path="./ip1.pcap",pkg="ip1",intf="eth1",intv=2,coun=10)
    ..........
    Sent 10 packets.

    >>pt.sendall(file_path="./ip1.pcap", intf="eth1", intv=2, coun=10)
    ..........
    Sent 10 packets.
    ..........
    Sent 10 packets.
    ........

Help
-----------------
pkgTest()
    the object of test packets

pkgTest.showpak(pkg)
    show packet structure as scapy like this:
        <Ether  type=0x800 |<IP  frag=0 proto=tcp |<TCP  |>>>

    pkg: the packet name like "ip1, tcp1, udp1, icmp1"
pkgTest.showhex(pkg)
    show the packets hex as scapy like this:
        0000   FF FF FF FF FF FF 00 00  00 00 00 00 08 00 45 00   ..............E.
        0010   00 28 00 01 00 00 40 06  7C CD 7F 00 00 01 7F 00   .(....@.|.......
        0020   00 01 00 14 00 50 00 00  00 00 00 00 00 00 50 02   .....P........P.
        0030   20 00 91 7C 00 00                                   ..|..

     pkg: the packet name like "ip1, tcp1, udp1, icmp1"

pkgTest.showinfo(pkg)
    show the packets information as scapy like this:
        dst        : DestMACField         = 'ff:ff:ff:ff:ff:ff' (None)
        src        : SourceMACField       = '00:00:00:00:00:00' (None)
        type       : XShortEnumField      = 2048            (0)
        --
        version    : BitField             = 4               (4)
        ihl        : BitField             = None            (None)
        tos        : XByteField           = 0               (0)
        len        : ShortField           = None            (None)
        ......

    pkg: the packet name like "ip1, tcp1, udp1, icmp1"

pkgTest.mkpcap(file_path, pkg, intf, intv, coun)
    make the packet to a pacp file

    file_path: Pcap file location
    pkg: the packet name like "ip1, tcp1, udp1, icmp1"
    inft: interface to sand the packet default is Loopback
    intv: interval to sand the packet default is 1 second
    count: The number of sending packets default is 10 times

pkgTest.sendall(file_path, intf, intv, count)
    sand all error packets and save to a pcap file

    file_path: Pcap file location
    inft: interface to sand the packet default is Loopback
    intv: interval to sand the packet default is 1 second
    count: The number of sending packets default is 10 times

Knowledge
-------------------
Just support IPv4

+ totallen is 16 bit total length 
+ headerlen is 4 bit header length
+ sizeof is all bit IP header length

+ [targe3 attack]
    ip1: totallen < sizeof
    ip2: totallen < headerlen
    ip3: headerlen  < sizeof
    ip4: headerlen < 5
    ip5: version != 5
    ip6: if TCP: totallen < headerlen + TCP(dataofs)
    ip7: if TCP: TCP(dataofs) < sizeof(TCP)
    ip8: if UDP: totallen < headerlen + UDP(len)
    ip9: if ICMP: totallen < headerlen + ICMP(8 byte)

+ [land attack]
    ip10: srcip = desip

+ [ping of death attack]
    ip11: totallen > 65535

+ [IP Option attack]
    opt1: ip option has IPOPT_LSRR(3):"loose_source_route"
    opt2: ip option has IPOPT_SSRR(9):"strict_source_route"
    opt3: ip option has IPOPT_RR(7)

+ [genport attack]
    tcp1: sport is 0
    tcp2: dport is 0

+ [winnuke attack]
    tcp3: dport is 139 and tcpflag with TH_URG

+ [tcpsscan attack]
    tcp4: tcpflag with SYN,RST,ACK,FIN,PUSH,URG
    tcp5: SYN,PSH,ACK,URG
    tcp6: FIN
    tcp7: SYN,FIN
    tcp8: tapflag is 0
    tcp9: FIN,PSH,URG
    tcp10: URG,FIN
    tcp11: PUSH,FIN
    tcp12: URG,PUSH
    tcp13: SYN,FIN,PSH,URG

+ [udp attack]
    udp1: sport is 0
    udp2: dport is 0

+ [icmp attack]
    icmp1: icmp echo is 8 and ipaddr is brocast

+ [dns attack] X
    dns1: dns request header request count less than 1
    dns2: dns request header request count more than 16
    dns3: dns request header response count more than 1
    dns4: only dns request header , not dns payload
    dns5: DNS request header after the first byte of the value of the < = 1

+ [dhcp attack] X
    dhcp1: The DHCP request source MAC and the EtherNet header source MAC is not equal
