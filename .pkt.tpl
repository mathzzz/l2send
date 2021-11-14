# cat ~/.pkt.tpl
# arp

# icmp
080027a23b3d080027b7ec880800 //l2
45000054ae3140004001b3e3ac100c0a0a161664  //l3
080000c107e4015d  //l4
0a778b61000000009752020000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637 //payload


# udp
080027 a23b3d // dmac
080027 b7ec88 // smac
0800  // etype
4500 0046 //ver,Hlen, tos, iplen=0x46
5f84 4000 // id, offset
4011 028f // ttl, protocol, checksum
ac10 0c0a // sip
0a16 1664 // dip
2710 2711 0032 d8d7  // udp sport, dport; udp len, checksum
6865 6c6c 6f2c 2077 6f72 6c64 2120
6865 6c6c 6f2c 2077 6f72 6c64 2120
6865 6c6c 6f2c 2077 6f72 6c64 210a



# tcp syn
080027 a23b3d
080027 b7ec88
0800 //etype
4500 003c // ver Hlen, tos, iplen
00e7 4000 // id, frag+offset
4006 6141 // ttl, protocol, checksum
ac10 0c0a // sip
0a16 1664 // dip
4e20 4e21 // sport, dport
3d26 3aa4 // seq num
0000 0000 // ack num
a002      // HL, Flags
7210      // window size
d8c2 0000 // tcp checksum, ugp
0204 05b4 0402 080a 0cf3
3a43 0000 0000 0103 0307


# tcp syn+ack
# tcp fin
# tcp rst
# tcp psh

# icmpv6

# vrrp

# lacp
