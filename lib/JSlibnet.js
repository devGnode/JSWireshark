/*
# JSlibpcap.js
#
# @Author : looterofflux
# @Licence: GPL 
# @Date:    2017	
#
# TCP/IP
*/
function eth_hdr( ){
return {
	hdw_dst_addr:	"6",
	hdw_src_addr:	"6",
	eth_type:	WORD
}
};
function arp_hdr(){
return{
	network_type:	uint16,
	protocol_type:	uint16,
	hdw_addr_len:	uint8,
	ip_len:		uint8,
	op:		uint16,
	
	hdw_src_addr:	"6",
	ip_src_addr:	uint32,

	hdw_dst_addr:	"6",
	ip_dst_addr:	uint32
};
}

function ipv4_hdr( ){
return {
	ihl:	uint8,
	service: { 
		priority:3, delay:1, deb:1, f:1, cost:1, mbz:1
	},
	payload_len: 	uint16,
	identification:	uint16,
	flag: { 
		flag:3, fragment:13 
	},
	ttl:		uint8,
	protocol:	uint8,
	checksum:	uint16,
	
	ip_src_addr:	uint32,
	ip_dst_addr:	uint32,

};
}
// sizeof 8+16+16= 40
function ipv6_hdr( ){
return {

	_:{ 
		version:4, class:8, label:20
	},
	payload_len: 	uint16,
	next:		uint8,
	jump:		uint8,
	
	src_addr:	"16",
	dst_addr:	"16",

};
}
// sizeof 28
function tcp_hdr( ){
return {
	port_src:	uint16,
	port_dst:	uint16,
	seq:		uint32,
	n_ack:		uint32,
	
	flag:{
	 	offset:4, reserved:6, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1 
	},
	window:		uint16,
	checksum:	uint16,
	ptr:		uint16,
};
}
//sizeof 8
function udp_hdr(){
return{
	port_src:	uint16,
	port_dst:	uint16,
	length:		uint16,
	checksum:	uint16
};
}

function dns_hdr(){
return {
	id:		uint32,
	_:{
		Qr:1, opcode:4, Aa:1, Tc:1, Rd:1, Z:1, Rcode:4
	},
	Qdcount:	uint16,
	Ancount:	uint16,
	Nscount:	uint16,
	Arcount:	uint16,
	
	query:		"",
	
	Qtype:		uint16,
	Qclass:		uint16,
};
}

function icmp_hdr( ){
return{
	type:		uint8,
	code:		uint8,
	checksum:	uint16,
	identifer:	uint16,
	seq:		uint16,

	payload:	""
}
};
function icmpv6_hdr( ){
return{
	type:		uint8,
	code:		uint8,
	checksum:	uint16,

	payload:	""
}
};

function igmp_hdr( ){
return {
	type:		uint8,
	trm:		uint8,
	checksum:	uint16,
	addr:		uint32,
};
}
var protocolType = {

	0x6000:"DEC",
	0x0609:"DEC",
	0x0600:"DEC",
	0x0800:"IPV4", // used
	0x0806:"ARP", // used
	0x8019:"DOMAIN",
	0x8035:"RARP",
	0x809B:"APPLE TALK", // deprecated
	0x8100:"802.1Q",
	0x86DD:"IPV6", // used
	0x8863:"PPPoE Discovery Stage",
	0x8864:"PPPoE Session Stage",
	0x88A2:"ATA", //used
	0x887B:"HomePlug Protocol", //used
	0x88E1:"HomePlug AV", // used
	0x88E3:"Media Redundacy Protocol",
	0x88E5:"MAC security",
	0x88F7:"Precision Time Protocol",
	//..
	0x8906:"FireChannel over Ethernet",
	

}, hdw_type = {
	
	0x01:"Ethernet",0x02:"Experimental Ethernet",
	0x03:"Radio Amator",0x04:"ProNet Token Ring",
	0x05:"Chaos",0x06:"IEEE 802 Net",
	0x07:"ARCNET",0x08:"Hyperchannel",
	0x09:"Lanstar",0x0A:"Auto Short Address",
	0x0B:"Local Talk",0x0C:"LocalNet",
	0x0D:"Ultra Link",0x0E:"SMDS",
	0x0F:"Frame Relay",0x10:"Asynchronous Transmission Mode ATM",
	0x11:"HDLC",0x12:"Fibre Channel",
	0x13:"Asynchronous Transmission Mode ATM",0x14:"Serial Line",
	0x15:"Asynchronous Transmission Mode ATM",0x16:"MIL-STD-188-220",
	0x17:"Metricom",0x18:"IEEE 1394.1995",
	0x19:"MAPOS",0x1A:"Twinaxial",
	0x1B:"EUI-64",0x1C:"HIPARP",
	0x1D:"IP and ARP over ISO-7816-3",0x1E:"ARPSec",
	0x1F:"IPsec tunnel",0x20:"InfiniBand(TM)",
	0x21:"TIA-102 Project 25 common Air Interface (CAI)"

}, ipv6next = { 
	0x01:"ICMP",
	0x02:"IGMP",
	0x06:"TCP",
	0x11:"UDP",
	0x3A:"ICMPV6"
}, ipv4Protocol = {
	// RFC
	0x01:"ICMP",0x02:"IGMP",
	0x03:"GGP",0x04:"IP",
	0x05:"ST",0x06:"TCP",
	0x07:"UCL",0x08:"EGP",
	0x09:"IGP", //...
	0x11:"UDP", 0x27:"RDP",
	0x1C:"IRTP"

}, 
// some port UDP & TCP
tcp_ports = {
	7:"echo/ICMP",
	20:"FTP",21:"FTP",22:"SSH",23:"TelNet",25:"SMTP",	
	53:"DNS", 69:"TFTP",80:"http",
	109:"POP2",110:"POP3",
	137:"NetBIOS", 138:"NetBIOS-ns", 139:"NetBIOS-dgm",
	143:"IMAP",194:"IRC", 443:"https", 445:"SMB", 465:"SMTPS",
	636:"SSL/TLS",
	990:"FTPS",993:"IMAP/SSL",995:"POP3/SSL",1080:"SOCKS",
	1337:"L33t",1883:"MQTT",2164:"DynDNS",
	8080:"http proxy", 1194:"OpenVPN", 1723:"PPTP", 3306:"MySQL",
	3389:"DPD",5432:"PostgreSQL",6000:"X11",9050:"TorProject", 9150:"TorProject"	
}, udp_port = {
	
	7:"echo/ICMP",53:"DNS",20:"FTP",21:"FTP",23:"TelNet",
	25:"SMTP",67:"BOOTSTRAPPC",68:"BOOTSTRAPPS",69:"TFTP",
	137:"NetBIOS",138:"NetBIOS-ns",139:"NetBIOS-dgm",
	161:"SNMP",445:"SMB",546:"DHCP",6000:"X11",
	1337:"L33t", 2164:"DynDNS"

},

net = {

	/*toString*/	
	macAddrToStr:function( ptr ){
	return vscanf( 
		"%h:%h:%h:%h:%h:%h",
		ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]
	 );
	},
	ipv6AddrToStr:function( ptr ){
	return vscanf( 
		"%h%h:%h%h:%h%h:%h%h:%h%h:%h%h:%h%h:%h%h",
		ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], 
		ptr[5], ptr[6], ptr[7], ptr[8], ptr[9],
		ptr[10], ptr[11], ptr[12], ptr[13], ptr[14],ptr[15]
	 ).replace(/(\:[0]{4})/g,"");
	},
	ipToStr:function( ipuint32 ){
	return ( (( ipuint32 >> 24 )&0xff) +"."+
		 (( ipuint32 >> 16 )&0xff) +"."+
		 (( ipuint32 >> 8  )&0xff) +"."+
		 (( ipuint32 )&0xff));	
	},
	htons:function( ip ){
	return LittleEndian( ip < 0 ? base.hex2dec( base.dec2hext( ip ) ) : ip, 4 );
	},
  
  };
