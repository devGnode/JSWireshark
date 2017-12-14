## :one: Pcap or pcapng

#### how does attach libpcap at your object JSON
For attach your object with the JSlibpcap, just create a empty array named **acceptExt** then a object empty JSON named **format**,
the library gonna attach himself at your object, like below.

```javascript
var opts = { acceptedExt:[], format:{} };
window.libpcap( 
 opts
);
```
your object will be extenced as below :

```javascript
opts = {
  acceptExt:[ "pcap", "pcapng" ],
  format:{
    pcap: function handler
    pcapng: function handler
    }
};
```
## :two: Prototype pcapng

### pcapng


```javascript
opts.format.pcapng( 
  StringBinnary __file__
);
```
The function to return 

```javascript
opts = {
  // error
  e: uint,
  
  //  Frame captured
  frame: array
  framelen: uint
  
  // structure
  shb: JSON,
  idb: JSON,
  isb: JOSN
  
  // offset
  capturedLen: uint 
  offset: uint 
};
```
* error : Error
* frame : Array who contains raw frames
```javascript
pcap_enhanced_block_hdr{
	type: 		uint32, // 0x00000006
	total_len: 	uint32,
	interfaces_id: 	uint32,
	timestamp_hight:uint32,
	timestamp_low:	uint32,
	captured_len: 	uint32,
	packet_len:	uint32,
	packet:		"*packet_len->dword",
}
```
* framelen : it's the number of frames captured
* shb : Header

```javascript
pcap_master_block_hdr{
	type:		uint32, // 0x0A0D0D0A
	total_len:	uint32,
	bo_magic:	uint32, // 0x1A2B3C4D LittleEndian
	version_major:	uint16, // 0x0001
	version_minor:	uint16, // 0x0000
	//64
	section_len_f:	uint32, // 0xFFFFFFFF
	section_len_s:	uint32, // 0xFFFFFFFF
  
  opts: [ *pcap_opts_hdr ]
}

pcap_opts_hdr{
	// opts_len
	// by order 32bits
	opts_code:	uint16,
	opts_len : 	uint16,
	opts_payload:	"*opts_len", // align 32 bits

	opts_endofopt:	uint16,
	opts_len_:	uint16,
	
}
```
* idb : Header 

```javascript
pcap_interface_descript_block{
	type:		uint32,
	total_len:	uint32,
	link_type:	uint16,
	reserved:	uint16,
	snaplen:	uint32,
}
```
* isb: Header
```javascript
pcap_isb_hdr{
	type:		uint32, // 0x00000005
	total_len:	uint32,
	if_id:		uint32,
	timestamp_h:	uint32,
	timestamp_l:	uint32,
	
}
```
* capturedlen : it's number of bytes captured.
* offset : offset should be equal to EOF, if offset is different to EOF therefore get peek to the report error

## :three: Prototype pcap

### pcap


```javascript
opts.format.pcap( 
  StringBinnary __file__
);
```
The function to return 


```javascript
{
	e: 		uint32,
  
	header:		JSON,
	frame : 	Array,

	framelen: 	uint32,
	capturedlen:	uint32,
  
	offset: 	uint32,

};
```
* header : Header

```javascript
pcap_hdr_s{
	magic_number:	uint32,
	version_major:	uint16,
	version_minor:	uint16,
	thiszone:	int32,
	sigfigs:	uint32,
	snaplen:	uint32,
	network:	uint32
};
```
* frame : Array who contains raw frames

```javascript
pcaprec_hdr_s{
	ts_sec:		uint32,
	ts_usec:	uint32,
	incl_len:	uint32,
	orig_len:	uint32,
	packet:		"*orig_len"
};
```
## :four: Error

| N°        | Text     |
| ------------- |:-------------:|
| 0xBAD01001      | This file is not a ( pcap ) or ( pcapng ) file |
| 0xBAD01002      | Warning : bad reading of the header has been detected, this is could modify the result of the output !      | 
| 0xBAD01003      |Bad end of file , reading has been broken, maybe it's a malformed file !      |
