/*
# JSlibpcap.js
#
# @Author : looterofflux
# @Licence: GPL 
# @Date:    2017	
#
# 
*/
(function(){
// PCAP FILE
function pcap_hdr_s( ){
return {
	magic_number:	uint32,
	version_major:	uint16,
	version_minor:	uint16,
	thiszone:	int32,
	sigfigs:	uint32,
	snaplen:	uint32,
	network:	uint32
};
}

function pcaprec_hdr_s( ){
return {
	ts_sec:		uint32,
	ts_usec:	uint32,
	incl_len:	uint32,
	orig_len:	uint32,
	packet:		"*orig_len"
};
}

// PCAPNG FILE
function pcap_master_block_hdr( ){
return{
	type:		uint32, // 0x0A0D0D0A
	total_len:	uint32,
	bo_magic:	uint32, // 0x1A2B3C4D LittleEndian
	version_major:	uint16, // 0x0001
	version_minor:	uint16, // 0x0000
	//64
	section_len_f:	uint32, // 0xFFFFFFFF
	section_len_s:	uint32, // 0xFFFFFFFF
};
}
function pcap_opts_hdr( ){
return {
	// opts_len
	// by order 32bits
	opts_code:	uint16,
	opts_len : 	uint16,
	opts_payload:	"*opts_len->dword",

	opts_endofopt:	uint16,
	opts_len_:	uint16,
	
}
};
function pcap_end_32( ){
return{
	b_len:		uint32,
}
};
function pcap_type32( ){
return{
	type:		uint32,
}
};

function pcap_interface_descript_block( ){
return{
	type:		uint32,
	total_len:	uint32,
	link_type:	uint16,
	reserved:	uint16,
	snaplen:	uint32,
};
}

function pcap_enhanced_block_hdr( ){
return{
	type: 		uint32, // 0x00000006
	total_len: 	uint32,
	interfaces_id: 	uint32,
	timestamp_hight:uint32,
	timestamp_low:	uint32,
	captured_len: 	uint32,
	packet_len:	uint32,
	packet:		"*packet_len->dword",
};
}

function pcap_isb_hdr( ){
return {
	type:		uint32, // 0x00000005
	total_len:	uint32,
	if_id:		uint32,
	timestamp_h:	uint32,
	timestamp_l:	uint32,
	
};
}

function pcap_simple_block_hdr( ){
return{
	type: 		uint32, // 0x00000003
	block_len: 	uint32,
	packet_len:	uint32,
	payload:	"*packet_len->dword",
};
}
	
var shbOpts = {
	2:"shb_hardware",
	3:"shb_os",
	4:"shb_userappl"
}, idbOpts = {
	2:"if_name",
	3:"if_description",
	4:"if_ipv4addr",
	5:"if_ipv6addr",
	6:"if_MACaddr",
	7:"if_EUIaddr",
	8:"if_speed",
	9:"if_tsresol",
	10:"if_zone",
	11:"if_filter",
	12:"if_os",
	13:"if_fcsien",
	14:"if_tsoffset",
};


/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Option Code              |         Option Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                       Option Value                            /
/                variable length, aligned to 32 bits            /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Option Code == opt_endofopt  |  Option Length == 0          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
function pcapReadOpt( __data__, off, endian, opts ){
	var pcapopts, sz;

	/*
	# Opts variable pcapng.
	*/
	try{
		sz = struct.sizeof( pcap_opts_hdr( ) );
		while( true ){
			
			struct.buffer2struct( 
				__data__,
				pcapopts = pcap_opts_hdr( ),
				off,
				endian
			);
			
			opts[ pcapopts.opts_code ] = pcapopts;
			off += sz + pcapopts.opts_len;

			// to take off four bytes at Offset
			// 2 bytes for endofopt and 2 bytes for optlen
			// other variable...
			if( pcapopts.opts_endofopt != 0x00 ){
				off-=4;
			}else
			break;;
									
		}
	}catch(e){
		return 0xFFFFFF;
	};
return off;
}
/**/
/*
# load file pcap
# @return object {
#	e 	: error,
#	header 	: struct pcap_hdr_s
#	frame 	: Array frameCaptured
#	framelen: uint Length of frames
#	offset	: uint32 position of cursor
# }
#
*/
function loadPcap( __binary__ ){
	var endian, pcaphdr,
	    off, hsz, e = 0;

	struct.buffer2struct(
		__binary__,
		pcaphdr = pcap_hdr_s( ),
		0,
		( endian = !true )
	);
	
	// BAD ENDIAN
	if( pcaphdr.magic_number !== 0xD4C3B2A1 )
	struct.buffer2struct(
		__binary__,
		pcaphdr = pcap_hdr_s( ),
		0,
		( endian = !endian )
	);;

	// magic number
	// BAD magic number
	if( pcaphdr.magic_number != 0xD4C3B2A1 ){
		return 0xBAD01001;
	}
	pcaphdr.network = LittleEndian( pcaphdr.network, 4 );
	off = struct.sizeof( pcap_hdr_s( ) );
	
	/**/
	try{
	 	var frame = [], pack;
		hsz = off;
		while( off < __binary__.length  ){
			
			struct.buffer2struct( 
				__binary__,
				pack = pcaprec_hdr_s( ),
				off,
				!endian
			);
			off += pack.orig_len + struct.sizeof( pcaprec_hdr_s( ) );
			frame.push( pack );
		}
	}catch(e){};

	// BROKEN FILE
	if( off !== __binary__.length ){
		e = 0xBAD0103;
	}

return {
	e: 		e,
	header:		pcaphdr,
	frame : 	frame,

	framelen: 	frame.length,
	// ( EOF - HEADER )- HEADER_FRAME * frameLength
	capturedlen:	(off-hsz) - struct.sizeof( pcaprec_hdr_s( ) ) * frame.length,

	// offset should be equal to EOF
	// if offset is different to EOF
	// then get peek see error 
	offset: 	off,

};
}
/*
# load file pcapng
# @return object {
#	e 	: error,
#	shb 	: struct pcap_master_block_hdr
#	idb 	: struct pcap_interface_descript_block _hdr
#	frame 	: Array frameCaptured
#	framelen: uint Length of frames
#	isb	: struct pcap_isb_hdr
#	offset	: uint32 position of cursor
# }
#
*/
function loadPcapng( __file__ ){
	var pcapmb,pcapopts, pcapidb,
	    endian, opts = [],
	    off, e = 0;
	
	// Little-Endian
	// First peek
	struct.buffer2struct(
		__file__,
		pcapmb = pcap_master_block_hdr( ),
		0,
		( endian = true )
	);
	

	// Big-Endian
	if( pcapmb.bo_magic != 0x1A2B3C4D )
	struct.buffer2struct(
		__file__,
		pcapmb = pcap_master_block_hdr( ),
		0,
		( endian = !endian )
	);
	
	// magic number
	// BAD magic number
	if( !( pcapmb.type == 0x0A0D0D0A ) ){
		
		return { e: 0xBAD01001 };
	}
	

	/*
	# Opts variable pcapng.
	*/
	try{
		off 	     =  pcapReadOpt( 
					__file__, 
					off = struct.sizeof( pcap_master_block_hdr( ) ) ,
					endian,
					opts 
				);

		pcapmb.opts  =  opts;
		pcapmb.b_len =  struct.buffer2struct( __file__, pcap_end_32( ), off, endian ).b_len;
		off+= 4;
			
	}catch(e){};
	/**/
	
	/*
	* Structure
	* Interface Description Block
	*/
	try{
		struct.buffer2struct( 
			__file__,
			( pcapidb = pcap_interface_descript_block( ) ), 
			off,
			endian 
		);
		off += struct.sizeof( pcap_interface_descript_block( ) );
		
		off 	      =  pcapReadOpt( __file__, off, endian,  ( opts = [] ) );
		pcapidb._opts = opts;
		pcapmb.b_len =  struct.buffer2struct( __file__, pcap_end_32( ), off, endian ).b_len;
		off+=4;

	}catch(e){  };
	// ERROR BAD READ HEADER PCAPNG
	// But Continue
	if( ( pcapmb.total_len + pcapidb.total_len ) !== off ) {
		e = 0xBAD01002;
	}
	
	/*
	# Get Frame 
	*/
	try{
		var frame = [], pcapisb,
		    packs, psz,tmp,fsz = off;

		psz = 0; 
		while( true && ( off < __file__.length ) ){
		
			tmp = struct.buffer2struct(
				__file__,
				pcap_type32( ),
				off,
				endian
			);

			if( tmp.type == 3 || tmp.type == 6 ){
				
				struct.buffer2struct( 
					__file__,
					packs =  ( tmp.type === 3 ? pcap_simple_dr( ) : pcap_enhanced_block_hdr( ) ), 
					off,
					endian
				);
				//console.log( packs );
				off += packs.total_len;
				frame.push( packs );

			// isb structure
			}else if( tmp.type === 5 ){
				
				struct.buffer2struct( 
					__file__,
					( packs = pcap_isb_hdr( ) ), 
					off,
					endian
				);
				
				// opts
				off += struct.sizeof( pcap_isb_hdr( ) );
				off  = pcapReadOpt( __file__, off, endian, ( opts = [] ) );
				packs.opts = opts;
				packs.b_len =  struct.buffer2struct( __file__, pcap_end_32( ), off, endian ).b_len;
				off+=4;
				
				pcapisb = packs;

			// NO ERROR
			}else if( off === __file__.length ){
				break;
			// Break in file
			}else{
				e = 0xBAD0103;
				break;
			}	
	
		}

	}catch(e){ console.log(e); };
	/**/	
return {
	e: 		e,
	pcapng:		!0,

	shb : 		pcapmb,
	idb : 		pcapidb,
	
	frame: 		frame,
	framelen: 	frame.length,
	// ( EOF - HEADER )- HEADER_FRAME * frameLength
	capturedlen:	(off-fsz) - ( struct.sizeof( pcap_enhanced_block_hdr( ) ) * frame.length ),
	isb: 		pcapisb,
	// offset should be equal to EOF
	// if offset is different to EOF
	// then get peek see error 
	offset: 	off,
	};
}

// export libpcap to window
// attach callback to __w__
window.libpcap = function( __w__ ){

	__w__.acceptedExt.push( 
		"pcap", "pcapng"
	);
	__w__.format[ "pcap" ]  = loadPcap;
	__w__.format[ "pcapng"] = loadPcapng;

return __w__;
};

window.libpcap.error = {
	
	0xBAD01001:"This file is not a ( pcap ) or ( pcapng ) file",
	0xBAD01002:"Warning : bad reading of the header has been detected, this is could modify the result of the output !",
	0xBAD01003:"Bad end of file , reading has been broken, maybe it's a malformed file !"
	
};
window.libpcap.idbOpts = idbOpts;
window.libpcap.shbOpts = shbOpts;

})( );

