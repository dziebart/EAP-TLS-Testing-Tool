##Based on the code of P. Ebbecke at "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/"
import multiprocessing
from scapy.all import *
#For signing without pad & Encrypting:
from M2Crypto import RSA, m2, EVP
#For Elliptic Curve Math:
import tinyec.ec as ec
import tinyec.registry as reg
import random
import hashlib
import hmac
#For PRF-Calculations:
import tlslite
from tlslite import X509, X509CertChain
from Crypto.Util.number import long_to_bytes, bytes_to_long

from Monitor_ifc import Monitor
 
#ConnectionPhase-class taken from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/", modified and extended
class ConnectionPhase:
    """
    Establish a connection to the AP via the following commands
    """
 
    def __init__(self, monitor_ifc, sta_mac, bssid, private_key, public_cert, ca_certs, identity):
        self.state = "Not Connected"
        self.mon_ifc = monitor_ifc
        self.sta_mac = sta_mac
		self.bssid = bssid
		self.handshake_log = ""
		self.client_secret = 0
		self.current_id = 0
		self.premaster = 0
		self.master = 0

		self.private_key_file = private_key
		self.public_cert_file = public_cert
		self.ca_certs_file = ca_certs

		self.eap_identity = identity

############################################################################################################ 
#Method based on code from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/"
    def send_authentication(self):
    """
    Send an Authentication Request and wait for the Authentication Response.
    Which works if the user defined Station MAC matches the one of the
    wlan ifc itself.

    :return: -Reserved=0 Ack Policy=0 EOSP=0 TID=0 TXOP=0
    """
        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid, SC=0x0010) / Dot11Auth(
                algo=0, seqnum=0x0001, status=0x0000)

		print("#########################################################")
		print("Sending following packet for authentication:")
		print("#########################################################")
        packet.show()
 
        jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_auth,
            args=(result_queue, ))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet,None, ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 
        if result_queue.get():
            self.state = "Authenticated"

############################################################################################################ 
#Method based on code from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/"
    def send_assoc_request(self, ssid):
    """
    Send an Association Request and wait for the Association Response.
    Which works if the user defined Station MAC matches the one of the
    wlan ifc itself.
	
    :param ssid: Name of the SSID (ESSID)
    :return: -
    """
        if self.state != "Authenticated":
            print("Wrong connection state for Association Request: {0} "
                  "- should be Authenticated".format(self.state))
            return 1
 
        packet = Dot11(
            addr1=self.bssid,
            addr2=self.sta_mac,
            addr3=self.bssid, SC=0x0020) / Dot11AssoReq(
                cap=0x3114, listen_interval=0x00a) / Dot11Elt(
                    ID=0, info="{}".format(ssid))
		print("#########################################################")
		print("Sending following packet as Association:")
		print("#########################################################")
        packet.show()
		jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_assoc_resp,
            args=(result_queue,))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet, "AssoReq", ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()
 	
        if result_queue.get():
            self.state = "Associated"

############################################################################################################

    def send_eap_identity(self):
	"""
	Wait for an EAP Identity-Request and send the Identity
	"""
		if self.state != "Associated":
			print("Wrong Connection State for EAP Identity: {0} - should be 'Associated'".format(self.state))
			return 1

		#sniffed QoS-Data('\x00\x00')
		dot11_qos = Dot11QoS("\x00\x00")
		packet = Dot11( addr1=self.bssid,
            		addr2=self.sta_mac,
            		addr3=self.bssid, 
			subtype=8, type="Data", proto=0, FCfield="to-DS",SC=0x0030) / dot11_qos / LLC(dsap=0xaa,ssap=0xaa,ctrl=3) / SNAP(OUI=0x0, code=0x888e) / EAPOL(version=1,type=0) / EAP(code="Response",id=1,type="Identity",identity=self.eap_identity)
	
		print("#########################################################")
		print("Sending following packet as EAP-Identity:")
		print("#########################################################")
		packet.show2()

		jobs = list()
        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_eap_identity,
            args=(result_queue,))
        jobs.append(receive_process)
        send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet,None, ))
        jobs.append(send_process)
 
        for job in jobs:
            job.start()
        for job in jobs:
            job.join()

		#First check if EAP-Identity-Request has been found
        if result_queue.get():
            self.state = "Accepted" 
		#If also TLS Request has been found -> skip one state
		if result_queue.get():
			self.state = "TLS START"

############################################################################################################

    def scan_eap_tls_request(self):
	"""
	Wait for an EAP Identity-Request and send the Identity
	"""
		if self.state != "Accepted":
			print("Wrong Connection State for EAP_TLS Request: {0} - should be 'Accepted'".format(self.state))
			return 1

        result_queue = multiprocessing.Queue()
        receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_eap_tls_request,
            args=(result_queue,))
 
        receive_process.start()
        receive_process.join()
 	
        if result_queue.get():
            self.state = "TLS START"

############################################################################################################
	
    def send_eap_tls_client_hello(self):
	"""
	Generate Client_Hello and send it to the AP
	"""
		if self.state != "TLS START":
			print("Wrong Connection State for Client_Hello Message: {0} - should be 'TLS START'".format(self.state)) 
			return 1
	
		packet_head = Dot11(addr1=self.bssid ,addr2=self.sta_mac ,addr3=self.bssid ,type=2 ,subtype=8 , FCfield="to-DS", SC=0x0040 )/ Dot11QoS('\x00\x00')/LLC(dsap=0xaa,ssap=0xaa,ctrl=3)/ SNAP(OUI=0x0, code=0x888e) / EAPOL(version=1,type=0)
		#Supported Ciphersuites
		ciphersuites=[0x00ff,0xc02c,0xc02b,0xc024,0xc023,0xc00a,0xc009,0xc008,0xc030,0xc02f,0xc028,0xc027,0xc014,0xc013,0xc012,0x009d,0x009c,0x003d,0x003c,0x0035,0x002f,0x000a]
		#Supported EC Point Formats
		ec_point_formats=[0x00,0x01,0x02]
		#Supported Elliptic Curve groups -> Server will probably select secp256r1 (0x0017)
		ec_groups=[0x0017,0x0018,0x0019]
		#Supported signature Algorithms
		signature=[0x0401,0x0201,0x0501,0x0601,0x0403,0x0203,0x0503,0x0603]
		
		tls_ext_supported_formats = TLS_Ext_SupportedPointFormat(type=11, ecpl=ec_point_formats)
	
		tls_ext_supported_groups = TLS_Ext_SupportedGroups(type=10, groups=ec_groups)

		tls_ext_signature_algos = TLS_Ext_SignatureAlgorithms(type=13, sig_algs=signature)

		#May be optional
		tls_ext_heartbeat = TLS_Ext_Heartbeat(type=15, heartbeat_mode="peer_allowed_to_send")
	
		extension_packets = tls_ext_supported_formats / tls_ext_supported_groups / tls_ext_signature_algos / tls_ext_heartbeat
	
		tls_client_hello = TLSClientHello(version=0x0303, gmt_unix_time=1513255978, random_bytes='\xd3\x0c\xaej_P\x86\xa0\xe3!\x05$vY-6\x8aCN\xef+\xd2\xe5\xb9\x0b\xc9h\xd5',sidlen=0, sid="", ciphers=ciphersuites, complen=1, comp="null", ext=extension_packets)
	

		#TLS Packet Head:
		tls_payload = TLS(type="handshake", version="TLS 1.0", iv="", msg=tls_client_hello)
	
		print("#########################################################")
		print("Generated TLS Client_Hello:")
		print("#########################################################")
		tls_payload.show2()	
		#use show2() to calculate fields like cipherslen etc. for tls_data AND the full packet
	
		packet = packet_head / EAP_TLS(code="Response", id=2, type="EAP-TLS", L=0, M=0, S=0, reserved=0, tls_data=tls_payload)
	
		print("#########################################################")
		print("Full TLS Client_Hello Packet:")
		print("#########################################################")
		packet.show2()	
	
		#append tls_client_hello to handshake log for calc. hash over all messages later
		#without Record Layer!
		self.handshake_log = tls_payload[TLSClientHello]	


		result_queue = multiprocessing.Queue()
	
		send_process = multiprocessing.Process(
            target=self.mon_ifc.send_packet,
            args=(packet,None, ))
	
		receive_process = multiprocessing.Process(
            target=self.mon_ifc.search_eap_tls_server_hello,
            args=(result_queue,))
	
		receive_process.start()
	
		#Scapy can run into some problems when sniffing and sending is simultaniously started
		time.sleep(.250)
	
		send_process.start()

		send_process.join()
		receive_process.join()

		received_fragments = result_queue.get()
	
		tls_payload = ""	

		for packets in received_fragments:
			tls_payload = tls_payload + packets[EAP_TLS].tls_data

		server_hello = TLS(tls_payload)

		if not(server_hello.haslayer(TLSServerHelloDone)):
			print("Server Hello not fully received!")
			return 0	
	
		print("Parsed Server_Hello!")
		#Append the Server_Hello Layers to the handshake_log via scapy
		self.handshake_log = self.handshake_log / server_hello[TLSServerHello] / server_hello[TLSCertificate] / server_hello[TLSServerKeyExchange] / server_hello[TLSCertificateRequest] / server_hello[TLSServerHelloDone]
	
		#Remember current EAP-ID for next Packets
		self.current_id = result_queue.get()
	
		if(server_hello.haslayer(TLSServerHelloDone)):
			self.state = "TLS HANDSHAKE 1"
	
############################################################################################################
	
    def send_eap_tls_client_key(self):
	"""
	Generate Client_Certificate, Client_KeyExchange, Client_CertificateVerify, 
	Client_ChangeCipherSpec & FINISHED Message and send it to the server
	"""
		if self.state != "TLS HANDSHAKE 1":
			print("Wrong Connection State for Client_Key Message: {0} - should be 'TLS HANDSHAKE 1'".format(self.state)) 
			return 1
		
		#May have to move this to the _init_ field
		packet_head = Dot11(addr1=self.bssid ,addr2=self.sta_mac ,addr3=self.bssid ,type=2 ,subtype=8 , FCfield="to-DS" )/ Dot11QoS('\x00\x00')/LLC(dsap=0xaa,ssap=0xaa,ctrl=3)/ SNAP(OUI=0x0, code=0x888e) / EAPOL(version=1,type=0)	

		#---------------------------------------------------------------------------#

		x509_1 = X509()
		x509_1.parse(self.public_cert_file)

		x509_2 = X509()
		x509_2.parse(self.ca_certs_file)
		
		cert1 = x509_1.writeBytes()
		cert2 = x509_2.writeBytes()
		#Add 3 Bytes for every Certificate as Length-Field has to be included
		chainLength = len(cert1)+3+len(cert2)+3

		cert1_len_hex = "{:06x}".format(len(cert1))
		cert2_len_hex = "{:06x}".format(len(cert2))

		cert1_len = binascii.unhexlify(cert1_len_hex)
		cert2_len = binascii.unhexlify(cert2_len_hex)
		
				
		client_certs = cert1_len + cert1 + cert2_len + cert2
		#We use str() because client_certs is a byte-array
		client_cert_load = TLSCertificate(certslen=chainLength, certs=str(client_certs))

		print("#########################################################")
		print("Generating CLIENT CERTIFICATE PAYLOAD")
		print("#########################################################")
		client_cert_load.show2()

		client_cert = TLS(type="handshake", version="TLS 1.0", iv="", msg=client_cert_load)	
		
		print("#########################################################")
		print("Generating CLIENTCERTIFICATE")
		print("#########################################################")
		client_cert.show2()


		self.handshake_log = self.handshake_log / client_cert[TLSCertificate]	
		print("#################################################################################################")	
		#---------------------------------------------------------------------------#
		#Generating ClientKey
		curve = reg.get_curve("secp256r1")
		self.client_secret = random.getrandbits(256)
		client_pubKey = curve.g * self.client_secret
		
		#04 Prefix for "uncompressed" and "41" for length of pubKey as scapy cant parse it right
		pubKey_head = binascii.unhexlify("4104")
		#This one is for sending
		raw_full_client_pubKey = pubKey_head + long_to_bytes(client_pubKey.x) + long_to_bytes(client_pubKey.y)
		
		print("#########################################################")
		print("Generated following Coordinates:")
		print("X:")
		print(client_pubKey.x)
		print("Y:")
		print(client_pubKey.y)
		print("#########################################################")

		#Parsing ServerKey
		raw_full_server_pubKey = self.handshake_log[TLSServerKeyExchange].params.point
		#Remove "uncompressed" indicator
		full_server_pubKey = raw_full_server_pubKey[1:]	

		#splitting the x and y coordinates
		server_key_x_raw = full_server_pubKey[0:32]
		server_key_y_raw = full_server_pubKey[32:64]
		server_key_x = bytes_to_long(server_key_x_raw)
		server_key_y = bytes_to_long(server_key_y_raw)

		server_parse = ec.Point(curve, server_key_x, server_key_y)

		print("#########################################################")
		print("Parsed following Server Coordinates:")
		print("X:")
		print(server_parse.x)
		print("Y:")
		print(server_parse.y)
		print("#########################################################")
		
		#Calculating the pre-master-secret (Returned as a long)
		long_premaster = (server_parse * self.client_secret).x

		self.premaster = long_to_bytes(long_premaster)

		#Generating ClientKeyExchange Layer

		print("#########################################################")
		print("Generating CLIENTKEYEXCHANGE Payload:")
		print("#########################################################")
		client_key_load = TLSClientKeyExchange(exchkeys=Raw(load=raw_full_client_pubKey))
		client_key_load.show2()
		
		client_key = TLS(type="handshake", version="TLS 1.0", iv="", msg=client_key_load)
		print("#########################################################")
		print("Generating CLIENTKEYEXCHANGE")
		print("#########################################################")
		client_key.show2()

		self.handshake_log = self.handshake_log / client_key_load
			
		print("#################################################################################################")
		#---------------------------------------------------------------------------#
		
		#Generating CertificateVerify Layer	

		#Hash-Value Calculation
		temp = hashlib.md5()
		temp.update(str(self.handshake_log))
		m_string = temp.digest()

		temp = hashlib.sha1()
		temp.update(str(self.handshake_log))
		s_string = temp.digest()
		
		concat_string = m_string + s_string
		concat_string_hex = binascii.hexlify(concat_string)
		
		#Padding Calculation
		head = "0001"
		bottom = "00"
		body = ""
		for i in range(0,434):
			body = body + "F"
		
		#Combining Hash & Padding
		concat_string_build = head + body + bottom + concat_string_hex
		concat_string_raw = binascii.unhexlify(concat_string_build)	
		
		#Signing Message with M2Crypto using no_padding mode
		m2_key = RSA.load_key(self.private_key_file)
		signature_m2 = m2_key.private_encrypt(concat_string_raw, m2.no_padding)

		#Parsing the Certificate Verify Layer from Wireshark as Scapy has problems generating it
		certificate_verify_head = binascii.unhexlify("0f0001020100")
		#Works, as the signature has same length every time
		certificate_verify_load = TLSCertificateVerify(certificate_verify_head + signature_m2)
		
		certificate_verify = TLS(type="handshake", version="TLS 1.0", iv="", msg=certificate_verify_load)	
		
		print("#########################################################")
		print("Generated CERTIFICATEVERIFY")
		print("#########################################################")
		certificate_verify.show2()
		#Used for FINISHED Message later
		self.handshake_log = self.handshake_log / certificate_verify[TLSCertificateVerify]	
		print("#################################################################################################")
		#---------------------------------------------------------------------------#
		
		#Generate ChangeCipherSpec Message
		#IS NOT RELEVANT FOR FINISHED MESSAGE -> Therefore not saved to log
		
		cipher_spec_load = TLSChangeCipherSpec()
		cipher_spec = TLS(type="change_cipher_spec", version="TLS 1.0", iv="", msg=cipher_spec_load)
		
		print("#########################################################")
		print("Generated CHANGECIPHERSPEC")
		print("#########################################################")
		cipher_spec.show2()
		print("#################################################################################################")
		#---------------------------------------------------------------------------#

		#Via Scapy: gmt_unix_time + random_bytes = FULL Random_bytes
		parsed_time_client = "{0:02x}".format(self.handshake_log[TLSClientHello].gmt_unix_time).zfill(8)
		parsed_time_server = "{0:02x}".format(self.handshake_log[TLSServerHello].gmt_unix_time).zfill(8)	

		client_random = binascii.unhexlify(parsed_time_client) + self.handshake_log[TLSClientHello].random_bytes
		server_random = binascii.unhexlify(parsed_time_server) + self.handshake_log[TLSServerHello].random_bytes

		print("#########################################################")
		print("Parsed following random_bytes:")
		print("Client Random:")
		print(binascii.hexlify(client_random))
		print("Server Random:")
		print(binascii.hexlify(server_random))

		#master bitaray with length 48 Bytes
		self.master = tlslite.mathtls.calcMasterSecret((3,1), None, self.premaster, client_random, server_random)
		print("#########################################################")	
		print("Calculated Master-Secret:")
		print(binascii.hexlify(str(self.master)))
		print("#########################################################")
		#---------------------------------------------------------------------------#

		#Calculate FINISHED Message via tlslite
		
		#handshakeHash = MD5(handshake_messages) + SHA-1(handshake_messages)
		#No Padding like RSA Signatur PKCS!
		#Method expects handshakeHash as byteArray -> makes no difference here

		print("#################################################################################################")		

		#Hash-Value Calculation exactly as in ClientVerify but now with ClientVerify appended to the log
		temp = hashlib.md5()
		temp.update(str(self.handshake_log))
		m_string = temp.digest()

		temp = hashlib.sha1()
		temp.update(str(self.handshake_log))
		s_string = temp.digest()
		
		handshakeHash = m_string + s_string	
		
		#content of FINISHED-Message:
		verifyData = tlslite.mathtls.PRF(self.master, "client finished", handshakeHash, 12)

		#Creating Header for Handshake-Layer (NOT Record!):
		#14 -> ContentType 20 = FINISHED
		#00000C -> Length of Content = 12 Bytes = VerifyData.length	
		header_hex = "1400000C"
		header = binascii.unhexlify(header_hex)
		finished_payload = header + verifyData
		
		#Generating Key-Material to calculate required Keys for Sending:
		#Required: client_write_MAC, client_write_key , client_write_IV
		#client_write_MAC with SHA-1 -> 20 Bytes
		#client_write_key with AES-256 -> 256 Bit -> 32 Bytes
		#client/server IV still uses 128 bit blocks, so 128-bit IV -> 16 Bytes
		#key_block = PRF(master_secret, "key expansion", server_random + client_random)
		#KEYLENGTH = 20 (MAC) + 20(Server MAC) + 32 (AES256) + 32 (AES256 Server) + 16 (IV) + 16 (Server IV) = 136 bytes
		#Order of Keys : client_write_MAC , server_write_MAC, client_write_key, server_write_key, client_write_IV, server_write_IV
		keys = tlslite.mathtls.PRF(self.master, "key expansion", server_random + client_random, 136)

		#20 Bytes per Key (SHA-1)
		client_mac_key = keys[0:20]
		server_mac_key = keys[20:40]
		
		#32 Bytes per Key (AES-256)
		client_write_key = keys[40:72]
		server_write_key = keys[72:104]

		#16 Bytes per Key (AES-CBC)
		client_write_iv = keys[104:120]
		server_write_iv = keys[120:136]
		
		print("#########################################################")
		print("Client_Mac_Key:")
		print(binascii.hexlify(str(client_mac_key)))
		print("Server_Mac_Key:")
		print(binascii.hexlify(str(server_mac_key)))
		print("Client_Write_Key:")
		print(binascii.hexlify(str(client_write_key)))	
		print("Server_Write_Key:")
		print(binascii.hexlify(str(server_write_key)))
		print("Client_Write_IV:")
		print(binascii.hexlify(str(client_write_iv)))
		print("Server_Write_IV:")	
		print(binascii.hexlify(str(server_write_iv)))
		print("#########################################################")

		#HMAC_SHA1(client_write_mac_key, seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length + TLSCompressed.fragment)	
		#client_write_mac_key = get from master_secret
		#seq_num = 0 as 8 Bytes -> 0x0000000000000000
		#TLSCompressed.type = 0x16 = 22 from Record-Layer
		#TLSCompressed.version = 0x0301
		#TLSCompressed.length = length(header+verifyData) -> 0x0010 because we have 16 bytes
		#TLSCompressed.fragment = header+verifyData
		
		#label = seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length
		label = binascii.unhexlify("0000000000000000") + binascii.unhexlify("16") + binascii.unhexlify("0301") + binascii.unhexlify("0010")
		fin_mac = hmac.new(client_mac_key, label+finished_payload, hashlib.sha1).digest()
		
		#Padding: (We need 12 Bytes Padding, so 11-Bytes with Value '11' and one Padding-Length-Byte with Value '11')
		padding_hex = ""
		for i in range(0,11):
			padding_hex = padding_hex + "0B"
		
		#Adding the Padding-Length 
		padding_hex = padding_hex + "0B"
		padding = binascii.unhexlify(padding_hex)

		#Encrypt the Layer:
		#USING IN THIS ORDER : finished_payload + fin_mac + padding
		encryptor = EVP.Cipher(alg="aes_256_cbc", key=client_write_key, iv=client_write_iv, op=1, padding=0)	

		encrypted_payload = encryptor.update(finished_payload + fin_mac + padding)
		encrypted_payload += encryptor.final()	
		
		#Generate TLS Record Layer:
		finished_head = binascii.unhexlify("1603010030")
		finished = finished_head + encrypted_payload
		
		print("#########################################################")
		print("Generated FINISHED")
		print("#########################################################")
		#---------------------------------------------------------------------------#
		
		#Construct the whole packet:
		packet_tls = str(client_cert) + str(client_key) + str(certificate_verify) + str(cipher_spec) + str(finished)

		#Fragment the packet: (In this Case - Fragments of the size of about 1266 Bytes)
		fragment1_payload = packet_tls[0:1266]
		fragment2_payload = packet_tls[1266:2532]
		fragment3_payload = packet_tls[2532:]

		#EAP Packet Head -> Remember ID regarding Fragmentation and "More Fragments"-Flag
		packet1 = packet_head / EAP_TLS(code="Response", id=(self.current_id - 1), type="EAP-TLS", L=1, M=1, S=0, reserved=0, tls_message_len=len(packet_tls) ,tls_data=fragment1_payload)
		packet1[Dot11].SC = 0x0090
		packet2 = packet_head / EAP_TLS(code="Response", id=self.current_id , type="EAP-TLS", L=1, M=1, S=0, reserved=0, tls_message_len=len(packet_tls) ,tls_data=fragment2_payload)
		packet2[Dot11].SC = 0x00A0
		self.current_id += 1
		packet3 = packet_head / EAP_TLS(code="Response", id=self.current_id , type="EAP-TLS", L=1, M=0, S=0, reserved=0, tls_message_len=len(packet_tls) ,tls_data=fragment3_payload)
		packet3[Dot11].SC = 0x00B0

		print("#########################################################")
		print("Generated 3 Fragments:")
		print("#########################################################")
		print("Fragment 1 :")
		packet1.show2()
		print("#########################################################")
		print("Fragment 2 :")
		packet2.show2()
		print("#########################################################")
		print("Fragment 3 :")
		packet3.show2()
		print("#########################################################")
		
		fragments = list()
		#First packet will be sent directly!
		fragments.append(packet2)
		fragments.append(packet3)	

		#Send it away!
		result_queue = multiprocessing.Queue()
		
		send_process = multiprocessing.Process(
				target=self.mon_ifc.send_packet,
				args=(packet1,None, ))	

		send_and_receive_process = multiprocessing.Process(
				target=self.mon_ifc.search_eap_tls_server_response,
				args=(result_queue, fragments,))
		
		send_and_receive_process.start()
		time.sleep(.250)
		send_process.start()
		
		send_process.join()
		send_and_receive_process.join()

			if result_queue.get():
				self.state = "TLS SUCCESS"


    def send_final_eap_tls(self):
	"""
	Send EAP-Response to the Server to finish Handshake (proto-method)
	"""
		packet_head = Dot11(addr1=self.bssid ,addr2=self.sta_mac ,addr3=self.bssid ,type=2 ,subtype=8 , FCfield="to-DS" )/ Dot11QoS('\x00\x00')/LLC(dsap=0xaa,ssap=0xaa,ctrl=3)/ SNAP(OUI=0x0, code=0x888e) / EAPOL(version=1,type=0)	

		self.current_id += 1
		packet = packet_head / EAP_TLS(code="Response", id=self.current_id, type="EAP-TLS", L=0, M=0, S=0, reserved=0)
		packet[Dot11].SC = 0x00C0

		send_process = multiprocessing.Process(
				target=self.mon_ifc.send_packet,
				args=(packet,None, ))

		send_process.start()
		send_process.join()
	
	
############################################################################################################
#--------------------------------------------------------------------------------------------------------------------------------------
############################################################################################################
#Method based on code from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/"
def main():
	monitor_ifc="wlan0"
	sta_mac="a8:a7:95:6a:94:c9" # MAC of your wifi-card
	bssid = "00:fe:c8:76:ba:c0" # edit for nearest Router-MAC

	private_key_file = "dziebart.key.pem"
	public_cert_file = open("dziebart.crt.pem").read()
	ca_certs_file = open("cacerts.cer").read()
	eap_identity = #EAP Identity example@uni-paderborn.de

	conf.iface = monitor_ifc

	#For Speed-Up after Authentication to the AP
	main_socket = conf.L3socket(iface=monitor_ifc)
	
	mon_ifc = Monitor(monitor_ifc, sta_mac.lower(), bssid.lower(), main_socket)
	connection = ConnectionPhase(mon_ifc, sta_mac, bssid, private_key_file, public_cert_file, ca_certs_file, eap_identity)


	connection.send_authentication()

	if connection.state == "Authenticated":
		print("STA is authenticated to the AP!")
	else:
		print("STA is NOT authenticated to the AP!")
		return 1

	time.sleep(.250)

	connection.send_assoc_request(ssid="eduroam")
	
	if connection.state == "Associated":
		print("STA is connected to the AP!")
	else:
		print("STA is NOT connected to the AP!")
		return 1

	connection.send_eap_identity()

	if connection.state == "Accepted":
		print("EAP Identity-Request received and Identity sent!")
	elif not(connection.state == "TLS START"):
		print("No EAP Identity-Request received!")
		return 1
	
	#Check for Skip (when Sniffer in Method already detected EAP-TLS Request)
	if not(connection.state == "TLS START"):	
		connection.scan_eap_tls_request()
	
	if connection.state == "TLS START":
		print("EAP TLS Request found!")
	else:
		print("EAP TLS Request not found!")
		return 1
	
	connection.send_eap_tls_client_hello()
	
	if connection.state == "TLS HANDSHAKE 1":
		print("Exchanged Client_Hello and Server_Hello!")
	else:
		print("Problem with parsing Server_Hello or not received!")
		return 1

	connection.send_eap_tls_client_key()

	if connection.state == "TLS SUCCESS":
		print("Server accepted Client TLS Answer!")
	else:
		print("Server did not accept Client TLS Answer!")
		return 1

	connection.send_final_eap_tls()

	print("Full EAP-TLS Handshake successfull!")

	main_socket.close()

if __name__ == "__main__":
	sys.exit(main())
	

