#Based on "Fake a WLAN Connection via Scapy" found here : https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/
from scapy.all import *
import multiprocessing
 
#Class created by P. Ebbecke on "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/"
#Modified by D. Ziebart to use the correct supported_rates at uni paderborn
class Dot11EltRates(Packet):
    """
    Our own definition for the supported rates field
    """
    name = "802.11 Rates Information Element"
    # Our Test AP has the rates 6, 9, 12 (B), 18, 24, 36, 48 and 54, with 12
    # Mbps as the basic rate - which does not have to concern us.
    # Eduroam Cisco uses : 5.5 (B), 6, 9(B), 11(B), 12, 18, 24, 36, 48, 54
    supported_rates = [0x8b, 0x96, 0x0c, 0x92, 0x18, 0x24, 0x30, 0x48]
 
    fields_desc = [
        ByteField("ID", 1),
        ByteField("len", len(supported_rates))
        ]
 
    for index, rate in enumerate(supported_rates):
        fields_desc.append(ByteField("supported_rate{0}".format(
            index + 1), rate))
			
class Dot11EltExtRates(Packet):
	"""
	Extended Rates appended to the packet, as seen by other sniffed packets
	"""
	name = "802.11 Extended Rates Information Element"
	ext_supported_rates = [0x60, 0x6c]
	
	fields_desc = [ByteField("ID",50),ByteField("len",len(ext_supported_rates))]
	
	for index, rate in enumerate(ext_supported_rates):
		fields_desc.append(ByteField("ext_supported_rate{0}".format(index+1), rate))
	
#Monitor based on "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/" but modified and expanded
class Monitor:
    def __init__(self, mon_ifc, sta_mac, bssid, socket):
        """
        :param mon_ifc: WLAN interface to use as a monitor
        :param sta_mac: MAC address of the STA
        :param bssid: BSSID of the AP to attack
        """
        self.mon_ifc = mon_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
	#---------------------------------
		self.auth_found = False
		self.assoc_found = False
		self.eap_identity_found = False
		self.eap_tls_request_found = False
		self.eap_tls_last_fragment = False
		self.eap_tls_fragments_sent = False
		self.eap_tls_success = False
		self.eap_tls_packet_fragments = list()
		self.eap_tls_id_counter = 3 # 3 because we already exchanged Identity and Client_Hello after using the id_counter for the first time
		self.send_socket = socket
	#---------------------------------
        self.dot11_rates = Dot11EltRates()
		self.dot11_ext_rates = Dot11EltExtRates()
		#RSNInfo appended by hexdump, as irrelevant for EAP-TLS Testing & required for WPA2
		self.dot11_rsn_info = rsn = Dot11Elt(ID='RSNinfo', info=(
		'\x01\x00'	     	 #RSN Version: 1
		'\x00\x0f\xac\x02'   #Group Cipher Suite: 00-0f-ac TKIP
		'\x01\x00'	     	 #1 Pairwise Cipher Suite
		'\x00\x0f\xac\x04'   #Pairwise Cipher Suite: 00-0f-ac AES
		'\x01\x00'	     	 #1 Auth Key Management Suite
		'\x00\x0f\xac\x01'   #Auth Key Management Suite: 00-0f-ac WPA
		'\x00\x00'))	     #No additional RSN capabilities

		packet_head = Dot11(addr1=self.bssid ,addr2=self.sta_mac ,addr3=self.bssid ,type=2 ,subtype=8 , FCfield="to-DS" )/ Dot11QoS('\x00\x00')/LLC(dsap=0xaa,ssap=0xaa,ctrl=3)/ SNAP(OUI=0x0, code=0x888e) / EAPOL(version=1,type=0)
		packet_body = EAP_TLS(code="Response", type="EAP-TLS", L=0, M=0, S=0, reserved=0)
		self.ACK_packet = packet_head / packet_body

		self.sc_numbers = [0x0050, 0x0060, 0x0070, 0x0080]

		self.ACK_packet.show2()
		print("Monitor initialized!")
		print("Initialized ACK Packet!")
	 
#--------------------------------------------------------------------------------------------------------------------------------------------------------
#Method taken from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/"  and modified
    def send_packet(self, packet, packet_type=None):
        """
        Send and display a packet.
 
        :param packet_type: Specific types require
        :param packet:
        :return:
        """
        # Send out the packet
		print("Sending out 1 Packet.")
        if packet_type is None:
            self.send_socket.send(packet)
        elif packet_type == "AssoReq":
			self.dot11_ext_rates /= self.dot11_rsn_info
			self.dot11_rates /= self.dot11_ext_rates
            packet /= self.dot11_rates
            self.send_socket.send(packet)
        else:
            print("Packet Type '{0}' unknown".format(packet_type))

#--------------------------------------------------------------------------------------------------------------------------------------------------------
#Method taken from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/"  
    def check_auth(self, packet):
        """
        Try to find the Authentication from the AP
 
        :param packet: sniffed packet to check for matching authentication
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
 
        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.auth_found = True
            print("Detected Authentication from Source {0}".format(
                seen_bssid))
        return self.auth_found

#-------------------------------------------------------------------------------------------------------------------------------------------------------- 
#Method taken from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/" 
    def check_assoc(self, packet):
        """
        Try to find the Association Response from the AP
 
        :param packet: sniffed packet to check for matching association
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
 
        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.assoc_found = True
            print("Detected Association Response from Source {0}".format(
                seen_bssid))
        return self.assoc_found

#--------------------------------------------------------------------------------------------------------------------------------------------------------
	
    def check_eap_identity(self, packet):
		"""
		Try to find the EAP-Identity-Request from the AP & detect early EAP TLS Request
		:param packet: sniffed packet to check for matching EAP type
		"""
		seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
	
		if self.bssid == seen_bssid and self.bssid == seen_sender and self.sta_mac == seen_receiver and (packet[EAP].code == 1):
			self.eap_identity_found = True
			print("Detected EAP Identity Request from Source {0}".format(seen_bssid))
		if self.bssid == seen_bssid and self.bssid == seen_sender and self.sta_mac == seen_receiver and (packet.haslayer(EAP_TLS)):	
			self.eap_tls_request_found = True
			print("Also detected prematurely EAP TLS Request!")		
	
		return self.eap_identity_found

#--------------------------------------------------------------------------------------------------------------------------------------------------------

    def check_eap_tls_request(self, packet):
		"""
		Try to find the EAP_TLS-Request from the AP
		:param packet: sniffed packet to check for matching EAP type
		"""
		seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
	
		if self.bssid == seen_bssid and self.bssid == seen_sender and self.sta_mac == seen_receiver and (packet[EAP].code == 1):
			print("Detected EAP TLS Request from Source {0}".format(seen_bssid))
			self.eap_tls_request_found = True

		return self.eap_tls_request_found

#--------------------------------------------------------------------------------------------------------------------------------------------------------

    def check_eap_tls_server_fragment(self, packet):
		"""
		Check received EAP_TLS Fragments from the AP to determine if more 
		Fragments are being send or the whole packet has been sent. 
		Additionally sends an EAP_TLS Response functioning as an ACK to the AP
		:param packet: sniffed packet to check for matching attributes
		"""
		seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3	
	
		if self.bssid == seen_bssid and self.bssid == seen_sender and self.sta_mac == seen_receiver and (packet[EAP_TLS].code == 1) and (packet[EAP_TLS].id == self.eap_tls_id_counter):
			print("Detected EAP_TLS Request from Server!")
			self.eap_tls_packet_fragments.append(packet)
			self.eap_tls_id_counter += 1
			#Each received fragment means that the next packet will have the ID+1
		
			if (packet[EAP_TLS].M == 1):
				#More Fragments to come!
				self.ACK_packet[EAP_TLS].id= packet[EAP_TLS].id
				self.ACK_packet[Dot11].SC = self.sc_numbers[0]
				del self.sc_numbers[0]

				print("Generating EAP_TLS ACK ...")
				#time.sleep(1)
				#self.send_packet(self.ACK_packet,)
				#Testing Purposes and Retransmissiob
				#self.send_packet(self.ACK_packet,)
				self.send_socket.send(self.ACK_packet)
			else:
				#All Fragments received!
				print("Last Fragment received!")
				self.eap_tls_last_fragment = True
	

		return self.eap_tls_last_fragment

#--------------------------------------------------------------------------------------------------------------------------------------------------------	

    def check_eap_tls_server_response(self, packet):
		"""
		Send EAP_TLS Client fragments and then search for Server Responses
		to send more framents.
		:param packet: sniffed packet to check for matching attributes
		"""
		seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3

		if self.bssid == seen_bssid and self.bssid == seen_sender and self.sta_mac == seen_receiver and (packet[EAP_TLS].code == 1) and (packet[EAP_TLS].id == self.eap_tls_id_counter):
		
			if(self.eap_tls_fragments_sent):
				self.eap_tls_success = True
				return self.eap_tls_success
				
			self.eap_tls_id_counter += 1		
			print("Found EAP-TLS Response from Server with matching ID!")
			#self.send_packet(self.eap_tls_packet_fragments[0],)
			self.send_socket.send(self.eap_tls_packet_fragments[0])
			del self.eap_tls_packet_fragments[0]
			print("Sent EAP-TLS Fragment!")
		
			if not self.eap_tls_packet_fragments:
				self.eap_tls_fragments_sent = True

		return self.eap_tls_success
			
	
#--------------------------------------------------------------------------------------------------------------------------------------------------------
#Method taken from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/" 
    def search_auth(self, mp_queue):
		print("#########################################################")
		print("\nScanning max 5 seconds for Authentication from BSSID {0}".format(self.bssid))
		print("#########################################################")
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11Auth),
              stop_filter=self.check_auth,
              timeout=5)
        mp_queue.put(self.auth_found)

#--------------------------------------------------------------------------------------------------------------------------------------------------------
#Method taken from "https://wlan1nde.wordpress.com/2016/08/24/fake-a-wlan-connection-via-scapy/" 
    def search_assoc_resp(self, mp_queue):
		print("#########################################################")
		print("\nScanning max 5 seconds for Association Response from BSSID {0}".format(self.bssid))
		print("#########################################################")
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11),
              stop_filter=self.check_assoc,
              timeout=5)
        mp_queue.put(self.assoc_found)

#--------------------------------------------------------------------------------------------------------------------------------------------------------

    def search_eap_identity(self, mp_queue):
		print("#########################################################")
		print("\nScanning max 5 seconds for EAP Identity-Request from BSSID {0}".format(self.bssid))
		print("#########################################################")	
		sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(EAP), stop_filter=self.check_eap_identity, timeout=5)
		mp_queue.put(self.eap_identity_found)
		mp_queue.put(self.eap_tls_request_found)

#--------------------------------------------------------------------------------------------------------------------------------------------------------

    def search_eap_tls_request(self, mp_queue):
		print("#########################################################")
		print("\nScanning max 3 seconds for EAP TLS Request from BSSID {0}".format(self.bssid))
		print("#########################################################")
		sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(EAP_TLS), stop_filter=self.check_eap_tls_request, timeout=3)
		mp_queue.put(self.eap_tls_request_found)

#--------------------------------------------------------------------------------------------------------------------------------------------------------

    def search_eap_tls_server_hello(self, mp_queue):
		print("#########################################################")
		print("\nScanning max 15 seconds for EAP-TLS Server_Hello Fragments from BSSID {0}".format(self.bssid))
		print("#########################################################")
		sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(EAP_TLS), stop_filter=self.check_eap_tls_server_fragment, timeout=15)
		#Put Packet-List in queue to read information in main script
		mp_queue.put(self.eap_tls_packet_fragments)
		mp_queue.put(self.eap_tls_id_counter)

#--------------------------------------------------------------------------------------------------------------------------------------------------------
    def search_eap_tls_server_response(self, mp_queue, fragments):
		print("#########################################################")
		print("\nScanning max 15 seconds for EAP-TLS Server EAP Responses from BSSID {0} and sending Fragments".format(self.bssid))
		print("#########################################################")
		self.eap_tls_packet_fragments = fragments
		self.eap_tls_id_counter = fragments[0][EAP_TLS].id #The first ACK we search for uses the same ID as our response to it
		sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(EAP_TLS), stop_filter=self.check_eap_tls_server_response, timeout=15)
		mp_queue.put(self.eap_tls_success)
	
