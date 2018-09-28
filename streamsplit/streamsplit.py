#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  streamsplit.py v0.1
#  
#  Copyright 2018 J.A. Schalow ,schalowj@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import dpkt
import struct 
import datetime
import time
import shelve
import os
import argparse

PCAP_GLOBAL_HEADER_FMT = '@ I H H i I I I '
BUFFER_SIZE = 100

# Global Header Values
PCAP_MAGICAL_NUMBER = 2712847316
PCAP_MJ_VERN_NUMBER = 2
PCAP_MI_VERN_NUMBER = 4
PCAP_LOCAL_CORECTIN = 0
PCAP_ACCUR_TIMSTAMP = 0
PCAP_MAX_LENGTH_CAP = 65535
PCAP_DATA_LINK_TYPE = 1

########Stream Status Constants#####
STREAM_ACTIVE = 1
STREAM_CLOSING_S1 = 2
STREAM_CLOSING_S2 = 3
STREAM_CLOSING_S3 = 4
STREAM_CLOSED = 5

#########TCP Flags##################
SYN = 0x02
ACK = 0x10
FIN = 0x01
RST = 0x04
SYNACK = 0x12
FINACK = 0x11
RSTACK = 0x14
ECN_MASK = 0x3f



########TCP Stream Class################

class TCPStream(object):
	
	def __init__(self, stream_id, h1_ip, h1_port, h2_ip, h2_port, start_time=None, packet_count=None, total_bytes=None, stream_status=None):
		 self.stream_matcher = format_stream_matcher(h1_ip, h1_port, h2_ip, h2_port) 
		 self.stream_id = stream_id
		 self.h1_ip = h1_ip 
		 self.h1_port = h1_port
		 self.h2_ip = h2_ip
		 self.h2_port = h2_port 
		 self.start_time = start_time 
		 self.end_time = start_time
		 self.packet_count = packet_count 
		 self.total_bytes = total_bytes
		 self.stream_status = stream_status
		 self.filename = None
	


########Handshake Buffer##################

class HandshakeBuffer(object):

	def __init__(self, h1_ip, h1_port, h2_ip, h2_port, syn_ts, syn_buffer):
		self.syn_buf = syn_buffer
		self.syn_ts = syn_ts
		self.synack_buf = None
		self.synack_ts = None

########Stream Index Class################

class StreamIndex(object):
	
	def __init__(self,export_man=None):
		self.streams={}
		self.active_streams={}
		self.handshakes={}
		self.export = export_man
		self.next_stream_id = 0
	
	def handshake_syn(self, h1_ip, h1_port, h2_ip, h2_port, ts, buf):
		new_handshake = HandshakeBuffer(h1_ip, h1_port, h2_ip, h2_port, ts, buf)
		self.handshakes[format_stream_matcher(h1_ip, h1_port, h2_ip, h2_port)] = new_handshake

	def handshake_synack(self, h1_ip, h1_port, h2_ip, h2_port, ts, buf):
		handshake_id = format_stream_matcher(h1_ip, h1_port, h2_ip, h2_port)
		if handshake_id in self.handshakes:
			self.handshakes[handshake_id].synack_buf = buf
			self.handshakes[handshake_id].synack_ts = ts

	def handshake_ack(self, h1_ip, h1_port, h2_ip, h2_port, ts, buf):
		handshake_id = format_stream_matcher(h1_ip, h1_port, h2_ip, h2_port)
		if handshake_id in self.handshakes and self.handshakes[handshake_id].synack_ts is not None:
			h = self.handshakes[handshake_id]
			del self.handshakes[handshake_id]
			self.update_stream(h1_ip, h1_port, h2_ip, h2_port, h.syn_ts, h.syn_buf, start_time=h.syn_ts, end_time=ts, packet_count=3, total_bytes=(len(h.syn_buf) + len(h.synack_buf) + len(buf)), stream_status=STREAM_ACTIVE)
			self.update_stream(h1_ip, h1_port, h2_ip, h2_port, h.synack_ts, h.synack_buf)
			self.update_stream(h1_ip, h1_port, h2_ip, h2_port, ts, buf)
			return h
		else:
			return None
			
	def handshake_flush(self, h1_ip, h1_port, h2_ip, h2_port):
		handshake_id = format_stream_matcher(h1_ip, h1_port, h2_ip, h2_port)
		if handshake_id in self.handshakes:
			h = self.handshakes[handshake_id]
			del self.handshakes[handshake_id]
			return h
		else:
			return None
	
	def update_stream(self, h1_ip, h1_port, h2_ip, h2_port, ts, buf, start_time=None, end_time=None, packet_count=None, total_bytes=None, stream_status=None):
		stream_id = self._find_active_stream(h1_ip, h1_port, h2_ip, h2_port)
		if stream_id is None:
			stream_id = self.next_stream_id
			self.next_stream_id += 1
			new_stream = TCPStream(stream_id,h1_ip, h1_port, h2_ip, h2_port)
			if self.export is not None: new_stream.filename = get_exp_file_name(stream_id, h1_ip, h1_port, h2_ip, h2_port)
			self.streams[stream_id] = new_stream
			
		if start_time is not None: 
			self.streams[stream_id].start_time=start_time
		if end_time is not None: 
			self.streams[stream_id].end_time=end_time
		if packet_count is not None: 
			self.streams[stream_id].packet_count=packet_count
		if total_bytes is not None: 
			self.streams[stream_id].total_bytes=total_bytes 
		if stream_status is not None:
			if self.streams[stream_id].stream_status != stream_status:
				self.streams[stream_id].stream_status=stream_status
				if stream_status == STREAM_ACTIVE: self.active_streams[self.streams[stream_id].stream_matcher] = stream_id
				if stream_status == STREAM_CLOSED: 
					del self.active_streams[self.streams[stream_id].stream_matcher]
					if self.export is not None: self.export.flush_buffer(get_exp_file_name(stream_id, h1_ip, h1_port, h2_ip, h2_port))
		if self.export is not None:
			self.export.export_packet(self.streams[stream_id].filename, ts, buf)
	
	def get_active_stream(self,	h1_ip, h1_port, h2_ip, h2_port):
		
		sid = self._find_active_stream(h1_ip, h1_port, h2_ip, h2_port)	
		if sid is not None:
			return self.streams[sid]
		else:
			return None
			
	def _find_active_stream(self,h1_ip, h1_port, h2_ip, h2_port):
		stream_matcher = format_stream_matcher(h1_ip, h1_port, h2_ip, h2_port)
		if stream_matcher in self.active_streams:
			return self.active_streams[stream_matcher]
		else:
			return None
			
########Packet Handler Class################

class PacketHandler(object):
	
	def __init__(self, stream_idx, host_list=[]):
		self.stream_idx = stream_idx
		self.host_list = host_list
	
	def handle_packet(self,ts, buf):
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		if isinstance(ip, dpkt.ip.IP):
			tcp = ip.data
			if isinstance(tcp, dpkt.tcp.TCP):		
				if self._filter(ip,tcp):
					if self._is_syn(tcp):
						self._process_syn(ip,tcp,ts,buf)
					elif self._is_synack(tcp):
						self._process_synack(ip,tcp,ts,buf)
					elif self._is_ack(tcp):
						self._process_ack(ip,tcp,ts,buf)
					elif self._is_fin(tcp):
						self._process_fin(ip,tcp,ts,buf)			
					elif self._is_finack(tcp):
						self._process_finack(ip,tcp,ts,buf)
					elif self._is_rst_or_rstack(tcp):
						self._process_rst_or_rstack(ip,tcp,ts,buf)	
					else:
						self._process_other(ip,tcp,ts,buf)
							

	def _process_syn(self,ip,tcp,ts,buf):
		self.stream_idx.handshake_syn(ip.src, tcp.sport, ip.dst, tcp.dport, ts,buf)

	def _process_synack(self,ip,tcp,ts,buf):
		self.stream_idx.handshake_synack(ip.src, tcp.sport, ip.dst, tcp.dport, ts,buf)
			
	def _process_ack(self,ip,tcp,ts,buf):
		my_stream = self.stream_idx.get_active_stream(ip.src, tcp.sport, ip.dst, tcp.dport)
		if my_stream is None:		
			self.stream_idx.handshake_ack(ip.src, tcp.sport, ip.dst, tcp.dport, ts,buf)
		elif my_stream.stream_status == STREAM_CLOSING_S3:
			self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1), stream_status=STREAM_CLOSED)
		else:
			self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1))						
			
	def _process_fin(self,ip,tcp,ts,buf):
		my_stream = self.stream_idx.get_active_stream(ip.src, tcp.sport, ip.dst, tcp.dport)
		if my_stream is not None:
			if my_stream.stream_status == STREAM_ACTIVE:
				self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,ip.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1), stream_status=STREAM_CLOSING_S1)
			elif my_stream.stream_status == STREAM_CLOSING_S2:
				self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,ip.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1), stream_status=STREAM_CLOSING_S3)
			else:
				self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,ip.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1))
				
	def _process_finack(self,ip,tcp,ts,buf):
		my_stream = self.stream_idx.get_active_stream(ip.src, tcp.sport, ip.dst, tcp.dport)
		if my_stream is not None:
			if my_stream.stream_status == STREAM_CLOSING_S1:
				self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,ip.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1), stream_status=STREAM_CLOSING_S3)
			else:
				self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1))
				
	def _process_rst_or_rstack(self,ip,tcp,ts,buf):
		my_stream = self.stream_idx.get_active_stream(ip.src, tcp.sport, ip.dst, tcp.dport)
		if my_stream is not None:
			self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1), stream_status=STREAM_CLOSED)

	def _process_other(self,ip,tcp,ts,buf):
		my_stream = self.stream_idx.get_active_stream(ip.src, tcp.sport, ip.dst, tcp.dport)
		if my_stream is not None:		
			self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,ts,buf,end_time=ts,total_bytes=(my_stream.total_bytes+len(buf)),packet_count=(my_stream.packet_count + 1))						
		elif len(tcp.data) > 0:
			h = self.stream_idx.handshake_flush(ip.src,tcp.sport,ip.dst,tcp.dport)
			pkt_cnt = 1
			if h is not None:
				pkt_cnt = 2
				self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,h.syn_ts,h.syn_buf,start_time=ts,end_time=ts,total_bytes=len(h.syn_buf),packet_count=pkt_cnt, stream_status=STREAM_ACTIVE)
				if h.synack_ts is not None:
					pkt_cnt = 3
					self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,h.synack_ts,h.synack_buf,total_bytes=len(h.synack_buf))
			self.stream_idx.update_stream(ip.src,tcp.sport,ip.dst,tcp.dport,ts,buf,start_time=ts,end_time=ts,total_bytes=len(buf),packet_count=pkt_cnt, stream_status=STREAM_ACTIVE)
			
	def _filter(self,ip,tcp):
		if len(self.host_list) == 0: return True
		h1_str = self._host_string(ip.src, tcp.sport)
		h2_str = self._host_string(ip.dst, tcp.dport)
		h1_any_prt = self._host_string(ip.src, 'any')
		h2_any_prt = self._host_string(ip.dst, 'any')
		h1_any_ip = self._host_string('any', tcp.sport)
		h2_any_ip = self._host_string('any', tcp.dport)
		
		
		h1_ok = (h1_str in self.host_list) or (h1_any_prt in self.host_list) or (h1_any_ip in self.host_list)
		h2_ok = (h2_str in self.host_list) or (h2_any_prt in self.host_list) or (h2_any_ip in self.host_list)
		any_ok = ("any:any" in self.host_list)
		
		if (h1_ok and h2_ok) or (any_ok and h1_ok) or (any_ok and h2_ok):
			return True
		else:
			return False

	def _host_string(self, h_ip, h_port):
		if h_ip != 'any':
			ipfields = struct.unpack("<BBBB", h_ip)
			return str(ipfields[0]) + "." + str(ipfields[1]) + "." + str(ipfields[2]) + "." + str(ipfields[3]) + ":" + str(h_port)
		else:
			return "any:" + str(h_port)
	
			
	def _is_syn(self,tcp):
		if (tcp.flags & ECN_MASK == SYN):
			return True;
		else:
			return False;

	def _is_synack(self,tcp):
		if (tcp.flags & ECN_MASK == SYNACK):
			return True;
		else:
			return False;

	def _is_ack(self,tcp):
		if (tcp.flags & ECN_MASK == ACK):
			return True;
		else:
			return False;

	def _is_fin(self,tcp):
		if (tcp.flags & ECN_MASK == FIN):
			return True;
		else:
			return False;

	def _is_finack(self,tcp):
		if (tcp.flags & ECN_MASK == FINACK):
			return True;
		else:
			return False;
			
	def _is_rst_or_rstack(self,tcp):
		if (tcp.flags & ECN_MASK == RSTACK) or (tcp.flags & ECN_MASK == RST):
			return True;
		else:
			return False;
	

########PCAP Reader Class################

class PCAPReader(object):

	def __init__(self,host_list=[]):
		self.host_list = host_list
				

	#Process the PCAP
	def process_pcap(self, mypcap, export=True):
		try:
			f = open(mypcap)
			pcap = dpkt.pcap.Reader(f)
		except:
			print >>2, "[ERROR] Unable to open PCAP file (" + mycap +")."
			sys.exit(1)
			
		e = None
		if export:
			e = ExportManager(mypcap)
			
		handler = PacketHandler(StreamIndex(e), self.host_list)
		processed = 0
		for ts, buf in pcap:
			handler.handle_packet(ts, buf)
		if handler.stream_idx.export is not None: handler.stream_idx.export.flush_all_buffers()
		return handler.stream_idx	

########PCAP Writer Class################

class PCAPWriter:

	def __init__(self, filename, link_type=PCAP_DATA_LINK_TYPE):
		self.filename = filename
		try:
			pcap_file = open(self.filename, 'ab')
			pcap_file.seek(0,2)
			pcap_file.write(struct.pack('@ I H H i I I I ', PCAP_MAGICAL_NUMBER, PCAP_MJ_VERN_NUMBER, PCAP_MI_VERN_NUMBER, PCAP_LOCAL_CORECTIN, PCAP_ACCUR_TIMSTAMP, PCAP_MAX_LENGTH_CAP, link_type))
			pcap_file.close()
		except:
			print >>2, "[ERROR] Unable to write to export file (" + self.filename +"), check filesystem and permissions."
			sys.exit(1)	
		


	def writelist(self, data=[]):
		try:
			pcap_file = open(self.filename, 'ab')
			pcap_file.seek(0,2)
			for i in data:
				self._write(i[1],i[0],pcap_file)
			pcap_file.close()
		except:
			print >>2, "[ERROR] Unable to write to export file (" + self.filename +"), check filesystem and permissions."
			sys.exit(1)
		
	def _write(self, data, ts, pcap_file):
		ts_sec, ts_usec = map(int, str(ts).split('.'))
		length = len(data)
		pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
		pcap_file.write(data)
	

#################Export Manager###################			

class ExportManager(object):
	
	def __init__(self, filename):
		
		self.filename = filename
		self.dirname = "streamexport_" + filename + "_" + str(time.time())
		try:
			os.mkdir(self.dirname)
		except:
			print >>2, "[ERROR] Unable to create export directory (" + self.dirname +"), check filesystem and permissions."
			sys.exit(1)
		self.active_buffers={}
		
	def export_packet(self, file_id, ts, buf):
		if file_id not in self.active_buffers:
			self.active_buffers[file_id] = [PCAPWriter(self.dirname + "/" + file_id + ".pcap"), [[ts,buf]]]
		else:
			self.active_buffers[file_id][1].append([ts,buf])
		if len(self.active_buffers[file_id][1]) > BUFFER_SIZE:
			
			self.active_buffers[file_id][0].writelist(self.active_buffers[file_id][1])
			self.active_buffers[file_id][1] = []
			
	def flush_buffer(self, file_id):
		
		self.active_buffers[file_id][0].writelist(self.active_buffers[file_id][1])
		self.active_buffers[file_id][1] = []

	def flush_all_buffers(self):
		for file_id in self.active_buffers:
			if len(self.active_buffers[file_id][1]) > 0:
				self.flush_buffer(file_id)
							
#################Utility Functions###################		
	
def format_stream_matcher( h1_ip, h1_port, h2_ip, h2_port):
	h1_ip_num = struct.unpack("<I",h1_ip)[0]
	h2_ip_num = struct.unpack("<I",h2_ip)[0]
	if (h1_ip_num < h2_ip_num) or ((h1_ip_num == h2_ip_num) and (h1_port < h2_port)):
		return str(h1_ip_num) + '_' + str(h1_port) + '_' + str(h2_ip_num) + '_' + str(h2_port)
	else:
		return str(h2_ip_num) + '_' + str(h2_port) + '_' + str(h1_ip_num) + '_' + str(h1_port)

def get_exp_file_name(sid, h1_ip, h1_port, h2_ip, h2_port):
	ipfields1 = struct.unpack("<BBBB", h1_ip)
	ipfields2 = struct.unpack("<BBBB", h2_ip)
	h1_ip_num = struct.unpack("<I",h1_ip)[0]
	h2_ip_num = struct.unpack("<I",h2_ip)[0]
	if (h1_ip_num < h2_ip_num) or ((h1_ip_num == h2_ip_num) and (h1_port < h2_port)):
		return str(ipfields1[0]) + "-" + str(ipfields1[1]) + "-" + str(ipfields1[2]) + "-" + str(ipfields1[3]) + "-" + str(h1_port) + "_" + str(ipfields2[0]) + "-" + str(ipfields2[1]) + "-" + str(ipfields2[2]) + "-" + str(ipfields2[3]) + "-" + str(h2_port) + "_" + str(sid)
	else:
		return str(ipfields2[0]) + "-" + str(ipfields2[1]) + "-" + str(ipfields2[2]) + "-" + str(ipfields2[3]) + "-" + str(h2_port) + "_" + str(ipfields1[0]) + "-" + str(ipfields1[1]) + "-" + str(ipfields1[2]) + "-" + str(ipfields1[3]) + "-" + str(h1_port) + "_" + str(sid)

	
	
def host_string(h_ip, h_port):
	ipfields = struct.unpack("<BBBB", h_ip)
	return str(ipfields[0]) + "." + str(ipfields[1]) + "." + str(ipfields[2]) + "." + str(ipfields[3]) + ":" + str(h_port)
	
def print_stream(s,use_time=True, use_filename=False):
	print (("[" + str(s.start_time) + "-" + str(s.end_time) + "] ") if use_time else "") + host_string(s.h1_ip, s.h1_port) + " <-> " + host_string(s.h2_ip, s.h2_port) + " " + str(s.packet_count) + " packets " + str(s.total_bytes) + "b [" + ("OPEN" if s.stream_status==1 else ("CLOSED" if s.stream_status==5 else "PARTIALLY CLOSED")) + ("]" if (not use_filename or s.filename is None) else ("] exported as: " + s.filename + ".pcap"))


#################MAIN###################

def main(args):

	parser = argparse.ArgumentParser()
	parser.add_argument("filename", help="PCAP file to be analyzed")
	parser.add_argument("-F", "--filter", help="Comma delimited list of hosts (ip:port) to filter results.\n You can use 'any' in place of an address or port.\nExample: '192.168.0.1:any,192.168.0.2:53,any:80'")
	parser.add_argument("-f", "--filenames", action='store_true', help="Includes exported filenames in the stream listing.")
	parser.add_argument("-l", "--list", action='store_true', help="Produces list of streams without exporting them to individual PCAP files (faster)")
	parser.add_argument("-t", "--notime", action='store_true', help="Removes timestamps from the stream listing.")
	parser.add_argument("-b", "--buffer", type=int, help="(advanced) Adjusts packet buffer sizes for export files. Generally should be left alone.")
	args = parser.parse_args()

	print >> sys.stderr, "|----| StreamSplit  v0.1 |----|"
	
	if args.buffer: BUFFER_SIZE = args.buffer
	
	do_file_export = True
	if args.list: do_file_export = False
	
	use_time = True
	if args.notime: use_time = False

	use_filenames = False
	if args.filenames: use_filenames = True

	
	if args.filename is None:
		print>> sys.stderr, "[ERROR] you must supply a PCAP filename for analysis"
		return 1
	
	print >> sys.stderr, "[INFO] Processing started: ", datetime.datetime.now()
	host_list = []
	if args.filter: 
		host_list = args.filter.split(",")
		host_list = [x.strip(' ') for x in host_list]

	r = PCAPReader(host_list)
	sidx = r.process_pcap(args.filename, do_file_export)
	stream_count = 0
	for key, value in sidx.streams.iteritems():
		print_stream(value, use_time, use_filenames)
		stream_count += 1
	print >> sys.stderr, "[INFO] Processing complete: ", datetime.datetime.now()	
	print >> sys.stderr, "[INFO]", stream_count, "streams processed."

	return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
