#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  __main__.py.py v0.1
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
import streamsplit

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
