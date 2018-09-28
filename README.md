# streamsplit
A utility to extract TCP streams from (large) pcap files
```
usage: streamsplit.py [-h] [-F FILTER] [-f] [-l] [-t] [-b BUFFER] filename

positional arguments:
  filename              PCAP file to be analyzed

optional arguments:
  -h, --help            show this help message and exit
  -F FILTER, --filter FILTER
                        Comma delimited list of hosts (ip:port) to filter
                        results. You can use 'any' in place of an address or
                        port. Example: '192.168.0.1:any,192.168.0.2:53,any:80'
  -f, --filenames       Includes exported filenames in the stream listing.
  -l, --list            Produces list of streams without exporting them to
                        individual PCAP files (faster)
  -t, --notime          Removes timestamps from the stream listing.
  -b BUFFER, --buffer BUFFER
                        (advanced) Adjusts packet buffer sizes for export
                        files. Generally should be left alone.
```
