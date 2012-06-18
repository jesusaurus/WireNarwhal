# Wirenarwhal

Copyright © 2012 K Jonathan Harker

Wirenarwhal is a ridiculously incomplete command-line PCAP
trace inspector in the style of WireShark
(http://wireshark.org).

Right now Wirenarwhal only works on Ethernet PCAP packet trace
files in little-endian format (or raw concatenated traces
with the "-r" option), and prints very little useful
information.

The files in the packets/ directory contain PCAP packet 
traces to play with.

Wirenarwhal is released under the MIT license. Please see the
file COPYING in this distribution for license information.

# Notes on Compiling

I have copied and pasted a couple of structs from the internet to
handle the pcap file header and packet headers. These structs depend
on glib.h, which may not be in the compilers search path. The command
to compile this code on a typical machine is:

    gcc `pkg-config --cflags glib-2.0` wirenarwhal.c

# Notes on Running

By default, wirenarwhal expects a pcap file on stdin. This can be
changed by passing the argument and option `--file $filename` to the
program (or its short form: `-f $filename`).

