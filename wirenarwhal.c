/*

Author:     K Jonathan Harker <kjharke@cs.pdx.edu>
Date:       2012-05-23
License:    MIT

Description:
    State machine to parse network traffic.

*/

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <getopt.h>

//http://wiki.wireshark.org/Development/LibpcapFileFormat
typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;
typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

//pcap data
pcap_hdr_t fileHeader;
pcaprec_hdr_t pcapHeader;


void parseEther(char* data);
char* parseARP(char* data);
char* parseIPv4(char* data);
char* parseIPv6(char* data);
char* parseICMP(char* data);
char* parseICMPv6(char* data);
char* parseUDP(char* data);
char* parseUDPLite(char* data);
char* parseTCP(char* data);
char* parseDNS(char* data);
char* parseDHCP(char* data);

//print a help message
void printHelp() {
    printf("\nWire Narwhal\nAnalyze captured network traffic\n");
    printf("\nUsage:  wirenarwhal [--help | -h] [ [--filename | -f] <pcap file> ]\n");
    printf("\nOptions:\n");
    printf("  -h\n");
    printf("  --help\n");
    printf("      Print this help message.\n\n");
    printf("  -f <pcap file>\n");
    printf("  --filename  <pcap file>\n");
    printf("      Specify the capture file to read from (default stdin)\n\n");
}

//parse dns queries
char* parseDNS(char* data) {

    //transaction id
    unsigned short int trans = 0;
    trans |= *data++ << 8;
    trans |= *data++;
    printf("\n  dns transaction id: %d\n", trans);

    //q-r, opcode, authoritative, truncated, recursion desired
    unsigned char flags = *data++;

    //1bit q-r
    if ( flags >> 7 ) {
        printf("  dns response\n");
    } else {
        printf("  dns query\n");
    }

    //4bit opcode
    switch ( (flags >> 3) & 0xf ) {
        case 4:
            printf("  dns notify\n");
            break;
        case 5:
            printf("  dns update\n");
            break;
    }

    //1bit authoritative answer
    if ( flags & 4 ) {
        printf("  dns authoritative answer\n");
    }

    //1bit truncated answer
    if ( flags & 2 ) {
        printf("  dns truncated answer\n");
    }

    //1bit recursion desired
    if ( flags & 1 ) {
        printf("  dns recursion desired\n");
    }

    //recursion available, zero, date, checking, rcode
    flags = *data++;

    //1bit recursion available
    if ( flags >> 7 ) {
        printf("  dns recursion available\n");
    }

    //4bit rcode
    switch ( flags & 0xf ) {
        case 1:
            printf("  dns format error\n");
            break;
        case 2:
            printf("  dns server failure\n");
            break;
        case 3:
            printf("  dns non-existent domain\n");
            break;
        case 4:
            printf("  dns not-implented error\n");
            break;
        case 5:
            printf("  dns query refused\n");
            break;
    }

    //query-zone count
    unsigned short int qcount = 0;
    qcount |= *data++ << 8;
    qcount |= *data++;

    printf("  dns query/zone count: %d\n", qcount);

    //answer-prereq count
    unsigned short int pcount = 0;
    pcount |= *data++ << 8;
    pcount |= *data++;

    printf("  dns answer/prereq count: %d\n", pcount);

    //record-update count
    unsigned short int ncount = 0;
    ncount |= *data++ << 8;
    ncount |= *data++;

    printf("  dns record/update count: %d\n", ncount);

    //additional info count
    unsigned short int acount = 0;
    acount |= *data++ << 8;
    acount |= *data++;

    printf("  dns additional info count: %d\n", acount);

    //query name
    int i;
    for (i=0; i<qcount; i++) {
        printf("\n  dns query: ");
        int j = *data++;
        //these arent quite c-strings
        while (j) {
            while(j--) {
                printf("%c", *data++);
            }
            printf(".");
            j = *data++;
        }
        printf("\n");
    }

    //query type
    unsigned short int qtype = 0;
    qtype |= *data++ << 8;
    qtype |= *data++;
    printf("  dns query type: ");
    switch (qtype) {
        case 1:
            printf("A\n");
            break;
        case 2:
            printf("NS\n");
            break;
        case 5:
            printf("CNAME\n");
            break;
        case 6:
            printf("SOA\n");
            break;
        case 12:
            printf("PTR\n");
            break;
        case 15:
            printf("MX\n");
            break;
        case 28:
            printf("AAAA\n");
            break;
    }

    //query class
    unsigned short int qclass = 0;
    qclass |= *data++ << 8;
    qclass |= *data++;

    //response

    //update

    //additional

    //return the new pointer location
    return data;
}

//parse tcp packet
char* parseTCP(char* data) {

    printf("\n  tcp packet\n");

    //16-bit source port
    unsigned short int sport = 0;
    sport |= (*data++ & 0xff) << 8;
    sport |= *data++ & 0xff;

    //16-bit destination port
    unsigned short int dport = 0;
    dport |= (*data++ & 0xff) << 8;
    dport |= *data++ & 0xff;

    printf("  src port: %d\n", sport);
    printf("  dst port: %d\n", dport);

    //32bit sequence number
    unsigned int seq_no = 0;
    seq_no |= (*data++ & 0xff) << 24;
    seq_no |= (*data++ & 0xff) << 16;
    seq_no |= (*data++ & 0xff) << 8;
    seq_no |= (*data++ & 0xff);

    //32bit acknowledgement number
    unsigned int ack_no = 0;
    ack_no |= (*data++ & 0xff) << 24;
    ack_no |= (*data++ & 0xff) << 16;
    ack_no |= (*data++ & 0xff) << 8;
    ack_no |= (*data++ & 0xff);

    //header length in high 4 bits,
    //resv lower 4 bits
    unsigned char header = *data++;
    header >>= 4;

    //8 bits of flags
    unsigned char flags = *data++;

    //16 bit window size
    unsigned short int wsize = 0;
    wsize |= (*data++ & 0xff) << 8;
    wsize |= (*data++ & 0xff);

    //16 bit checksum
    unsigned short int check = 0;
    check |= (*data++ & 0xff) << 8;
    check |= (*data++ & 0xff);

    //16 bit urgent pointer
    unsigned short int urgent = 0;
    urgent |= (*data++ & 0xff) << 8;
    urgent |= (*data++ & 0xff);

    //TODO: handle possible options
    if (header - 5) {
        data += (header - 5) * 32;
        printf("  skipping %d words of options\n", header-5);
    }

    //return the new pointer location
    return data;
}

//parse udp packet
char* parseUDP(char* data) {

    printf("\n  udp packet\n");
    
    //16-bit source port
    unsigned short int sport = 0;
    sport |= (*data++ & 0xff) << 8;
    sport |= *data++ & 0xff;

    //16-bit destination port
    unsigned short int dport = 0;
    dport |= (*data++ & 0xff) << 8;
    dport |= *data++ & 0xff;

    //16-bit length
    unsigned short int length = 0;
    length |= (*data++ & 0xff) << 8;
    length |= *data++ & 0xff;

    //16-bit checksum
    unsigned short int check = 0;
    check |= (*data++ & 0xff) << 8;
    check |= *data++ & 0xff;

    printf("  src port: %d\n", sport);
    printf("  dst port: %d\n", dport);

    if (sport == 53 || dport == 53) {
        data = parseDNS(data);
    }

    //return the new pointer location
    return data;
}

//parse udp-lite packet
char* parseUDPLite(char* data) {

    printf("\n  udp-lite packet\n");
    
    //16-bit source port
    unsigned short int sport = 0;
    sport |= (*data++ & 0xff) << 8;
    sport |= *data++ & 0xff;

    //16-bit destination port
    unsigned short int dport = 0;
    dport |= (*data++ & 0xff) << 8;
    dport |= *data++ & 0xff;

    //16-bit length
    unsigned short int length = 0;
    length |= (*data++ & 0xff) << 8;
    length |= *data++ & 0xff;

    //16-bit checksum
    unsigned short int check = 0;
    check |= (*data++ & 0xff) << 8;
    check |= *data++ & 0xff;

    printf("  src port: %d\n", sport);
    printf("  dst port: %d\n", dport);

    if (sport == 53 || dport == 53) {
        data = parseDNS(data);
    }

    //return the new pointer location
    return data;
}

//parse icmpv6 packet
char* parseICMPv6(char* data) {

    printf("\n  icmpv6 packet\n");
    
    unsigned char type = *data++;

    unsigned char code = *data++;

    unsigned short int check = 0;
    check |= (*data++ & 0xff) << 8;
    check |= *data++ & 0xff;

    unsigned int body = 0;
    body |= (*data++ & 0xff) << 24;
    body |= (*data++ & 0xff) << 16;
    body |= (*data++ & 0xff) << 8;
    body |= *data++ & 0xff;

    switch (type) {
        case 1:
            printf("  icmpv6 destination unreachable\n");
            break;
        case 2:
            printf("  icmpv6 packet too big\n");
            break;
        case 3:
            printf("  icmpv6 time exceeded\n");
            break;
        case 128:
            printf("  icmpv6 echo request\n");
            break;
        case 129:
            printf("  icmpv6 echo reply\n");
            break;
        case 133:
            printf("  icmpv6 router solicitation\n");
            break;
        case 134:
            printf("  icmpv6 router advertisement\n");
            break;
        case 135:
            printf("  icmpv6 neighbor solicitation\n");
            break;
        case 136:
            printf("  icmpv6 neighbor advertisement\n");
            break;
        case 137:
            printf("  icmpv6 redirect message\n");
            break;
        default:
            printf("  icmpv6 unknown type: %d\n", type);
    }

    //return the new pointer location
    return data;
}

//parse icmp packet
char* parseICMP(char* data) {

    printf("  icmp packet\n");
    
    unsigned char type = *data++;

    unsigned char code = *data++;

    unsigned short int check = 0;
    check |= (*data++ & 0xff) << 8;
    check |= *data++ & 0xff;

    unsigned int body = 0;
    body |= (*data++ & 0xff) << 24;
    body |= (*data++ & 0xff) << 16;
    body |= (*data++ & 0xff) << 8;
    body |= *data++ & 0xff;

    switch (type) {
        case 0:
            printf("  icmp echo reply\n");
            break;
        case 3:
            printf("  icmp destination unreachable\n");
            break;
        case 5:
            printf("  icmp message redirect\n");
            break;
        case 8:
            printf("  icmp echo request\n");
            break;
        default:
            printf("  icmp unknown type: %d\n", type);
    }

    //return the new pointer location
    return data;
}

//parse ipv6 packet
char* parseIPv6(char* data) {
    
    //4bit version, 6bit dsfield, 2bit ecn, 20bit flow label
    unsigned int vdf = 0;
    vdf |= *data++ << 24;
    vdf |= *data++ << 16;
    vdf |= *data++ << 8;
    vdf |= *data++;

    char version = vdf >> 28;
    char dsfield = (vdf >> 22) & 0x3f;
    char ecn = (vdf >> 20) & 0x3;
    int flow = vdf & 0xfffff;

    printf(" ip version: %x\n", version);

    //16bit payload length
    unsigned short int length = 0;
    length |= *data++ << 8;
    length |= *data++;
    printf(" ip payload length: %x\n", length);

    //8bit next header type
    unsigned char nextType = *data++;
    printf(" next header type: %x\n", nextType);

    //8bit hop limit
    unsigned char hopLimit = *data++;
    printf(" hop limit: %x\n", hopLimit);

    int i;

    //128bit source address
    unsigned char source[16];
    for (i = 0; i < 16; i++) {
        source[i] = *data++;
    }

    printf(" ip src: ");
    for (i = 0; i < 14; i+=2) {
        printf("%02x%02x:", source[i], source[i+1]);
    }
    printf("%02x%02x\n", source[i], source[i+1]);

    //128bit destination address
    unsigned char dest[16];
    for (i = 0; i < 16; i++) {
        dest[i] = *data++;
    }

    printf(" ip dst: ");
    for (i = 0; i < 14; i+=2) {
        printf("%02x%02x:", dest[i], dest[i+1]);
    }
    printf("%02x%02x\n", dest[i], dest[i+1]);

    switch (nextType) {
        case 0x1:
            //ICMP
            data = parseICMP(data);
            break;
        case 0x4:
            //IP in IP
            data = parseIPv4(data);
            break;
        case 0x6:
            //TCP
            data = parseTCP(data);
            break;
        case 0x11:
            //UDP
            data = parseUDP(data);
            break;
        case 0x29:
            //IP in IP
            data = parseIPv6(data);
            break;
        case 0x3A:
            //ICMPv6
            data = parseICMPv6(data);
            break;
        case 0x73:
            //L2TP
            //TODO
            break;
        case 0x88:
            //UDPLite
            data = parseUDPLite(data);
            break;
    }
    //return the new pointer location
    return data;
}

//parse ipv4 packet
char* parseIPv4(char* data) {
    
    //version in high 4 bits, ihl in low 4 bits
    char vi = *data++;
    char version = vi >> 4;
    char ihl = vi & 0xf;
    
    printf("\n ip version: %u\n", version);

    //ds field in the high 6 bits, ecn in the low 2 bits
    char dsecn = *data++;
    char dsfield = dsecn >> 2;
    char ecn = dsecn & 0x3;

    //16-bit length
    short int length = 0;
    length |= (*data++ & 0xff) << 8;
    length |= *data++ & 0xff;

    printf(" ip data length: %u\n", length);

    //16-bit identification
    short int id = 0;
    id |= (*data++ & 0xff) << 8;
    id |= *data++ & 0xff;

    //3 bits of flags, followed by 13-bit fragment offset
    short int ff = 0;
    ff |= (*data++ & 0xff) << 8;
    ff |= *data++ & 0xff;
    char flags = ff >> 13;
    short int offset = ff & 0x1fff;

    //time to live is easy
    char ttl = *data++;
    //same with protocol
    unsigned char proto = *data++;

    //16bit header checksum
    short int check = 0;
    check |= (*data++ & 0xff) << 8;
    check |= *data++ & 0xff;

    //source address
    //an array makes life easy both for reading in the value,
    //and for printing in dotted-decimal
    unsigned char source[4];
    source[0] = *data++;
    source[1] = *data++;
    source[2] = *data++;
    source[3] = *data++;

    printf(" ip src: %d.%d.%d.%d\n", source[0],source[1],source[2],source[3]);

    //destination address, also an array
    unsigned char dest[4];
    dest[0] = *data++;
    dest[1] = *data++;
    dest[2] = *data++;
    dest[3] = *data++;

    printf(" ip dst: %u.%u.%u.%u\n", dest[0],dest[1],dest[2],dest[3]);

    //TODO: handle possible options
    if (ihl-5) {
        printf(" skipping %d words of options\n", ihl-5);
        data += ihl-5;
    }

    switch (proto) {
        case 0x1:
            //ICMP
            data = parseICMP(data);
            break;
        case 0x4:
            //IP in IP
            data = parseIPv4(data);
            break;
        case 0x6:
            //TCP
            data = parseTCP(data);
            break;
        case 0x11:
            //UDP
            data = parseUDP(data);
            break;
        case 0x29:
            //IP in IP
            data = parseIPv6(data);
            break;
        case 0x73:
            //L2TP
            break;
        case 0x88:
            //UDPLite
            data = parseUDPLite(data);
            break;
    }

    //return the new pointer location
    return data;
}

//parse arp packet
char* parseARP(char* data) {
    
    //

    //return the new pointer location
    return data;
}

//parse 802.3 frame
void parseEther(char* data) {

    //6 octets of destination mac
    printf("src mac: ");
    int i=0;
    while (i<5) {
        printf("%02x:", *data++ & 0xff);
        i++;
    }
    printf("%02x\n", *data++ & 0xff);

    //6 octets of source mac
    printf("dst mac: ");
    i=0;
    while (i<5) {
        printf("%02x:", *data++ & 0xff);
        i++;
    }
    printf("%02x\n", *data++ & 0xff);

    //2 octets of type or length
    unsigned short int type = 0;
    type |= (*data++ & 0xff) << 8;
    type |= *data++;
    printf("type: %04x\n", type);

    switch (type) {
        case 0x0800:
            //printf("found ipv4 payload\n");
            data = parseIPv4(data);
            break;
        case 0xffdd: //where does this come from?
        case 0x86dd:
            //printf("found ipv6 payload\n");
            data = parseIPv6(data);
            break;
        case 0x0806:
            //printf("found arp payload\n");
            data = parseARP(data);
            break;
        default:
            printf("payload length: %d\n", type);
            data += type;
    }

    //footer: crc
    int crc = *((int*)data);
    printf("\n802.3 CRC: %08x\n", crc);

}

//program entry
int main(int argc, char** argv) {
    
    //file to open
    char* fileName = 0; //default to stdin

    //getopt long options
    static struct option long_options[] = {
        {"file", required_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    //parse command-line arguments
    char c;
    int iptr;
    while ( (c = getopt_long( argc, argv, "hf:", long_options, &iptr )) != -1 ) {
        switch (c) {
            case 'f':
                fileName = optarg;
                break;
            case 'h':
            default:
                printHelp();
                return 0;
        }
    }

    //open file
    int file;
    if (fileName) {
        file = open(fileName, 0);
    } else {
        file = 0;
    }

    //read header
    read(file, &fileHeader, sizeof(fileHeader));

    //print out file info
    printf("PCAP File info:\n");
    printf("magic number: %x\n", fileHeader.magic_number);
    printf("max capture size: %d octets\n", fileHeader.snaplen);
    printf("network link type: ");
    switch(fileHeader.network) {
        case 1:
            printf("Ethernet\n");
            break;
        default:
            printf("Unknown (%x)\nExiting due to unknown link type\n", fileHeader.network);
            return -1;
    }

    //read sequential packets
    while(read(file, &pcapHeader, sizeof(pcapHeader))) {
        //process packet
        printf("\nPacket Found (%d octets)\n", pcapHeader.incl_len);

        //capture data
        char* data = malloc(pcapHeader.incl_len);
        read(file, data, pcapHeader.incl_len);

        //parse link frame
        switch(fileHeader.network) {
            case 1:
                parseEther(data);
                break;
        }

        //we're done with this data
        free(data);

    }//next packet

}//program exit
