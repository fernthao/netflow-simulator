/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: proj3.cc
 Date created: Oct 23, 2025
 Description: This program simulate how a router logs the traffic arriving at it.

 There are 3 modes: 
 -p: print the packet trace file in the format:
	ts sip sport dip dport iplen protocol thlen paylen seqno ackno
 -n: netflow mode, a summary of the traffic will be printed:
 	sip sport dip dport protocol first_ts duration tot_pkts tot_payload_bytes
 -r: RTT mode, a summary of the RTT between IP addresses in the trace is given.
    sip sport dip dport rtt

 It is submitted as Assignment 3 in the course CSDS 325: Computer Networks, Fall 2025.
*/
#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <vector>
#include <string>

using namespace std;

#define ARG_PACKET_PRINT  0x1
#define ARG_NETFLOW_MODE   0x2
#define ARG_RTT_MODE 0x4
#define ARG_TRACE_FILE 0x8
#define MIN_PKT_SZ 22
#define IPv4 0x0800
#define IP_HDR_LEN 20
#define UDP 17
#define TCP 6
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN_MIN 20 

unsigned short cmd_line_flags = 0;
char *trace_file = NULL;

typedef struct {
    uint32_t tv_sec;
    uint32_t tv_usec;
} timev;

struct packet {
    timev timestamp;
    ether_header ethh;
    iphdr iph;
    udphdr udph;
    tcphdr tcph;
    bool isIP; 
};

bool next_pkt (packet* pkt, FILE* file)
{
    if (fread(pkt, MIN_PKT_SZ, 1, file) != 1) {
        return false;
    }

    // read the ethernet header type first
    pkt->ethh.ether_type = ntohs(pkt->ethh.ether_type);

    // to ignore if not ipv4
    if (pkt->ethh.ether_type != IPv4) {
        pkt->isIP = false;
        return true;
    } 
    
    pkt->isIP = true;

    // read the IP header 
    // TODO is there better way than pointer arithmetic
    if (fread(pkt + MIN_PKT_SZ, IP_HDR_LEN, 1, file) != 1) {
        return false;
    }

    // check ip header protocol, to ignore if not udp/tcp
    if (pkt->iph.protocol != UDP && pkt->iph.protocol != TCP) {
        return true;
    }

    // Convert the timestamp to host byte order
    pkt->timestamp.tv_sec = ntohl(pkt->timestamp.tv_sec);
    pkt->timestamp.tv_usec = ntohl(pkt->timestamp.tv_usec);

    // Convert IP header to host byte order
    pkt->iph.tot_len = ntohs(pkt->iph.tot_len);
    pkt->iph.id = ntohs(pkt->iph.id);
    pkt->iph.frag_off = ntohs(pkt->iph.frag_off);
    pkt->iph.check = ntohs(pkt->iph.check);
    pkt->iph.saddr = ntohl(pkt->iph.saddr);
    pkt->iph.daddr = ntohl(pkt->iph.daddr);
    
    // udp 
    if (pkt->iph.protocol == UDP) {
        // read the udp header (fixed length)
        if (fread(pkt + MIN_PKT_SZ + IP_HDR_LEN, UDP_HDR_LEN,1, file) != 1) {
            return false;
        }
        // Convert udp header to host byte order
        pkt->udph.source = ntohs(pkt->udph.source);
        pkt->udph.dest = ntohs(pkt->udph.dest);
        pkt->udph.len = ntohs(pkt->udph.len);
        pkt->udph.check = ntohs(pkt->udph.check);
    }

    // tcp
    else if (pkt->iph.protocol == TCP) {
        // read the minimum length of tcp header
        if (fread(pkt + MIN_PKT_SZ + IP_HDR_LEN + UDP_HDR_LEN, TCP_HDR_LEN_MIN, 1, file) != 1) {
            return false;
        }

        // Data offset field = tcp header length in 32-bit words
        // Convert to length in 16-bit bytes 
            // TODO 2 structs defined in tcp.h, use th_off or doff?
        uint8_t tcphlen = 2 * pkt->tcph.doff;

        // Read tcp options
        if (fread(pkt + MIN_PKT_SZ + IP_HDR_LEN + UDP_HDR_LEN + TCP_HDR_LEN_MIN, tcphlen - TCP_HDR_LEN_MIN, 1, file) != 1) {
            return false;
        }

        // Convert to host byte order
        pkt->tcph.source = ntohs(pkt->tcph.source);
        pkt->tcph.dest = ntohs(pkt->tcph.dest);
        pkt->tcph.window = ntohs(pkt->tcph.window);
        pkt->tcph.check = ntohs(pkt->tcph.check);
        pkt->tcph.urg_ptr = ntohs(pkt->tcph.urg_ptr);
    }
    return true;
}

string dotted_quad(uint32_t ip) {
    return to_string(ip & 0xFF000000) + "." + to_string(ip & 0xFF0000) + "." + to_string(ip & 0xFF00) + "." + to_string(ip & 0xFF);
}

void usage (char *progname)
{
    fprintf (stderr,"--------------- USAGE: ---------------\n");
    fprintf (stderr,"%s [-p] [-n] [-r] -f trace_file\n", progname);
    fprintf (stderr,"   -p    packet printing mode\n");
    fprintf (stderr,"   -n    netflow mode\n");
    fprintf (stderr,"   -r    rtt mode\n");
    fprintf (stderr,"   -f X  set trace file to \'X\'\n");
    exit (1);
}

// Parse command line arguments
void parseargs (int argc, char *argv [])
{
    int opt;

    while ((opt = getopt (argc, argv, "pnrf:")) != -1)
    {
        switch (opt)
        {
            case 'p':
              cmd_line_flags |= ARG_PACKET_PRINT;
              break;
            case 'n':
              cmd_line_flags |= ARG_NETFLOW_MODE;
              break;
            case 'r':
              cmd_line_flags |= ARG_RTT_MODE;
              break;
            case 'f':
              cmd_line_flags |= ARG_TRACE_FILE;
              trace_file = optarg;
              break;
            default:
              usage (argv [0]);
        }
    }
    if (cmd_line_flags == 0)
    {
        fprintf (stderr,"error: no command line option given\n");
        usage (argv [0]);
    }
}

void print_packet(char *trace_file) {
    packet pkt;
    FILE* file = fopen(trace_file, "rb");
    
    if (file == nullptr) {
        fprintf(stderr, "Error: could not open file %s \n", trace_file);
        exit(1);
    }

    while (next_pkt(&pkt, file)) {
        // ignore if not ip
        if (!pkt.isIP) {
            continue;
        }
        // ignore if not udp or tcp
        if (pkt.iph.protocol != UDP && pkt.iph.protocol != TCP) {
            continue;
        }

        // Format header fields
        // timestamp
        ostringstream oss;
        oss << pkt.timestamp.tv_sec << '.'
            << setw(6) << setfill('0') << pkt.timestamp.tv_usec;
        string timestamp = oss.str();    
        
        // ip 
        string sip = dotted_quad(pkt.iph.saddr);
        string dip = dotted_quad(pkt.iph.daddr);
        uint16_t iplen = pkt.iph.tot_len;

        // transport layer
        char protocol;
        uint16_t sport;
        uint16_t dport;
        uint8_t thlen;
        uint16_t paylen;
        string seqno;
        string ackno;
        if (pkt.iph.protocol == UDP) {
            protocol = 'U';
            sport = pkt.udph.source;
            dport = pkt.udph.dest;
            thlen = UDP_HDR_LEN;
            seqno = "-";
            ackno = "-";
        } else if (pkt.iph.protocol == TCP) {
            protocol = 'T';
            sport = pkt.tcph.source;
            dport = pkt.tcph.dest;
            thlen = pkt.tcph.doff;
            seqno = to_string(pkt.tcph.seq);
            ackno = pkt.tcph.ack == 1 ? to_string(pkt.tcph.ack_seq) : "-";
        }
        uint16_t  paylen = iplen - IP_HDR_LEN - thlen;

        // Print format:
        //  ts sip sport dip dport iplen protocol thlen paylen seqno ackno
        printf("%s %s %u %s %u %u %c %u %u %s %s",
                timestamp,
                sip,
                sport,
                dip,
                dport,
                iplen,
                protocol,
                thlen,
                paylen,
                seqno,
                ackno
              ); 
    }
}

void netflow (char* trace_file) {
    cout << "netflow mode" << endl;
}

void rtt (char* trace_file) {
    cout << "rtt mode" << endl;
}

int main (int argc, char *argv [])
{
    parseargs (argc,argv);

    if (trace_file == NULL)
    {
        fprintf (stderr,"Error: no trace file provided\n");
        exit(1);
    }
    
    if (cmd_line_flags == (ARG_PACKET_PRINT | ARG_TRACE_FILE)) {
        print_packet(trace_file);
    }
    else if (cmd_line_flags == (ARG_NETFLOW_MODE | ARG_TRACE_FILE)) {
        netflow(trace_file);
    }
    else if (cmd_line_flags == (ARG_RTT_MODE | ARG_TRACE_FILE)) {
        rtt(trace_file);
    }
    else
    {
        fprintf (stderr, "Error: only one mode can be selected at a time\n");
        usage(argv[0]);
    }
    exit (0);
}
