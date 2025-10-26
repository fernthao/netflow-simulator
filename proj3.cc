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
#include <cmath>
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
#define ARG_DEBUG 0x16
#define MIN_PKT_SZ 22
#define IPv4 0x0800
#define IP_HDR_LEN 20
#define UDP 17
#define TCP 6
#define UDP_HDR_LEN 8
#define TCP_HDR_LEN_MIN 20 
#define NO_BYTES_PER_DOFF_WORD 4
#define NO_USEC_PER_SEC 1e6

unsigned short cmd_line_flags = 0;
char *trace_file = NULL;

struct timev {
    uint32_t tv_sec;
    uint32_t tv_usec;
};

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
    // Read timestamp (8 bytes)
    if (fread(&pkt->timestamp, sizeof(pkt->timestamp), 1, file) != 1) {
        return false;
    }
    // Read ethernet header (14 bytes)
    if (fread(&pkt->ethh, sizeof(pkt->ethh), 1, file) != 1) {
        return false;
    }

    // Convert timestamp to host byte order 
    pkt->timestamp.tv_sec = ntohl(pkt->timestamp.tv_sec);
    pkt->timestamp.tv_usec = ntohl(pkt->timestamp.tv_usec);

    // ethernet type
    pkt->ethh.ether_type = ntohs(pkt->ethh.ether_type);
    // to ignore if not ipv4
    if (pkt->ethh.ether_type != IPv4) {
        pkt->isIP = false;
        return true;
    }
    pkt->isIP = true;

    // read the IP header (20 bytes)
    if (fread(&pkt->iph, IP_HDR_LEN, 1, file) != 1) {
        return false;
    }
    // check ip header protocol, to ignore if not udp/tcp
    if (pkt->iph.protocol != UDP && pkt->iph.protocol != TCP) {
        return true;
    }
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
        if (fread(&pkt->udph, UDP_HDR_LEN,1, file) != 1) {
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
        if (fread(&pkt->tcph, TCP_HDR_LEN_MIN, 1, file) != 1) {
            return false;
        }

        // Data offset field = tcp header length in 32-bit words
        // Convert to length in 8-bit bytes 
            // TODO 2 structs defined in tcp.h, use th_off or doff?
        uint8_t tcphlen = NO_BYTES_PER_DOFF_WORD * pkt->tcph.doff;

         // Skip TCP options (if any)
        int options_len = tcphlen - TCP_HDR_LEN_MIN;
        if (options_len > 0) {
            if (fseek(file, options_len, SEEK_CUR) != 0) {
                return false;
            }
        }

        // Convert to host byte order
        pkt->tcph.source = ntohs(pkt->tcph.source);
        pkt->tcph.dest = ntohs(pkt->tcph.dest);
        pkt->tcph.seq = ntohl(pkt->tcph.seq);
        pkt->tcph.ack_seq = ntohl(pkt->tcph.ack_seq);
        pkt->tcph.window = ntohs(pkt->tcph.window);
        pkt->tcph.check = ntohs(pkt->tcph.check);
        pkt->tcph.urg_ptr = ntohs(pkt->tcph.urg_ptr);
    }
    return true;
}

string dotted_quad(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "." + 
           to_string((ip >> 16) & 0xFF) + "." + 
           to_string((ip >> 8) & 0xFF) + "." + 
           to_string(ip & 0xFF);
}

string format_ts(timev time) {
    ostringstream oss;
    oss << time.tv_sec << '.'
        << setw(6) << setfill('0') << time.tv_usec;
    return oss.str();  
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
            case 'd':
              cmd_line_flags |= ARG_DEBUG;
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
        string timestamp = format_ts(pkt.timestamp);   
        
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
            // TCP header length in bytes
            thlen = pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD;
            seqno = to_string(pkt.tcph.seq);
            ackno = (pkt.tcph.ack == 1) ? to_string(pkt.tcph.ack_seq) : "-";
        }
        paylen = iplen - IP_HDR_LEN - thlen;

        // Print format:
        //  ts sip sport dip dport iplen protocol thlen paylen seqno ackno
        cout << timestamp << " " 
             << sip << " " 
             << to_string(sport) << " " 
             << dip << " " 
             << to_string(dport) << " "
             << to_string(iplen) << " "
             << protocol << " "
             << to_string(thlen) << " "
             << paylen << " "
             << seqno << " "
             << ackno << endl;
    }
}

timev add_tv(timev tv1, timev tv2) {
    float time1 = tv1.tv_sec + (tv1.tv_usec / NO_USEC_PER_SEC);
    float time2 = tv2.tv_sec + (tv2.tv_usec / NO_USEC_PER_SEC);
    float result = time1 + time2;
    uint32_t result_sec = floor(result);
    uint32_t result_usec = (result - result_sec) * NO_USEC_PER_SEC;
    return timev{result_sec, result_usec};
}

void netflow (char* trace_file) {
    // 1. Read 1 packet
    // 2. Store the 5-tuple that identify the flow
    //      source IP address, 
    //      source transport port
    //      destination IP address, 
    //      destination transport port
    //      transport protocol
    // 3. While the next packet has the same matching 5 tuple, update flow info
    // 4. Detecting end of flow - non-matching tuple, print out flow info and reset
    //      sip sport dip dport protocol first_ts duration tot_pkts tot_payload_bytes

        uint32_t sip;
        uint16_t sport;
        uint32_t dip;
        uint16_t dport;
        uint8_t protocol;
        timev first_ts;
        timev duration; // usec = sec/ 1e6
        // TODO is int big enough
        int tot_pkts;
        int tot_payload_bytes;
        bool flowExist = false;
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
        // if udp, 
        // if new flow
        if (pkt.iph.saddr != sip ||
            pkt.iph.daddr != dip ||
            pkt.iph.protocol != protocol ||
            ((pkt.iph.protocol == UDP) && (pkt.udph.source != sport)) ||
            ((pkt.iph.protocol == UDP) && (pkt.udph.dest != dport)) ||
            ((pkt.iph.protocol == TCP) && (pkt.tcph.source != sport)) ||
            ((pkt.iph.protocol == TCP) && (pkt.tcph.dest != dport)) 
        ) {
            // print out current flow if exist
    //      sip sport dip dport protocol first_ts duration tot_pkts tot_payload_bytes
           if (flowExist) {
                char protocol = pkt.iph.protocol == UDP ? 'U' : 'T';
                cout << dotted_quad(sip) << " " 
                << to_string(sport) << " " 
                << dotted_quad(dip) << " " 
                << to_string(dport) << " " 
                << protocol << " "
                << format_ts(first_ts) << " "
                << format_ts(duration) << " "
                << tot_pkts << " "
                << tot_payload_bytes << endl;
           } 

            // start new flow (resetting fields)
            flowExist = true;
            sip = pkt.iph.saddr;
            dip = pkt.iph.daddr;
            protocol = pkt.iph.protocol;
            sport = pkt.iph.protocol == UDP ? pkt.udph.source : pkt.tcph.source;
            dport = pkt.iph.protocol == UDP ? pkt.udph.dest : pkt.tcph.dest;
            first_ts = pkt.timestamp;
            duration = timev{0,0};
            tot_pkts = 1;
            tot_payload_bytes = pkt.iph.protocol == UDP ? pkt.iph.tot_len - IP_HDR_LEN - UDP_HDR_LEN
                                                        : pkt.iph.tot_len - IP_HDR_LEN - (pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD);
        } else {
            // update current flow with packet
            duration = add_tv(duration, pkt.timestamp);
            tot_pkts++;
            tot_payload_bytes += pkt.iph.protocol == UDP ? pkt.iph.tot_len - IP_HDR_LEN - UDP_HDR_LEN
                                                         : pkt.iph.tot_len - IP_HDR_LEN - (pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD);
        }
    }
    // last flow of the file
    cout << dotted_quad(sip) << " " 
    << to_string(sport) << " " 
    << dotted_quad(dip) << " " 
    << to_string(dport) << " " 
    << protocol << " "
    << format_ts(first_ts) << " "
    << format_ts(duration) << " "
    << tot_pkts << " "
    << tot_payload_bytes << endl;
}

void rtt (char* trace_file) {
    cout << "rtt mode" << endl;
}

void debug() {

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
    // TODO: debugging, to delete
    else if (cmd_line_flags == ARG_DEBUG) {
        debug();
    }
    else
    {
        fprintf (stderr, "Error: only one mode can be selected at a time\n");
        usage(argv[0]);
    }
    exit (0);
}
