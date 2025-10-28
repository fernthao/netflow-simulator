
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
#include <unordered_map>
#include <tuple>
#include <map>

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
            // Add missing closing brace for rtt function
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

timev deduct_tv(timev tv, timev deduct_by) {
    int32_t sec = static_cast<int32_t>(tv.tv_sec) - static_cast<int32_t>(deduct_by.tv_sec);
    int32_t usec = static_cast<int32_t>(tv.tv_usec) - static_cast<int32_t>(deduct_by.tv_usec);
    if (usec < 0) {
        sec -= 1;
        usec += 1000000;
    }
    return timev{static_cast<uint32_t>(sec), static_cast<uint32_t>(usec)};
}

struct flow_key {
    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
    uint8_t protocol;
    bool operator==(const flow_key& other) const {
        return (sip == other.sip &&
                sport == other.sport &&
                dip == other.dip &&
                dport == other.dport &&
                protocol == other.protocol
            );
    }
};

struct flow_info {
        uint32_t sip;
        uint16_t sport;
        uint32_t dip;
        uint16_t dport;
        uint8_t protocol;
        timev first_ts;
        timev last_ts;
        // TODO is int big enough
        int tot_pkts;
        int tot_payload_bytes;
};

// custom hasher for flow_key
struct key_hasher {
  size_t operator()(const flow_key& k) const
  {
    size_t seed = 0;
    hash<uint32_t> hasher32;
    hash<uint16_t> hasher16;
    hash<uint8_t> hasher8;
    // constexpr evaluates var at compile time instead of runtime -> performance optimization
    constexpr size_t kMul = 0x9e3779b97f4a7c15ULL; // from Boost::hash_combine

    auto mix = [&](size_t h) {
        h ^= (h >> 30);
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= (h >> 27);
        h *= 0x94d049bb133111ebULL;
        h ^= (h >> 31);
        seed ^= h + kMul + (seed << 6) + (seed >> 2);
    };

    mix(hasher32(k.sip));
    mix(hasher16(k.sport));
    mix(hasher32(k.dip));
    mix(hasher16(k.dport));
    mix(hasher8(k.protocol));

    return seed;
  }
};

void netflow (char* trace_file) {
    unordered_map<flow_key, flow_info, key_hasher> flows;   
    packet pkt;
    // TODO use c++ open file
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
        uint16_t sport;
        uint16_t dport;
        int cur_paylen;

        // set fields depending on transport protocol
        if (pkt.iph.protocol == UDP) {
            sport = pkt.udph.source;
            dport = pkt.udph.dest;
            cur_paylen = pkt.iph.tot_len - IP_HDR_LEN - UDP_HDR_LEN;
        } else if (pkt.iph.protocol == TCP) {
            sport = pkt.tcph.source;
            dport = pkt.tcph.dest;
            cur_paylen = pkt.iph.tot_len - IP_HDR_LEN - (pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD);
        };

        flow_key cur_flow_id = flow_key {
            pkt.iph.saddr,
            sport,
            pkt.iph.daddr,
            dport,
            pkt.iph.protocol
        };

        if (flows.find(cur_flow_id) != flows.end()) {
            // update current flow with packet
            flow_info cur_flow_info = flows[cur_flow_id];

            cur_flow_info.last_ts = pkt.timestamp;
            cur_flow_info.tot_pkts++;
            cur_flow_info.tot_payload_bytes += cur_paylen;
            flows[cur_flow_id] = cur_flow_info;
        } else {
            // create new flow
            timev first_ts = pkt.timestamp;
            timev last_ts = pkt.timestamp;
            int tot_pkts = 1;
            int tot_payload_bytes = cur_paylen;
            flows[cur_flow_id] = flow_info {
                pkt.iph.saddr,
                sport,
                pkt.iph.daddr,
                dport,
                pkt.iph.protocol,
                first_ts,
                last_ts,
                tot_pkts,
                tot_payload_bytes
            };
        };
    }

    //printing out flow info
    for (const auto& pair : flows) {
        char protocol = pair.first.protocol == UDP ? 'U' : 'T';
        timev duration = deduct_tv(pair.second.last_ts, pair.second.first_ts);
        cout << dotted_quad(pair.first.sip) << " " 
        << to_string(pair.first.sport) << " " 
        << dotted_quad(pair.first.dip) << " " 
        << to_string(pair.first.dport) << " " 
        << protocol << " "
        << format_ts(pair.second.first_ts) << " "
        << format_ts(duration) << " "
        << pair.second.tot_pkts << " "
        << pair.second.tot_payload_bytes << endl;
    }
};

struct tcp_flow_key {
    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
    bool operator==(const tcp_flow_key& other) const {
        return (sip == other.sip &&
                sport == other.sport &&
                dip == other.dip &&
                dport == other.dport
            );
    }
};

struct tcp_flow_info {
        uint32_t sip;
        uint16_t sport;
        uint32_t dip;
        uint16_t dport;
        // send direction
        timev first_ts;
        uint32_t first_seq;
        // receive direction
        map<uint32_t, timev> acks;
};

// custom hasher for tcp_flow_key
struct tcp_key_hasher {
  size_t operator()(const tcp_flow_key& k) const
  {
    size_t seed = 0;
    hash<uint32_t> hasher32;
    hash<uint16_t> hasher16;
    // constexpr evaluates var at compile time instead of runtime -> performance optimization
    constexpr size_t kMul = 0x9e3779b97f4a7c15ULL; // from Boost::hash_combine

    auto mix = [&](size_t h) {
        h ^= (h >> 30);
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= (h >> 27);
        h *= 0x94d049bb133111ebULL;
        h ^= (h >> 31);
        seed ^= h + kMul + (seed << 6) + (seed >> 2);
    };

    mix(hasher32(k.sip));
    mix(hasher16(k.sport));
    mix(hasher32(k.dip));
    mix(hasher16(k.dport));

    return seed;
  }
};

void rtt (char* trace_file) {
    // Problem
    /*
    When the “-r” option is given your program will operate in RTT mode. In this mode, you will print
    information about the round-trip time (RTT) of each TCP flow in the packet trace. A “flow” is defined by
    the source IP address, source TCP port number, destination IP address and destination TCP port number.
    Each direction of a conversation is reported independently. You must track each flow and once all packets
    in the given trace have been processed you will print a summary of the flow.
    Packets that do not use IPv4 as the network layer protocol must be ignored. Packets that do not use TCP
    as their transport protocol must be ignored.
    Each flow summary will produce a single line of output, as follows:
    sip sport dip dport rtt
    The fields in each line will be separated by a single space. Each line will end with a newline character (“\n”).
    Do not include any additional information or whitespace. The fields will be printed as follows:
    • sip: This is the IPv4 source address for the flow printed in dotted-quad notation. That is, four
    unpadded decimal integers separated by periods (“.”). E.g., “192.168.10.54”.
    • sport: This is the TCP source port number for the flow printed as an unpadded decimal number.
    • dip: This is the IPv4 destination address for the flow printed in dotted-quad notation. That is, four
    unpadded decimal integers separated by periods (“.”). E.g., “132.235.1.2”.
    • dport: This is the TCP destination port number for the flow printed as an unpadded decimal number.
    • rtt: This is the RTT of the flow to 6 decimal places of precision. If no RTT is observed for the flow
    this field will contain a single dash (“-”).
    It is possible to observe many RTTs for every TCP connection. In this project you will report the first RTT
    observation for each traffic flow. That is you will remember the sequence number of the first packet in the
    flow that contains data as S1, as well as the timestamp of this packet as T1. Then, you will observe traffic
    in the opposite direction looking for the first packet with an acknowledgment (ACK) number greater than
    S1. The timestamp of the ACK is recorded as T2. The RTT will then be T2 − T1. When no suitable ACK
    arrives then no RTT can be computed and a “-” will be reported, as noted above.
    */


    // Solution design
    // flow id - same as above but without protocol
    // flow info 
    //      1. send direction: remember first_seq and first_ts
    //      2. rcv direction: remember all packet acks and their ts
    // update info rcv direction if new packet belongs to old flow
    // at the end, iterate through the flows
    //      for each, find opposite flow, if exist higher ack # than seq # then calculate rtt, else print "-"
    unordered_map<tcp_flow_key, tcp_flow_info, tcp_key_hasher> flows;   
    packet pkt;
    // TODO use c++ open file
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
        // ignore if not tcp
        if (pkt.iph.protocol != TCP) {
            continue;
        }
        uint16_t sport = pkt.tcph.source;
        uint16_t dport = pkt.tcph.dest;

        tcp_flow_key cur_flow_id = tcp_flow_key {
            pkt.iph.saddr,
            sport,
            pkt.iph.daddr,
            dport
        };

        if (flows.find(cur_flow_id) != flows.end()) {
            // update current flow with packet info
            flows[cur_flow_id].acks.insert({pkt.tcph.ack_seq, pkt.timestamp});
        } else {
            // create new flow with first packet that contains data
            if (pkt.iph.tot_len > IP_HDR_LEN + pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD) {
                timev first_ts = pkt.timestamp;
                uint32_t first_seq = pkt.tcph.seq;
                map<uint32_t, timev> acks;
                acks.insert({pkt.tcph.ack_seq, pkt.timestamp});
                flows[cur_flow_id] = tcp_flow_info {
                    pkt.iph.saddr,
                    sport,
                    pkt.iph.daddr,
                    dport,
                    first_ts,
                    first_seq,
                    acks
                };
            }
        }
    }

    //printing out flow info
    for (const auto& pair : flows) {
        // consider current pair the sending direction
        uint32_t first_seq = pair.second.first_seq;
        timev rtt_tv;
        timev t1 = pair.second.first_ts;
        bool noRTT = true;

        // find flow of opposite direction
        tcp_flow_key opposite_flow = tcp_flow_key {pair.first.dip, 
                                                pair.first.dport,
                                                pair.first.sip,
                                                pair.first.sport};
        if (flows.find(opposite_flow) != flows.end()) {
            // found opposite flow 
            map<uint32_t, timev> acks = flows[opposite_flow].acks;
            // look for the first packet with an acknowledgment (ACK) number greater than seq # of sending packet
            if (acks.upper_bound(first_seq) != acks.end()) {
                noRTT = false;
                // calculate RTT = t2 - t1
                // t2 = flows[opposite_flow].acks.upper_bound(first_seq)
                timev t2 = acks.upper_bound(first_seq)->second;
                rtt_tv = deduct_tv(t2, t1);
            }
        }
        string rtt = noRTT ? "-" : format_ts(rtt_tv);
        
        cout << dotted_quad(pair.first.sip) << " " 
        << to_string(pair.first.sport) << " " 
        << dotted_quad(pair.first.dip) << " " 
        << to_string(pair.first.dport) << " " 
        << rtt << endl;
    }
}

int main (int argc, char *argv []) {
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
