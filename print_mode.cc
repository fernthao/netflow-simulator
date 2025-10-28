/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: print_mode.cc
 Date created: Oct 28, 2025
 Description: Implementation of packet printing mode.
*/
#include "print_mode.h"
#include "packet_reader.h"
#include "utils.h"
#include "constants.h"
#include <iostream>
#include <cstdio>
#include <cstdlib>

void print_packet(char* trace_file) {
    packet pkt;
    FILE* file = fopen(trace_file, "rb");
    
    if (file == nullptr) {
        fprintf(stderr, "Error: could not open file %s \n", trace_file);
        exit(1);
    }

    while (next_pkt(&pkt, file)) {
        // Ignore if not IP
        if (!pkt.isIP) {
            continue;
        }
        // Ignore if not UDP or TCP
        if (pkt.iph.protocol != UDP && pkt.iph.protocol != TCP) {
            continue;
        }
        
        // Format header fields
        // Timestamp
        std::string timestamp = format_ts(pkt.timestamp);   
        
        // IP 
        std::string sip = dotted_quad(pkt.iph.saddr);
        std::string dip = dotted_quad(pkt.iph.daddr);
        uint16_t iplen = pkt.iph.tot_len;

        // Transport layer
        char protocol;
        uint16_t sport;
        uint16_t dport;
        uint8_t thlen;
        uint16_t paylen;
        std::string seqno;
        std::string ackno;
        
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
            seqno = std::to_string(pkt.tcph.seq);
            ackno = (pkt.tcph.ack == 1) ? std::to_string(pkt.tcph.ack_seq) : "-";
        }
        paylen = iplen - IP_HDR_LEN - thlen;

        // Print format:
        // ts sip sport dip dport iplen protocol thlen paylen seqno ackno
        std::cout << timestamp << " " 
                  << sip << " " 
                  << std::to_string(sport) << " " 
                  << dip << " " 
                  << std::to_string(dport) << " "
                  << std::to_string(iplen) << " "
                  << protocol << " "
                  << std::to_string(thlen) << " "
                  << paylen << " "
                  << seqno << " "
                  << ackno << std::endl;
    }
    
    fclose(file);
}
