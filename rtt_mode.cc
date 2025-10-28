/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: rtt_mode.cc
 Date created: Oct 28, 2025
 Description: Implementation of RTT mode.
*/
#include "rtt_mode.h"
#include "packet_reader.h"
#include "utils.h"
#include "constants.h"
#include <iostream>
#include <unordered_map>
#include <cstdio>
#include <cstdlib>

void rtt(char* trace_file) {
    std::unordered_map<tcp_flow_key, tcp_flow_info, tcp_key_hasher> flows;   
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
        // Ignore if not TCP
        if (pkt.iph.protocol != TCP) {
            continue;
        }
        
        uint16_t sport = pkt.tcph.source;
        uint16_t dport = pkt.tcph.dest;

        tcp_flow_key cur_flow_id = tcp_flow_key{
            pkt.iph.saddr,
            sport,
            pkt.iph.daddr,
            dport
        };

        // Check if this packet contains data
        bool has_data = pkt.iph.tot_len > IP_HDR_LEN + pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD;
        
        // Create flow entry only for the first packet with data
        if (has_data && flows.find(cur_flow_id) == flows.end()) {
            flows[cur_flow_id] = tcp_flow_info{
                pkt.iph.saddr,
                sport,
                pkt.iph.daddr,
                dport,
                pkt.timestamp,
                pkt.tcph.seq,  // Store S1 (sequence number of first data packet)
                false,         // No ACK found yet
                timev{0, 0}    // Since no ACK, no timestamp -> use placeholder
            };
        }
        
        // Check if this packet ACKs data in the opposite direction's flow
        tcp_flow_key opposite_flow = tcp_flow_key{
            pkt.iph.daddr,
            dport,
            pkt.iph.saddr,
            sport
        };
        
        // If opposite flow exists and we haven't found an ACK yet
        if (flows.find(opposite_flow) != flows.end() && !flows[opposite_flow].has_ack) {
            // Check if this ACK > S1 of the opposite flow
            if (pkt.tcph.ack_seq > flows[opposite_flow].first_seq) {
                flows[opposite_flow].has_ack = true;
                flows[opposite_flow].ack_ts = pkt.timestamp;
            }
        }
    }

    // Print flow information
    for (const auto& pair : flows) {
        timev t1 = pair.second.first_ts;
        std::string rtt_str = "-";

        // Check if we found an ACK for this flow
        if (pair.second.has_ack) {
            // Calculate RTT = t2 - t1
            timev t2 = pair.second.ack_ts;
            timev rtt_tv = deduct_tv(t2, t1);
            rtt_str = format_ts(rtt_tv);
        }
        
        std::cout << dotted_quad(pair.first.sip) << " " 
                  << std::to_string(pair.first.sport) << " " 
                  << dotted_quad(pair.first.dip) << " " 
                  << std::to_string(pair.first.dport) << " " 
                  << rtt_str << std::endl;
    }
    
    fclose(file);
}
