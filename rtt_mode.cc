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

        if (flows.find(cur_flow_id) != flows.end()) {
            // Update current flow with packet info
            flows[cur_flow_id].acks.insert({pkt.tcph.ack_seq, pkt.timestamp});
        } else {
            // Create new flow with first packet that contains data
            if (pkt.iph.tot_len > IP_HDR_LEN + pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD) {
                std::map<uint32_t, timev> acks;
                acks.insert({pkt.tcph.ack_seq, pkt.timestamp});
                flows[cur_flow_id] = tcp_flow_info{
                    pkt.iph.saddr,
                    sport,
                    pkt.iph.daddr,
                    dport,
                    pkt.timestamp,
                    pkt.tcph.seq,
                    acks
                };
            }
        }
    }

    // Print flow information
    for (const auto& pair : flows) {
        // Consider current pair the sending direction
        uint32_t first_seq = pair.second.first_seq;
        timev rtt_tv;
        timev t1 = pair.second.first_ts;
        bool noRTT = true;

        // Find flow of opposite direction
        tcp_flow_key opposite_flow = tcp_flow_key{
            pair.first.dip, 
            pair.first.dport,
            pair.first.sip,
            pair.first.sport
        };
        
        if (flows.find(opposite_flow) != flows.end()) {
            // Found opposite flow 
            std::map<uint32_t, timev> acks = flows[opposite_flow].acks;
            // Look for the first packet with an acknowledgment (ACK) number greater than seq # of sending packet
            if (acks.upper_bound(first_seq) != acks.end()) {
                noRTT = false;
                // Calculate RTT = t2 - t1
                timev t2 = acks.upper_bound(first_seq)->second;
                rtt_tv = deduct_tv(t2, t1);
            }
        }
        
        std::string rtt_str = noRTT ? "-" : format_ts(rtt_tv);
        
        std::cout << dotted_quad(pair.first.sip) << " " 
                  << std::to_string(pair.first.sport) << " " 
                  << dotted_quad(pair.first.dip) << " " 
                  << std::to_string(pair.first.dport) << " " 
                  << rtt_str << std::endl;
    }
    
    fclose(file);
}
