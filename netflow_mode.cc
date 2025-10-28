/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: netflow_mode.cc
 Date created: Oct 28, 2025
 Description: Implementation of netflow mode.
*/
#include "netflow_mode.h"
#include "packet_reader.h"
#include "utils.h"
#include "constants.h"
#include <iostream>
#include <unordered_map>
#include <cstdio>
#include <cstdlib>

void netflow(char* trace_file) {
    std::unordered_map<flow_key, flow_info, key_hasher> flows;   
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
        
        uint16_t sport;
        uint16_t dport;
        int cur_paylen;

        // Set fields depending on transport protocol
        if (pkt.iph.protocol == UDP) {
            sport = pkt.udph.source;
            dport = pkt.udph.dest;
            cur_paylen = pkt.iph.tot_len - IP_HDR_LEN - UDP_HDR_LEN;
        } else if (pkt.iph.protocol == TCP) {
            sport = pkt.tcph.source;
            dport = pkt.tcph.dest;
            cur_paylen = pkt.iph.tot_len - IP_HDR_LEN - (pkt.tcph.doff * NO_BYTES_PER_DOFF_WORD);
        }

        flow_key cur_flow_id = flow_key{
            pkt.iph.saddr,
            sport,
            pkt.iph.daddr,
            dport,
            pkt.iph.protocol
        };

        if (flows.find(cur_flow_id) != flows.end()) {
            // Update current flow with packet
            flow_info& cur_flow_info = flows[cur_flow_id];
            cur_flow_info.last_ts = pkt.timestamp;
            cur_flow_info.tot_pkts++;
            cur_flow_info.tot_payload_bytes += cur_paylen;
        } else {
            // Create new flow
            flows[cur_flow_id] = flow_info{
                pkt.iph.saddr,
                sport,
                pkt.iph.daddr,
                dport,
                pkt.iph.protocol,
                pkt.timestamp,
                pkt.timestamp,
                1,
                cur_paylen
            };
        }
    }

    // Print flow information
    for (const auto& pair : flows) {
        char protocol = pair.first.protocol == UDP ? 'U' : 'T';
        timev duration = deduct_tv(pair.second.last_ts, pair.second.first_ts);
        std::cout << dotted_quad(pair.first.sip) << " " 
                  << std::to_string(pair.first.sport) << " " 
                  << dotted_quad(pair.first.dip) << " " 
                  << std::to_string(pair.first.dport) << " " 
                  << protocol << " "
                  << format_ts(pair.second.first_ts) << " "
                  << format_ts(duration) << " "
                  << pair.second.tot_pkts << " "
                  << pair.second.tot_payload_bytes << std::endl;
    }
    
    fclose(file);
}
