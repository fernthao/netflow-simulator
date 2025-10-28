/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: packet_reader.cc
 Date created: Oct 28, 2025
 Description: Implementation of packet reading functions.
*/
#include "packet_reader.h"
#include "constants.h"
#include <arpa/inet.h>

bool next_pkt(packet* pkt, FILE* file) {
    // Read timestamp (8 bytes)
    if (fread(&pkt->timestamp, sizeof(pkt->timestamp), 1, file) != 1) {
        return false;
    }
    
    // Read ethernet header (14 bytes)
    if (fread(&pkt->ethh, sizeof(pkt->ethh), 1, file) != 1) {
        return false;
    }

    // Convert timestamp to host byte order 
    pkt->timestamp.tv_sec = static_cast<int32_t>(ntohl(static_cast<uint32_t>(pkt->timestamp.tv_sec)));
    pkt->timestamp.tv_usec = static_cast<int32_t>(ntohl(static_cast<uint32_t>(pkt->timestamp.tv_usec)));

    // Ethernet type
    pkt->ethh.ether_type = ntohs(pkt->ethh.ether_type);
    
    // Ignore if not IPv4
    if (pkt->ethh.ether_type != IPv4) {
        pkt->isIP = false;
        return true;
    }
    pkt->isIP = true;

    // Read the IP header (20 bytes)
    if (fread(&pkt->iph, IP_HDR_LEN, 1, file) != 1) {
        return false;
    }
    
    // Check IP header protocol, to ignore if not UDP/TCP
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
    
    // UDP 
    if (pkt->iph.protocol == UDP) {
        // Read the UDP header (fixed length)
        if (fread(&pkt->udph, UDP_HDR_LEN, 1, file) != 1) {
            return false;
        }
        // Convert UDP header to host byte order
        pkt->udph.source = ntohs(pkt->udph.source);
        pkt->udph.dest = ntohs(pkt->udph.dest);
        pkt->udph.len = ntohs(pkt->udph.len);
        pkt->udph.check = ntohs(pkt->udph.check);
    }
    // TCP
    else if (pkt->iph.protocol == TCP) {
        // Read the minimum length of TCP header
        if (fread(&pkt->tcph, TCP_HDR_LEN_MIN, 1, file) != 1) {
            return false;
        }

        // Data offset field = TCP header length in 32-bit words
        // Convert to length in 8-bit bytes 
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
