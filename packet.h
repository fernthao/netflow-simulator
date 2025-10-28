/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: packet.h
 Date created: Oct 28, 2025
 Description: Data structures for packets and flows.
*/
#ifndef PACKET_H
#define PACKET_H

#include <cstdint>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <map>

// Timestamp structure with int32_t instead of uint32_t
struct timev {
    int32_t tv_sec;
    int32_t tv_usec;
};

// Packet structure
struct packet {
    timev timestamp;
    ether_header ethh;
    iphdr iph;
    udphdr udph;
    tcphdr tcph;
    bool isIP; 
};

// Flow key for netflow mode
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
                protocol == other.protocol);
    }
};

// Flow information for netflow mode
struct flow_info {
    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
    uint8_t protocol;
    timev first_ts;
    timev last_ts;
    int tot_pkts;
    int tot_payload_bytes;
};

// TCP flow key for RTT mode
struct tcp_flow_key {
    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint16_t dport;
    
    bool operator==(const tcp_flow_key& other) const {
        return (sip == other.sip &&
                sport == other.sport &&
                dip == other.dip &&
                dport == other.dport);
    }
};

// TCP flow information for RTT mode
struct tcp_flow_info {
    uint32_t sip;
    uint16_t sport;
    uint32_t dip;
    uint32_t dport;
    timev first_ts;
    uint32_t first_seq;
    bool has_ack;  // Whether we've found an ACK > first_seq
    timev ack_ts;  // Timestamp of the first ACK > first_seq
};

// Custom hasher for flow_key
struct key_hasher {
    std::size_t operator()(const flow_key& k) const;
};

// Custom hasher for tcp_flow_key
struct tcp_key_hasher {
    std::size_t operator()(const tcp_flow_key& k) const;
};

#endif // PACKET_H
