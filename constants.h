/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: constants.h
 Date created: Oct 28, 2025
 Description: Common constants for the netflow simulator.
*/
#ifndef CONSTANTS_H
#define CONSTANTS_H

#define ARG_PACKET_PRINT  0x1
#define ARG_NETFLOW_MODE  0x2
#define ARG_RTT_MODE      0x4
#define ARG_TRACE_FILE    0x8

#define MIN_PKT_SZ        22
#define IPv4              0x0800
#define IP_HDR_LEN        20
#define UDP               17
#define TCP               6
#define UDP_HDR_LEN       8
#define TCP_HDR_LEN_MIN   20 
#define NO_BYTES_PER_DOFF_WORD 4
#define NO_USEC_PER_SEC   1e6

#endif // CONSTANTS_H
