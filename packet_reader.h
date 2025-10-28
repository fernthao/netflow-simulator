/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: packet_reader.h
 Date created: Oct 28, 2025
 Description: Packet reading functions for the netflow simulator.
*/
#ifndef PACKET_READER_H
#define PACKET_READER_H

#include <cstdio>
#include "packet.h"

// Read next packet from trace file
bool next_pkt(packet* pkt, FILE* file);

#endif // PACKET_READER_H
