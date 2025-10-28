/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: utils.h
 Date created: Oct 28, 2025
 Description: Utility functions for the netflow simulator.
*/
#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <cstdint>
#include "packet.h"

// Convert IP address from uint32_t to dotted-quad notation
std::string dotted_quad(uint32_t ip);

// Format timestamp as sec.usec
std::string format_ts(timev time);

// Subtract two timestamps
timev deduct_tv(timev tv, timev deduct_by);

#endif // UTILS_H
