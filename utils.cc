/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: utils.cc
 Date created: Oct 28, 2025
 Description: Implementation of utility functions.
*/
#include "utils.h"
#include <sstream>
#include <iomanip>

std::string dotted_quad(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." + 
           std::to_string((ip >> 16) & 0xFF) + "." + 
           std::to_string((ip >> 8) & 0xFF) + "." + 
           std::to_string(ip & 0xFF);
}

std::string format_ts(timev time) {
    std::ostringstream oss;
    oss << time.tv_sec << '.'
        << std::setw(6) << std::setfill('0') << time.tv_usec;
    return oss.str();  
}

timev deduct_tv(timev tv, timev deduct_by) {
    int32_t sec = tv.tv_sec - deduct_by.tv_sec;
    int32_t usec = tv.tv_usec - deduct_by.tv_usec;
    if (usec < 0) {
        sec -= 1;
        usec += 1000000;
    }
    return timev{sec, usec};
}
