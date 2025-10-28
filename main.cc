/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: main.cc
 Date created: Oct 28, 2025
 Description: Main program for the netflow simulator.

 There are 3 modes: 
 -p: print the packet trace file in the format:
	ts sip sport dip dport iplen protocol thlen paylen seqno ackno
 -n: netflow mode, a summary of the traffic will be printed:
 	sip sport dip dport protocol first_ts duration tot_pkts tot_payload_bytes
 -r: RTT mode, a summary of the RTT between IP addresses in the trace is given.
    sip sport dip dport rtt

 It is submitted as Assignment 3 in the course CSDS 325: Computer Networks, Fall 2025.
*/
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include "constants.h"
#include "print_mode.h"
#include "netflow_mode.h"
#include "rtt_mode.h"

unsigned short cmd_line_flags = 0;
char* trace_file = nullptr;

void usage(char* progname) {
    fprintf(stderr, "--------------- USAGE: ---------------\n");
    fprintf(stderr, "%s [-p] [-n] [-r] -f trace_file\n", progname);
    fprintf(stderr, "   -p    packet printing mode\n");
    fprintf(stderr, "   -n    netflow mode\n");
    fprintf(stderr, "   -r    rtt mode\n");
    fprintf(stderr, "   -f X  set trace file to \'X\'\n");
    exit(1);
}

// Parse command line arguments
void parseargs(int argc, char* argv[]) {
    int opt;

    while ((opt = getopt(argc, argv, "pnrf:")) != -1) {
        switch (opt) {
            case 'p':
                cmd_line_flags |= ARG_PACKET_PRINT;
                break;
            case 'n':
                cmd_line_flags |= ARG_NETFLOW_MODE;
                break;
            case 'r':
                cmd_line_flags |= ARG_RTT_MODE;
                break;
            case 'f':
                cmd_line_flags |= ARG_TRACE_FILE;
                trace_file = optarg;
                break;
            default:
                usage(argv[0]);
        }
    }
    
    if (cmd_line_flags == 0) {
        fprintf(stderr, "error: no command line option given\n");
        usage(argv[0]);
    }
}

int main(int argc, char* argv[]) {
    parseargs(argc, argv);

    if (trace_file == nullptr) {
        fprintf(stderr, "Error: no trace file provided\n");
        exit(1);
    }
    
    if (cmd_line_flags == (ARG_PACKET_PRINT | ARG_TRACE_FILE)) {
        print_packet(trace_file);
    } else if (cmd_line_flags == (ARG_NETFLOW_MODE | ARG_TRACE_FILE)) {
        netflow(trace_file);
    } else if (cmd_line_flags == (ARG_RTT_MODE | ARG_TRACE_FILE)) {
        rtt(trace_file);
    } else {
        fprintf(stderr, "Error: only one mode can be selected at a time\n");
        usage(argv[0]);
    }
    
    exit(0);
}
