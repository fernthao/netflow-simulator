/* Name: Thao Nguyen 
 Case Network ID: ttn60
 The filename: hashers.cc
 Date created: Oct 28, 2025
 Description: Implementation of hash functions for flow keys.
*/
#include "packet.h"
#include <functional>

std::size_t key_hasher::operator()(const flow_key& k) const {
    std::size_t seed = 0;
    std::hash<uint32_t> hasher32;
    std::hash<uint16_t> hasher16;
    std::hash<uint8_t> hasher8;
    constexpr std::size_t kMul = 0x9e3779b97f4a7c15ULL; // from Boost::hash_combine

    auto mix = [&](std::size_t h) {
        h ^= (h >> 30);
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= (h >> 27);
        h *= 0x94d049bb133111ebULL;
        h ^= (h >> 31);
        seed ^= h + kMul + (seed << 6) + (seed >> 2);
    };

    mix(hasher32(k.sip));
    mix(hasher16(k.sport));
    mix(hasher32(k.dip));
    mix(hasher16(k.dport));
    mix(hasher8(k.protocol));

    return seed;
}

std::size_t tcp_key_hasher::operator()(const tcp_flow_key& k) const {
    std::size_t seed = 0;
    std::hash<uint32_t> hasher32;
    std::hash<uint16_t> hasher16;
    constexpr std::size_t kMul = 0x9e3779b97f4a7c15ULL; // from Boost::hash_combine

    auto mix = [&](std::size_t h) {
        h ^= (h >> 30);
        h *= 0xbf58476d1ce4e5b9ULL;
        h ^= (h >> 27);
        h *= 0x94d049bb133111ebULL;
        h ^= (h >> 31);
        seed ^= h + kMul + (seed << 6) + (seed >> 2);
    };

    mix(hasher32(k.sip));
    mix(hasher16(k.sport));
    mix(hasher32(k.dip));
    mix(hasher16(k.dport));

    return seed;
}
