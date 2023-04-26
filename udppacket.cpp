#include "udppacket.h"

UdpPacket::UdpPacket(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    udphdr hdr  = (udphdr)(rawpkt + offset);
    src         = ntohs(hdr->src);
    dst         = ntohs(hdr->dst);
    checksum    = ntohs(hdr->checksum);
    pktlen      = ntohs(hdr->payloadlen);
}

quint16 UdpPacket::getSrcPort() {
    return src;
}

quint16 UdpPacket::getDstPort() {
    return dst;
}

quint16 UdpPacket::getChecksum() {
    return checksum;
}

quint32 UdpPacket::getPktLen() {
    return pktlen;
}
