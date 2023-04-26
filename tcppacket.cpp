#include "tcppacket.h"

TcpPacket::TcpPacket(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    tcphdr hdr      = (tcphdr)(rawpkt + offset);
    src             = ntohs(hdr->src);
    dst             = ntohs(hdr->dst);
    seqN            = ntohl(hdr->seqN);
    ackN            = ntohl(hdr->ackN);
    hdrlen          = ((hdr->hdrlen & 0xf0) >> 4) * 4;
    flags           = ((hdr->hdrlen & 0x0f) << 8) | hdr->flags;
    winsize         = ntohs(hdr->winsize);
    checksum        = ntohs(hdr->checksum);
    urgptr          = ntohs(hdr->urgptr);
    pktlen          = getCapLen() - offset;
}

quint16 TcpPacket::getSrcPort() {
    return src;
}

quint16 TcpPacket::getDstPort() {
    return dst;
}

quint32 TcpPacket::getSeqN() {
    return seqN;
}

quint32 TcpPacket::getAckN() {
    return ackN;
}

quint8 TcpPacket::gethdrlen() {
    return hdrlen;
}

quint16 TcpPacket::getFlags() {
    return flags;
}

quint16 TcpPacket::getWinSize() {
    return winsize;
}

quint16 TcpPacket::getChecksum() {
    return checksum;
}

quint16 TcpPacket::getUrgptr() {
    return urgptr;
}

quint32 TcpPacket::getPktLen() {
    return pktlen;
}
