#include "arppacket.h"

ARPPacket::ARPPacket(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    arp a       = (arp)(rawpkt + offset);
    type        = ntohs(a->type);
    protocol    = ntohs(a->protocol);
    haddrlen    = a->haddrlen;
    paddrlen    = a->paddrlen;
    opcode      = ntohs(a->opcode);
    hSrc        = a->srchaddr;
    pSrc        = a->srcpaddr;
    hDst        = a->dsthaddr;
    pDst        = a->dstpaddr;
    pktlen      = getCapLen() - offset;
}

quint16 ARPPacket::getType() {
    return type;
}

quint16 ARPPacket::getProtocol() {
    return protocol;
}

quint8 ARPPacket::getHAddrLen() {
    return haddrlen;
}

quint8 ARPPacket::getPAddrLen() {
    return paddrlen;
}

quint16 ARPPacket::getOpcode() {
    return opcode;
}

QString ARPPacket::getHSrc()
{
    QString qs = "";
    for (int i = 0; i < haddrlen; i++) {
        qs += QString::number(hSrc[i], 16);
        if (i != haddrlen - 1)
            qs += ':';
    }
    return qs;
}

QString ARPPacket::getPSrc() {
    QString qs = "";
    for (int i = 0; i < paddrlen; i++) {
        qs += QString::number(pSrc[i]);
        if (i != paddrlen - 1)
            qs += '.';
    }
    return qs;
}

QString ARPPacket::getHDst() {
    QString qs = "";
    for (int i = 0; i < haddrlen; i++) {
        qs += QString::number(hDst[i], 16);
        if (i != haddrlen - 1)
            qs += ':';
    }
    return qs;
}

QString ARPPacket::getPDst() {
    QString qs = "";
    for (int i = 0; i < paddrlen; i++) {
        qs += QString::number(pDst[i]);
        if (i != paddrlen - 1)
            qs += '.';
    }
    return qs;
}

quint32 ARPPacket::getPktLen() {
    return pktlen;
}
