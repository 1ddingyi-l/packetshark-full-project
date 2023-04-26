#include "ipv4packet.h"

IPv4Packet::IPv4Packet(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    ipv4hdr hdr         = (ipv4hdr)(rawpkt + offset);
    version             = ((hdr->version_hdrlen & 0xf0) >> 4);      // get ip version
    hdrlen              = (hdr->version_hdrlen & 0x0f) * 4;         // get header len (unit: 4-byte)
    diffServices        = hdr->sertype;
    totalLen            = ntohs(hdr->pktlen);                       // unit: 1-byte
    iden                = ntohs(hdr->iden);
    quint16 tmp         = ntohs(hdr->offset);
    flags               = tmp & 0xe000;                             // 0b1110 0000 0000 0000 = 0xe000
    fragmentOffset      = (tmp & 0x1fff) * 8;                       // unit: 8-byte
    ttl                 = hdr->ttl;
    protocol            = hdr->protocol;
    checksum            = ntohs(hdr->checksum);
    src                 = hdr->src;
    dst                 = hdr->dst;
    if (hdrlen != defaultLen)                                       // 20-byte
        options = hdr->opts;
    pktlen              = getCapLen() - offset;
}

quint8 IPv4Packet::getVersion() {
    return version;
}

quint8 IPv4Packet::getHeaderLen() {
    return hdrlen;
}

quint8 IPv4Packet::getDiffServices() {
    return diffServices;
}

quint16 IPv4Packet::getTotalLen() {
    return totalLen;
}

quint16 IPv4Packet::getIden() {
    return iden;
}

quint16 IPv4Packet::getFlags() {
    return flags;
}

quint16 IPv4Packet::getFragmentOffset() {
    return fragmentOffset;
}

quint8 IPv4Packet::getTtl() {
    return ttl;
}

quint8 IPv4Packet::getProtocol() {
    return protocol;
}

quint16 IPv4Packet::getChecksum() {
    return checksum;
}

QString IPv4Packet::getSrc() {
    QString qs = "";
    for (int i = 0; i < 4; i++) {
        qs += QString::number(src[i]);
        if (i != 3)
            qs += '.';
    }
    return qs;
}

QString IPv4Packet::getDst() {
    QString qs = "";
    for (int i = 0; i < 4; i++) {
        qs += QString::number(dst[i]);
        if (i != 3)
            qs += '.';
    }
    return qs;
}

bool IPv4Packet::hasOptions() {
    if (defaultLen == 20)
        return false;
    return hdrlen == defaultLen;
}

quint32 IPv4Packet::getPktLen() {
    return pktlen;
}

quint32 *IPv4Packet::getOptions() {
    return options;
}
