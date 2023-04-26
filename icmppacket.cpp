#include "icmppacket.h"

IcmpPacket::IcmpPacket(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    icmp i = (icmp)(rawpkt + offset);
    type            = i->type;
    code            = i->code;
    checksum        = ntohs(i->checksum);
    iden            = ntohs(i->iden);
    seq             = ntohs(i->seq);
    pktlen          = getCapLen() - offset;
    data            = (rawpkt + offset + 8);
}

quint8 IcmpPacket::getType() {
    return type;
}

quint8 IcmpPacket::getCode() {
    return code;
}

quint16 IcmpPacket::getChecksum() {
    return checksum;
}

quint16 IcmpPacket::getIden() {
    return iden;
}

quint16 IcmpPacket::getSeq() {
    return seq;
}

quint32 IcmpPacket::getPktLen() {
    return pktlen;
}

const u_char * IcmpPacket::getData() {
    return data;
}
