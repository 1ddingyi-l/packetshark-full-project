#include "igmppacket.h"

IgmpPacket::IgmpPacket(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    igmp i          = (igmp)(rawpkt + offset);
    type            = i->type;
    maxresptime     = i->maxresptime;
    checksum        = ntohs(i->checksum);
    groupaddr       = i->groupaddr;
    pktlen          = getCapLen() - offset;
}

quint32 IgmpPacket::getPktLen() {
    return pktlen;
}

bool IgmpPacket::check() {
    return false;                               // not implemented
}

quint8 IgmpPacket::getType() {
    return type;
}

quint8 IgmpPacket::getMaxRespTime() {
    if (maxresptime < 128)
        return maxresptime;
    quint8 mant = maxresptime & 0x0f;
    quint8 exp = (maxresptime & 0x70) >> 4;
    return (mant | 0x10) << (exp + 3);          // reference: https://datatracker.ietf.org/doc/html/rfc3376#section-4.1.1
}

quint16 IgmpPacket::getChecksum() {
    return checksum;
}

QString IgmpPacket::getGroupAddr() {
    QString qs = "";
    for (int i = 0; i < 4; i++) {
        qs += QString::number(groupaddr[i]);
        if (i != 3)
            qs += '.';
    }
    return qs;
}
