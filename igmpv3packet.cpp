#include "igmpv3packet.h"

Igmpv3Packet::Igmpv3Packet(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    igmpv3 i3 = (igmpv3)(rawpkt + offset);
    type = i3->type;
    maxresptime = i3->maxresptime;
    checksum = ntohs(i3->checksum);
    groupaddr = i3->groupaddr;
    resv = i3->rsq & 0xf0;
    s = i3->rsq & 0x08;
    qrv = i3->rsq & 0x07;
    qqic = i3->qqic;
    numberOfSource = ntohs(i3->nos);
}

quint8 Igmpv3Packet::getType() {
    return type;
}

quint8 Igmpv3Packet::getMaxRespTime() {
    if (maxresptime < 128)
        return maxresptime;
    quint8 mant = maxresptime & 0x0f;
    quint8 exp = (maxresptime & 0x70) >> 4;
    return (mant | 0x10) << (exp + 3);
}

quint16 Igmpv3Packet::getChecksum() {
    return checksum;
}

QString Igmpv3Packet::getGroupAddr() {
    QString qs;
    for (int i = 0; i < 4; i++) {
        qs += QString::number(i);
        if (i != 3)
            qs += '.';
    }
    return qs;
}

quint8 Igmpv3Packet::getResv() {
    return resv;
}

quint8 Igmpv3Packet::getS() {
    return s;
}

quint8 Igmpv3Packet::getQRV() {
    return qrv;
}

quint8 Igmpv3Packet::getQQI() {
    if (qqic < 128)
        return qqic;
    quint8 mant = qqic & 0x0f;
    quint8 exp = (qqic & 0x70) >> 4;
    return (mant | 0x10) << (exp + 3);          // reference: https://datatracker.ietf.org/doc/html/rfc3376#section-4.1.7
}

quint16 Igmpv3Packet::getNumberOfSource() {
    return numberOfSource;
}

bool Igmpv3Packet::check() {
    return false;                               // not implemented
}
