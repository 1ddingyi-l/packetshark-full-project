#include "packet.h"

Packet::Packet(quint64 number,
               pcap_pkthdr *pkthdr,
               qint32 linktype,
               const u_char *raw,
               quint16 offset,
               QString name,
               QString description) {
    this->number = number;
    this->pkthdr = *pkthdr;
    this->linktype = linktype;
    this->len = pkthdr->len;
    this->caplen = pkthdr->caplen;
    tv = pkthdr->ts;
    this->offset = offset;
    rawpkt = (u_char *)malloc(sizeof(u_char) * caplen);
    memcpy((u_char *)rawpkt, raw, sizeof(u_char) * caplen);
    fromDeviceName = name;
    fromDeviceDescription = description;
}

Packet::Packet(Packet *pkt, quint16 offset) {
    number = pkt->number;
    pkthdr = pkt->pkthdr;
    linktype = pkt->linktype;
    len = pkt->len;
    caplen = pkt->caplen;
    tv = pkt->tv;
    this->offset = offset == 0 ? pkt->offset : offset;
    rawpkt = (u_char *)malloc(sizeof(u_char) * caplen);
    memcpy((u_char *)rawpkt, pkt->rawpkt, sizeof(u_char) * caplen);
    fromDeviceName = pkt->fromDeviceName;
    fromDeviceDescription = pkt->fromDeviceDescription;
    protocolStack = pkt->protocolStack;
}

Packet::~Packet() {
    if (rawpkt == nullptr)
        return;
    free((u_char *)rawpkt);
}

quint64 Packet::getNumber() {
    return number;
}

quint32 Packet::getLen() {
    return len;
}

quint32 Packet::getCapLen() {
    return caplen;
}

quint32 Packet::getPktLen() {
    return caplen;
}

qint32 Packet::getLinkType() {
    return linktype;
}

quint16 Packet::getOffset() {
    return offset;
}

struct timeval Packet::getTimeval() {
    return tv;
}

QColor Packet::getColor() {
    switch (mark) {
    case ipv4pkt: return QColor::fromRgb(0xF4C3C3);
    case ipv6pkt: return QColor::fromRgb(0xFCFB7D);
    case arppkt: return QColor::fromRgb(0xfff1b8);
    case icmppkt: return QColor::fromRgb(0xF4C3EE);
    case igmppkt: return QColor::fromRgb(0xF4E2C3);
    case tcppkt: return QColor::fromRgb(0xB6F497);
    case udppkt: return QColor::fromRgb(0x99F0FF);
    case dnspkt: return QColor::fromRgb(0xC3E2F4);
    case httppkt: return QColor::fromRgb(0xB6F497);
    case httpspkt: return QColor::fromRgb(0xd9f7be);  //
    case etherpkt:
    default: return QColor::fromRgb(0xbfbfbf);
    }
}

u_char Packet::getByte(quint32 index) {
    if (index >= caplen)
        return '\0';
    return rawpkt[index];
}

const pcap_pkthdr Packet::getHeader() {
    return pkthdr;
}

void Packet::setMark(qint32 m) {
    mark = m;
}

QString Packet::getProtocolStack() {
    return protocolStack;
}

void Packet::setProtocolStack(QString protocolStack) {
    this->protocolStack = protocolStack;
}

QString Packet::getFromDeviceName() {
    return fromDeviceName;
}

QString Packet::getFromDeviceDescription() {
    return fromDeviceDescription;
}
