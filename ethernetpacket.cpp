#include "ethernetpacket.h"

EthernetPacket::EthernetPacket(Packet *pkt) : Packet(pkt){
    etherhdr hdr = (etherhdr)rawpkt;
    src = hdr->src;
    dst = hdr->dst;
    type = ntohs(hdr->type);
}

QString EthernetPacket::getSrc() {
    QString qs = "";
    for (int i = 0; i < 6; i++) {
        qs += QString("%1").arg(QString::number(src[i], 16), 2, '0');
        if (i != 5)
            qs += ':';
    }
    return qs;
}

QString EthernetPacket::getDst()
{
    QString qs = "";
    for (int i = 0; i < 6; i++) {
        qs += QString("%1").arg(QString::number(dst[i], 16), 2, '0');
        if (i != 5)
            qs += ':';
    }
    return qs;
}

EthernetPacket::protocol EthernetPacket::getUpperType() {
    return (EthernetPacket::protocol)type;
}

quint32 EthernetPacket::getPktLen() {
    return getCapLen();
}
