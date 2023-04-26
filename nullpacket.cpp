#include "nullpacket.h"

NullPacket::NullPacket(Packet *pkt) : Packet(pkt, 0) {
    nullpkthdr hdr = (nullpkthdr)rawpkt;
    family = ntohl(hdr->family);
    pktlen = getCapLen();
}

quint32 NullPacket::getFamily() {
    return family;
}

quint32 NullPacket::getPktLen() {
    return pktlen;
}
