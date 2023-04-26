#ifndef IPV6PACKET_H
#define IPV6PACKET_H

#include <QByteArray>
#include <QDebug>
#include <QMap>
#include <QRegularExpression>

#include "pktf.h"
#include "packet.h"

class IPv6Packet : public Packet {
public:
    IPv6Packet(Packet *, quint16);
    quint8                  getVersion();
    quint8                  getDiffServices();
    quint32                 getFlowLabel();
    quint16                 getPayloadLen();
    quint8                  getNextHeader();
    quint8                  getHopLimit();
    QString                 getSrc();
    QString                 getDst();
    quint32                 getPktLen() override;

private:
    QString                 getUnifiedString(quint8 *);

    const quint8            fixedLen = 40;                  // bytes
    quint8                  version;                        // ip version
    quint8                  diffServices;                   //
    quint32                 flowLabel;                      //
    quint16                 payloadlen;
    quint8                  nexthdr;                        //
    quint8                  hoplimit;                       // packet living, decrementing on each hop
    quint8                  *src;
    quint8                  *dst;
    quint32                 pktlen;
};

#endif // IPV6PACKET_H
