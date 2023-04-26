#include "ipv6packet.h"

IPv6Packet::IPv6Packet(Packet *pkt, quint16 offset) : Packet(pkt, offset) {
    ipv6hdr hdr             = (ipv6hdr)(rawpkt + offset);
#ifdef DEBUG
    qDebug() << QString("offset: %1").arg(offset);
#endif
    quint32 ver_ds_fl = ntohl(hdr->ver_ds_fl);
    version                 = ((ver_ds_fl & 0xf0000000) >> 28);
    diffServices            = ((ver_ds_fl & 0x0ff00000) >> 20);
    flowLabel               = ver_ds_fl & 0x000fffff;
    payloadlen              = ntohs(hdr->payloadlen);
    nexthdr                 = hdr->nexthdr;
    hoplimit                = hdr->hoplimit;
    src                     = hdr->src;
    dst                     = hdr->dst;
    pktlen                  = getCapLen() - offset;
}

quint8 IPv6Packet::getVersion() {
    return version;
}

quint8 IPv6Packet::getDiffServices() {
    return diffServices;
}

quint32 IPv6Packet::getFlowLabel() {
    return flowLabel;
}

quint16 IPv6Packet::getPayloadLen() {
    return payloadlen;
}

quint8 IPv6Packet::getNextHeader() {
    return nexthdr;
}

quint8 IPv6Packet::getHopLimit() {
    return hoplimit;
}

QString IPv6Packet::getSrc() {
    return getUnifiedString(src);
}

QString IPv6Packet::getDst() {
    return getUnifiedString(dst);
}

quint32 IPv6Packet::getPktLen() {
    return pktlen;
}

QString IPv6Packet::getUnifiedString(quint8 *a) {
    static QRegularExpression preambleZ("^0*");
    static QRegularExpression colon(":{3,}");
    QStringList sl;
    QString qs1 = "";
    for (int i = 0; i < 2; i++)
        qs1 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs1 = qs1.remove("^0*");
    QString qs2 = "";
    for (int i = 2; i < 4; i++)
        qs2 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs2 = qs2.remove("^0*");
    QString qs3 = "";
    for (int i = 4; i < 6; i++)
        qs3 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs3 = qs3.remove("^0*");
    QString qs4 = "";
    for (int i = 6; i < 8; i++)
        qs4 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs4 = qs4.remove("^0*");
    QString qs5 = "";
    for (int i = 8; i < 10; i++)
        qs5 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs5 = qs5.remove("^0*");
    QString qs6 = "";
    for (int i = 10; i < 12; i++)
        qs6 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs6 = qs6.remove("^0*");
    QString qs7 = "";
    for (int i = 12; i < 14; i++)
        qs7 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs7 = qs7.remove("^0*");
    QString qs8 = "";
    for (int i = 14; i < 16; i++)
        qs8 += QString("%1").arg(QString::number(a[i], 16), 2, '0');
    qs8 = qs8.remove("^0*");

    // simplify
    sl << qs1 << qs2 << qs3 << qs4 << qs5 << qs6 << qs7 << qs8;
    for (int i = 0; i < sl.size(); i++) {
        QString target = sl[i];
        sl[i] = target.remove(preambleZ);
    }
    QString tResult = sl.join(':');

    QRegularExpressionMatch rColon = colon.match(tResult);
    if (rColon.hasMatch()) {
        if (colon.captureCount() == 1)
            return tResult.replace(colon, "::");
        else {        // has multiple items captured
            QStringList items = rColon.capturedTexts();
            int maxIndex = -1;
            int max = -1;
            for (int i = 0; i < items.size(); i++) {
                if (items[i].length() > max) {
                    max = items[i].length();
                    maxIndex = i;
                }
            }
            QString maxItem = items[maxIndex];
            return tResult.replace(maxItem, "::");
        }
    }
    return tResult;
}
