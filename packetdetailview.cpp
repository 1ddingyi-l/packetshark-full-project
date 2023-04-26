#include "packetdetailview.h"
#include "ui_packetdetailview.h"

PacketDetailView::PacketDetailView(Packet *pkt, QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::PacketDetailView) {
    ui->setupUi(this);
    this->pkt = new Packet(pkt);
}

PacketDetailView::~PacketDetailView() {
    delete ui;
    delete pkt;
}

void PacketDetailView::showEvent(QShowEvent *) {
    /* set table widget */
    ui->detailedPacketView->setFont(detailedPacketViewFont);
    ui->detailedPacketView->setHeaderHidden(true);
    /* set text browser */
    ui->rawPacketView->setFont(rawPacketViewFont);
    ui->rawPacketView->setWordWrapMode(QTextOption::NoWrap);

    // show infomation by tree widget
    ui->detailedPacketView->clear();                                    // clear old data item
    QVector<QTreeWidgetItem *> items;
    // show infomation by tree widget
    quint32 linktype = pkt->getLinkType();
    switch (linktype) {
    case DLT_EN10MB: {
        EthernetPacket epkt(pkt);
        QString src = epkt.getSrc();
        QString dst = epkt.getDst();
        quint16 type = epkt.getUpperType();
        QTreeWidgetItem *linklayer = new QTreeWidgetItem(QStringList() << "Ethernet II, Src: " + src + ", Dst: " + dst);
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination: " + dst));
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Source: " + src));
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: 0x" + QString::number(type, 16)));
        items.append(linklayer);
        switch (type) {
        case 0x0800: {                                                  // ipv4
            IPv4Packet ipv4pkt(pkt, 14);
            quint8 version = ipv4pkt.getVersion();
            quint8 hdrlen = ipv4pkt.getHeaderLen();
            quint8 diffSerives = ipv4pkt.getDiffServices();
            quint16 totalLen = ipv4pkt.getTotalLen();
            quint16 iden = ipv4pkt.getIden();
            quint16 flags = ipv4pkt.getFlags();
            quint16 offset = ipv4pkt.getFragmentOffset();
            quint8 ttl = ipv4pkt.getTtl();
            quint8 protocol = ipv4pkt.getProtocol();
            quint16 checksum = ipv4pkt.getChecksum();
            QString src = ipv4pkt.getSrc();
            QString dst = ipv4pkt.getDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Internet Protocol Version 4, Src: " + src + ", Dst: " + dst);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Version: " + QString::number(version)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Differentiated Services Field: 0x" + QString::number(diffSerives, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Total Length: " + QString::number(totalLen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Identification: 0x" + QString::number(iden, 16)));
            QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
            for (quint16 i = 0x8000; i != 0x1000; i >>= 1) {
                if ((i & flags) != 0)
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 1"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 1"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 1"));
                        break;
                    }
                else
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 0"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 0"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 0"));
                        break;
                    }
            }
            networklayer->addChild(flagswidget);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Fragment Offset: " + QString::number(offset)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Time to Live: : " + QString::number(ttl)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol: " + QString::number(protocol)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Checksum: 0x" + QString::number(checksum, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Source Address: " + src));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Address: " + dst));
            items.append(networklayer);
            switch (protocol) {
            case 0x01: {                                                // icmp
                IcmpPacket icmppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint8 type = icmppkt.getType();
                quint8 code = icmppkt.getCode();
                quint16 checksum = icmppkt.getChecksum();
                quint16 iden = icmppkt.getIden();
                quint16 seq = icmppkt.getSeq();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Control Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Code: " + QString::number(code)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Identifier: " + QString::number(iden)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence: " + QString::number(seq)));
                items.append(beforeNetworklayer);
                break;
            }
            case 0x02: {                                                // igmp
                IgmpPacket igmppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint8 type = igmppkt.getType();
                quint8 maxRespTime = igmppkt.getMaxRespTime();
                quint16 checksum = igmppkt.getChecksum();
                QString groupaddr = igmppkt.getGroupAddr();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Group Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Max Resp Time: 0x" + QString::number(maxRespTime, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Multicast Address: " + groupaddr));
                if (type == 0x22) {                                     // igmpv3
                    Igmpv3Packet igmpv3pkt(pkt, 14 + ipv4pkt.getHeaderLen());
                    quint8 reserved = igmpv3pkt.getResv();
                    quint8 s = igmpv3pkt.getS();
                    quint8 qrv = igmpv3pkt.getQRV();
                    quint8 qqi = igmpv3pkt.getQQI();
                    quint16 nos = igmpv3pkt.getNumberOfSource();
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Reserved: " + QString::number(reserved)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "S Flag: " + QString::number(s)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Robustness Variable: " + QString::number(qrv)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Query Interval: " + QString::number(qqi)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Number of Sources: " + QString::number(nos)));
                }
                items.append(beforeNetworklayer);
                break;
            }
            case 0x06: {                                                // tcp
                TcpPacket tcppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint16 srcPort = tcppkt.getSrcPort();
                quint16 dstPort = tcppkt.getDstPort();
                quint32 seqNumber = tcppkt.getSeqN();
                quint32 ackNumber = tcppkt.getAckN();
                quint8 hdrlen = tcppkt.gethdrlen();
                quint16 flags = tcppkt.getFlags();
                quint16 winsize = tcppkt.getWinSize();
                quint16 checksum = tcppkt.getChecksum();
                quint16 urgptr = tcppkt.getUrgptr();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "Transmission Control Protocol: Src Port: " + QString::number(srcPort) +
                                                                      ", Dst port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + QString::number(seqNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Acknowledge Number: " + QString::number(ackNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
                QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
                for (int i = 0x001; i != 0x200; i <<= 1) {
                    if ((i & flags) != 0)
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 1"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 1"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 1"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 1"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 1"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 1"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 1"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 1"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 1"));
                            break;
                        }
                    else
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 0"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 0"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 0"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 0"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 0"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 0"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 0"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 0"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 0"));
                            break;
                        }
                }
                transportlayer->addChild(flagswidget);
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Window Size: " + QString::number(winsize)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Urgent Pointer: " + QString::number(urgptr)));
                items.append(transportlayer);
                break;
            }
            case 0x11: {                                                // udp
                UdpPacket udppkt(pkt, 14 + ipv4pkt.getHeaderLen());
                quint16 srcPort = udppkt.getSrcPort();
                quint16 dstPort = udppkt.getDstPort();
                quint16 checksum = udppkt.getChecksum();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "User Datagram Protocol, Src Port: " + QString::number(srcPort) + ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                items.append(transportlayer);
                break;
            }
            }
            break;
        }
        case 0x0806: {                                                  // arp
            ARPPacket arppkt(pkt, 14);
            quint16 htype = arppkt.getType();
            quint16 ptype = arppkt.getProtocol();
            quint8  hsize = arppkt.getHAddrLen();
            quint8  psize = arppkt.getPAddrLen();
            quint16 opcode = arppkt.getOpcode();
            QString hsrc = arppkt.getHSrc();
            QString psrc = arppkt.getPSrc();
            QString hdst = arppkt.getHDst();
            QString pdst = arppkt.getPDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Address Resolution Protocol");
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Hardware Type: " + QString::number(htype)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol Type: 0x" + QString::number(ptype, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Hardware Size: " + QString::number(hsize)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol Size: " + QString::number(psize)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Opcode: " + QString::number(opcode)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Sender Hardware Address: " + hsrc));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Sender Protocol Address: " + psrc));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Target Hardware Address: " + hdst));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Target Protocol Address: " + pdst));
            items.append(networklayer);
            break;
        }
        case 0x86dd:  {                                                 // ipv6
            IPv6Packet ipv6pkt(pkt, 14);
            quint8 version = ipv6pkt.getVersion();
            quint8 tf = ipv6pkt.getDiffServices();
            quint32 fl = ipv6pkt.getFlowLabel();
            quint16 payloadlen = ipv6pkt.getPayloadLen();
            quint8 nexthdr = ipv6pkt.getNextHeader();
            quint8 hoplimit = ipv6pkt.getHopLimit();
            QString src = ipv6pkt.getSrc();
            QString dst = ipv6pkt.getDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Internet Protocol Version 6, Src: " + src + ", Dst: " + dst);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Version: " + QString::number(version)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Traffic Class: 0x" + QString::number(tf, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Flow Label: 0x" + QString::number(fl, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Payload Length: " + QString::number(payloadlen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Next Header: " + QString::number(nexthdr)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Hop Limit: " + QString::number(hoplimit)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Source Address: " + src));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Address: " + dst));
            items.append(networklayer);
            switch (nexthdr) {
            case 0x06: {                                                // tcp
                TcpPacket tcppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                quint16 srcPort = tcppkt.getSrcPort();
                quint16 dstPort = tcppkt.getDstPort();
                quint32 seqNumber = tcppkt.getSeqN();
                quint32 ackNumber = tcppkt.getAckN();
                quint8 hdrlen = tcppkt.gethdrlen();
                quint16 flags = tcppkt.getFlags();
                quint16 winsize = tcppkt.getWinSize();
                quint16 checksum = tcppkt.getChecksum();
                quint16 urgptr = tcppkt.getUrgptr();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "Transmission Control Protocol: Src Port: " + QString::number(srcPort) +
                                                                      ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + QString::number(seqNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Acknowledge Number: " + QString::number(ackNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
                QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
                for (int i = 0x001; i != 0x200; i <<= 1) {
                    if ((i & flags) != 0)
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 1"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 1"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 1"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 1"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 1"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 1"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 1"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 1"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 1"));
                            break;
                        }
                    else
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 0"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 0"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 0"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 0"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 0"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 0"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 0"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 0"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 0"));
                            break;
                        }
                }
                transportlayer->addChild(flagswidget);
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Window Size: " + QString::number(winsize)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Urgent Pointer: " + QString::number(urgptr)));
                items.append(transportlayer);
                break;
            }
            case 0x11: {                                                // udp
                UdpPacket udppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                quint16 srcPort = udppkt.getSrcPort();
                quint16 dstPort = udppkt.getDstPort();
                quint16 checksum = udppkt.getChecksum();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "User Datagram Protocol, Src Port: " + QString::number(srcPort) + ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                items.append(transportlayer);
                break;
            }
            case 0x3a: {                                                // icmp
                IcmpPacket icmppkt(pkt, 14 + ipv6pkt.getPktLen() - ipv6pkt.getPayloadLen());
                quint8 type = icmppkt.getType();
                quint8 code = icmppkt.getCode();
                quint16 checksum = icmppkt.getChecksum();
                quint16 iden = icmppkt.getIden();
                quint16 seq = icmppkt.getSeq();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Control Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Code: " + QString::number(code)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Identifier: " + QString::number(iden)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence: " + QString::number(seq)));
                items.append(beforeNetworklayer);
                break;
            }
            }
            break;
        }
        }
        break;
    }
    case DLT_NULL: {
        NullPacket nullpkt(pkt);
        quint32 family = nullpkt.getFamily();
        QTreeWidgetItem *linklayer = new QTreeWidgetItem(QStringList() << "Null/Loopback");
        linklayer->addChild(new QTreeWidgetItem(QStringList() << "Family: 0x" + QString::number(family, 16)));
        items.append(linklayer);
        switch (family) {
        case 0x02000000: {                                              // ipv4
            IPv4Packet ipv4pkt(pkt, 4);
            quint8 version = ipv4pkt.getVersion();
            quint8 hdrlen = ipv4pkt.getHeaderLen();
            quint8 diffSerives = ipv4pkt.getDiffServices();
            quint16 totalLen = ipv4pkt.getTotalLen();
            quint16 iden = ipv4pkt.getIden();
            quint16 flags = ipv4pkt.getFlags();
            quint16 offset = ipv4pkt.getFragmentOffset();
            quint8 ttl = ipv4pkt.getTtl();
            quint8 protocol = ipv4pkt.getProtocol();
            quint16 checksum = ipv4pkt.getChecksum();
            QString src = ipv4pkt.getSrc();
            QString dst = ipv4pkt.getDst();
            QTreeWidgetItem *networklayer = new QTreeWidgetItem(QStringList() << "Internet Protocol Version 4, Src: " + src + ", Dst: " + dst);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Version: " + QString::number(version)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Differentiated Services Field: 0x" + QString::number(diffSerives, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Total Length: " + QString::number(totalLen)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Identification: 0x" + QString::number(iden, 16)));
            QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
            for (quint16 i = 0x8000; i != 0x1000; i >>= 1) {
                if ((i & flags) != 0)
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 1"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 1"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 1"));
                        break;
                    }
                else
                    switch (i) {
                    case 0x8000:                                        // reserved bit
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Reserved bit: 0"));
                        break;
                    case 0x4000:                                        // don't fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "Don't fragment: 0"));
                        break;
                    case 0x2000:                                        // more fragment
                        flagswidget->addChild(new QTreeWidgetItem(QStringList() << "More fragments: 0"));
                        break;
                    }
            }
            networklayer->addChild(flagswidget);
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Fragment Offset: " + QString::number(offset)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Time to Live: : " + QString::number(ttl)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Protocol: " + QString::number(protocol)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Header Checksum: 0x" + QString::number(checksum, 16)));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Source Address: " + src));
            networklayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Address: " + dst));
            items.append(networklayer);
            switch (protocol) {
            case 0x01: {                                                // icmp
                IcmpPacket icmppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint8 type = icmppkt.getType();
                quint8 code = icmppkt.getCode();
                quint16 checksum = icmppkt.getChecksum();
                quint16 iden = icmppkt.getIden();
                quint16 seq = icmppkt.getSeq();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Control Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Code: " + QString::number(code)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Identifier: " + QString::number(iden)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence: " + QString::number(seq)));
                items.append(beforeNetworklayer);
                break;
            }
            case 0x02: {                                                // igmp
                IgmpPacket igmppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint8 type = igmppkt.getType();
                quint8 maxRespTime = igmppkt.getMaxRespTime();
                quint16 checksum = igmppkt.getChecksum();
                QString groupaddr = igmppkt.getGroupAddr();
                QTreeWidgetItem *beforeNetworklayer = new QTreeWidgetItem(QStringList() << "Internet Group Message Protocol");
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Type: " + QString::number(type)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Max Resp Time: 0x" + QString::number(maxRespTime, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Multicast Address: " + groupaddr));
                if (type == 0x22) {                                     // igmpv3
                    Igmpv3Packet igmpv3pkt(pkt, 4 + ipv4pkt.getHeaderLen());
                    quint8 reserved = igmpv3pkt.getResv();
                    quint8 s = igmpv3pkt.getS();
                    quint8 qrv = igmpv3pkt.getQRV();
                    quint8 qqi = igmpv3pkt.getQQI();
                    quint16 nos = igmpv3pkt.getNumberOfSource();
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Reserved: " + QString::number(reserved)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "S Flag: " + QString::number(s)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Robustness Variable: " + QString::number(qrv)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Querier's Query Interval: " + QString::number(qqi)));
                    beforeNetworklayer->addChild(new QTreeWidgetItem(QStringList() << "Number of Sources: " + QString::number(nos)));
                }
                items.append(beforeNetworklayer);
                break;
            }
            case 0x06: {                                                // tcp
                TcpPacket tcppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint16 srcPort = tcppkt.getSrcPort();
                quint16 dstPort = tcppkt.getDstPort();
                quint32 seqNumber = tcppkt.getSeqN();
                quint32 ackNumber = tcppkt.getAckN();
                quint8 hdrlen = tcppkt.gethdrlen();
                quint16 flags = tcppkt.getFlags();
                quint16 winsize = tcppkt.getWinSize();
                quint16 checksum = tcppkt.getChecksum();
                quint16 urgptr = tcppkt.getUrgptr();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "Transmission Control Protocol: Src Port: " + QString::number(srcPort) +
                                                                      ", Dst port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number: " + QString::number(seqNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Acknowledge Number: " + QString::number(ackNumber)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Header Length: " + QString::number(hdrlen)));
                QTreeWidgetItem *flagswidget = new QTreeWidgetItem(QStringList() << "Flags: 0x" + QString::number(flags, 16));
                for (int i = 0x001; i != 0x200; i <<= 1) {
                    if ((i & flags) != 0)
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 1"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 1"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 1"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 1"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 1"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 1"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 1"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 1"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 1"));
                            break;
                        }
                    else
                        switch (i) {
                        case 0x001:                                     // fin
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "FIN: 0"));
                            break;
                        case 0x002:                                     // syn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "SYN: 0"));
                            break;
                        case 0x004:                                     // rst
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "RST: 0"));
                            break;
                        case 0x008:                                     // psh
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "PSH: 0"));
                            break;
                        case 0x010:                                     // ack
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ACK: 0"));
                            break;
                        case 0x020:                                     // urg
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "URG: 0"));
                            break;
                        case 0x040:                                     // ecn
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "ECN: 0"));
                            break;
                        case 0x080:                                     // cwr
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "CWR: 0"));
                            break;
                        case 0x100:                                     // nonce
                            flagswidget->addChild(new QTreeWidgetItem(QStringList() << "NONCE: 0"));
                            break;
                        }
                }
                transportlayer->addChild(flagswidget);
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Window Size: " + QString::number(winsize)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Urgent Pointer: " + QString::number(urgptr)));
                items.append(transportlayer);
                break;
            }
            case 0x11: {                                                // udp
                UdpPacket udppkt(pkt, 4 + ipv4pkt.getHeaderLen());
                quint16 srcPort = udppkt.getSrcPort();
                quint16 dstPort = udppkt.getDstPort();
                quint16 checksum = udppkt.getChecksum();
                QTreeWidgetItem *transportlayer = new QTreeWidgetItem(QStringList() << "User Datagram Protocol, Src Port: " + QString::number(srcPort) + ", Dst Port: " + QString::number(dstPort));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Source Port: " + QString::number(srcPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Destination Port: " + QString::number(dstPort)));
                transportlayer->addChild(new QTreeWidgetItem(QStringList() << "Checksum: 0x" + QString::number(checksum, 16)));
                items.append(transportlayer);
                break;
            }
            }
            break;
        }
        }
        break;
    }
    default: {
        break;
    }
    }
    QTreeWidgetItem *rawinfo = new QTreeWidgetItem(QStringList() << "Frame " + QString::number(pkt->getNumber()) + ": " +
                                                    QString::number(pkt->getLen()) +
                                                    " bytes on wire (" + QString::number(pkt->getLen() * 8) + " bits), " +
                                                    QString::number(pkt->getCapLen()) + " bytes captured (" +
                                                    QString::number(pkt->getCapLen() * 8) + " bits) on interface " + pkt->getFromDeviceName());
    QString protocolStack = pkt->getProtocolStack();
    QTreeWidgetItem *deviceInfo = new QTreeWidgetItem(QStringList() << "Interface: " + pkt->getFromDeviceName());
    deviceInfo->addChild(new QTreeWidgetItem(QStringList() << "Interface name: " + pkt->getFromDeviceName()));
    deviceInfo->addChild(new QTreeWidgetItem(QStringList() << "Interface description: " + pkt->getFromDeviceDescription()));
    rawinfo->addChild(deviceInfo);
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Encapsulation type: " + QString::number(linktype)));
    time_t time_sec = pkt->getTimeval().tv_sec;
    struct tm *datetime = localtime(&time_sec);
    datetime->tm_year += 1900;
    datetime->tm_mon++;
    QString datetimeStr = QString::number(datetime->tm_year) + '-' + QString::number(datetime->tm_mon) + '-' +
            QString::number(datetime->tm_mday) + ' ' + QString::number(datetime->tm_hour) + ':' + QString::number(datetime->tm_min) +
            ':' + QString::number(datetime->tm_sec) + '.' + QString::number(pkt->getTimeval().tv_usec);
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Arrival Time: " + datetimeStr));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Epoch Time: " + QString::number(pkt->getTimeval().tv_sec) + '.' +
                                          QString::number(pkt->getTimeval().tv_usec) + " seconds"));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Frame Number: " + QString::number(pkt->getNumber())));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Frame Length: " + QString::number(pkt->getLen()) + " bytes (" +
                                          QString::number(pkt->getLen() * 8) + " bits)"));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Capture Length: " + QString::number(pkt->getCapLen()) +
                                          " bytes (" + QString::number(pkt->getCapLen() * 8) + " bits)"));
    rawinfo->addChild(new QTreeWidgetItem(QStringList() << "Protocols in frame: " + protocolStack));
    items.prepend(rawinfo);
    ui->detailedPacketView->addTopLevelItems(items);



    // show infomation by text browser
    quint64 pktlen = pkt->getCapLen();
    QString text;
    for (quint32 i = 1; i <= pktlen; i += 16) {
        QString line = QString("%1").arg(i - 1, 4, 16, QLatin1Char('0')) + "   ";
        for (quint32 j = i - 1; j < qMin(pktlen, (i + 16) - 1); j++) {
            line += QString("%1").arg(pkt->getByte(j), 2, 16, QLatin1Char('0')) + ' ';
            if ((j + 1) % 8 == 0)
                line += ' ';
        }
        if ((i + 16) > pktlen) {                                        // the last row
            while (line.size() != 60 - 3)
                line += ' ';
        }
        line += "   ";                                                  // 3
//        qDebug() << line.size();                                      // by this get aligning position (60)
        for (quint32 z = i - 1; z < qMin(pktlen, (i + 16) - 1); z++) {
            if (pkt->getByte(z) >= 33 && pkt->getByte(z) <= 126)
                line += QChar(pkt->getByte(z));
            else
                line += "·";
            if ((z + 1) % 8 == 0)
                line += ' ';
        }
        text += line;
        if (i < pktlen)
            text += '\n';
    }
    ui->rawPacketView->setText(text);
}
