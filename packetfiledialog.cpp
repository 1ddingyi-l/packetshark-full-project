#include "packetfiledialog.h"

PacketFileDialog::PacketFileDialog() {

}

QString PacketFileDialog::getOpenPcapFileName() {
    return getOpenFileName(nullptr,
                           QString(),
                           QString(),
                           tr("pcapng (*.pcapng);;pcap (*.pcap)"));
}

QString PacketFileDialog::getSavePcapFileName() {
    return getSaveFileName(nullptr,
                           QString(),
                           QString(),
                           tr("pcapng (*.pcapng);;pcap (*.pcap)"));
}
