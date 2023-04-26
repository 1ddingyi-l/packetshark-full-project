#include "packetfilterproxymodel.h"

#include <QMetaType>

PacketFilterProxyModel::PacketFilterProxyModel(QObject *parent)
    : QSortFilterProxyModel{parent}
{

}

bool PacketFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    return true;  // accept all packets whatever it is
}

bool PacketFilterProxyModel::lessThan(const QModelIndex &left, const QModelIndex &right) const
{
    QVariant leftData = sourceModel()->data(left);
    QVariant rightData = sourceModel()->data(right);

    switch (left.column()) {
    case 0: {   // num
        long le = qvariant_cast<long>(leftData);
        long ri = qvariant_cast<long>(rightData);
        return le > ri;
    }
    case 1: {  // arrtime
        double le = qvariant_cast<double>(leftData);
        double ri = qvariant_cast<double>(rightData);
        return le > ri;
    }
    case 4: {   // caplen
        int le = qvariant_cast<int>(leftData);
        int ri = qvariant_cast<int>(rightData);
        return le > ri;
    }
    case 2:     // src
    case 3:     // dst
    case 5:     // protocol
    case 6:     // info
    default:
        break;
    }
    return qvariant_cast<QString>(leftData) > qvariant_cast<QString>(rightData);
}
