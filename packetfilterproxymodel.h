#ifndef PACKETFILTERPROXYMODEL_H
#define PACKETFILTERPROXYMODEL_H

#include <QSortFilterProxyModel>

class PacketFilterProxyModel : public QSortFilterProxyModel
{
public:
    explicit PacketFilterProxyModel(QObject *parent = nullptr);

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;
    bool lessThan(const QModelIndex &left, const QModelIndex &right) const override;
};

#endif // PACKETFILTERPROXYMODEL_H
