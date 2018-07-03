// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOV_QT_SOVADDRESSVALIDATOR_H
#define SOV_QT_SOVADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class SOVAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit SOVAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** SOV address widget validator, checks for a valid sov address.
 */
class SOVAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit SOVAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // SOV_QT_SOVADDRESSVALIDATOR_H
