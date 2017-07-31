#ifndef CCIOPERATORPROFILE_H
#define CCIOPERATORPROFILE_H

#include <vdr/ci.h>

// Resource Identifiers:
#define RI_OPERATOR_PROFILE           0x008F1001

#define AOT_OPERATOR_STATUS_REQ         0x9F9C00
#define AOT_OPERATOR_STATUS             0x9F9C01
#define AOT_OPERATOR_NIT_REQ            0x9F9C02
#define AOT_OPERATOR_NIT                0x9F9C03
#define AOT_OPERATOR_INFO_REQ           0x9F9C04
#define AOT_OPERATOR_INFO               0x9F9C05
#define AOT_OPERATOR_SEARCH_START       0x9F9C06
#define AOT_OPERATOR_SEARCH_STATUS      0x9F9C07
#define AOT_OPERATOR_EXIT               0x9F9C08
#define AOT_OPERATOR_TUNE               0x9F9C09
#define AOT_OPERATOR_TUNE_STATUS        0x9F9C0A
#define AOT_OPERATOR_ENTITLEMENT_ACK    0x9F9C0B
#define AOT_OPERATOR_SEARCH_CANCEL      0x9F9C0C


class cCiOperatorProfile : public cCiSession {
public:
    cCiOperatorProfile(uint16_t SessionId, cCiTransportConnection *Tc);
    virtual ~cCiOperatorProfile();
    virtual void Process(int Length = 0, const uint8_t *Data = NULL);
};

#endif /* CCIOPERATORPROFILE_H */

