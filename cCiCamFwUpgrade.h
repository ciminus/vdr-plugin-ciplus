#ifndef CCICAMFWUPGRADE_H
#define CCICAMFWUPGRADE_H

#include <vdr/ci.h>

// Resource Identifiers:
#define RI_CAM_UPGRADE            0x008E1001

#define AOT_CAM_FW_UPGRADE          0x9F9D01
#define AOT_CAM_FW_UPGRADE_REPLY    0x9F9D02
#define AOT_CAM_FW_UPGRADE_PROGRESS 0x9F9D03
#define AOT_CAM_FW_UPGRADE_COMPLETE 0x9F9D04


class cCiCamFwUpgrade : public cCiSession {
public:
    cCiCamFwUpgrade(uint16_t SessionId, cCiTransportConnection *Tc);
    virtual ~cCiCamFwUpgrade();
    virtual void Process(int Length = 0, const uint8_t *Data = NULL);
};

#endif /* CCICAMFWUPGRADE_H */

