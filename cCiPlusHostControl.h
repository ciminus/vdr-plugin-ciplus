#ifndef CCIPLUSHOSTCONTROL_H
#define CCIPLUSHOSTCONTROL_H

#include <vdr/ci.h>

#define RI_HOST_CONTROL_V2        0x00200042

#define AOT_TUNE                    0x9F8400
#define AOT_REPLACE                 0x9F8401
#define AOT_CLEAR_REPLACE           0x9F8402
#define AOT_ASK_RELEASE             0x9F8403
#define AOT_TUNE_BROADCAST_REQ      0x9F8404
#define AOT_TUNE_REPLY              0x9F8405
#define AOT_ASK_RELEASE_REPLY       0x9F8406


class cCiPlusHostControl : public cCiSession {
public:
  cCiPlusHostControl(uint16_t SessionId, cCiTransportConnection *Tc);
  virtual void Process(int Length = 0, const uint8_t *Data = NULL);
  };

#endif /* CCIPLUSHOSTCONTROL_H */

