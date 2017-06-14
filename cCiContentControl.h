#ifndef CCICONTENTCONTROL_H
#define CCICONTENTCONTROL_H

#include <vdr/ci.h>
#include "cCiPlusCredentials.h"

// Resource Identifiers:
#define RI_CONTENT_CONTROL        0x008C1001

// Content Control
#define AOT_CC_OPEN_REQ             0x9F9001
#define AOT_CC_OPEN_CNF             0x9F9002
#define AOT_CC_DATA_REQ             0x9F9003
#define AOT_CC_DATA_CNF             0x9F9004
#define AOT_CC_SYNC_REQ             0x9F9005
#define AOT_CC_SYNC_CNF             0x9F9006
#define AOT_CC_SAC_DATA_REQ         0x9F9007
#define AOT_CC_SAC_DATA_CNF         0x9F9008
#define AOT_CC_SAC_SYNC_REQ         0x9F9009
#define AOT_CC_SAC_SYNC_CNF         0x9F9010

#define TSC_EVEN                    0x80
#define TSC_ODD                     0xc0

class cCiContentControl : public cCiSession {
private:
    uint8_t payloadBuf[184] = { 0 };
    struct TsDecryptionKeyData key_register[2];
    cCiPlusCredentials credentials;
    
    int state;
    
    void cc_open_cnf();
    void cc_data_cnf(int Length, const uint8_t* Data);
    void cc_sync_cnf();
    void cc_sac_data_cnf(int Length, const uint8_t* Data);
    void cc_sac_sync_cnf(int Length, const uint8_t* Data);
    
    bool cc_sac_send(int tag, uint8_t *data, unsigned int pos);
    
public:
  cCiContentControl(uint16_t SessionId, cCiTransportConnection *Tc, cCiPlusPrivate *ciplusPrivate);
  virtual ~cCiContentControl();
  virtual void Process(int Length = 0, const uint8_t *Data = NULL);
  bool TsPostProcess(uint8_t *tsPacket);
};

#endif /* CCICONTENTCONTROL_H */

