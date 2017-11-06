#ifndef CCIMULTISTREAM_H
#define CCIMULTISTREAM_H

#include <vdr/ci.h>

// Resource Identifiers:
#define RI_MULTISTREAM                      0x00900041

#define AOT_CICAM_MULTISTREAM_CAPABILITY      0x9F9200
#define AOT_PID_SELECT_REQ                    0x9F9201
#define AOT_PID_SELECT_REPLY                  0x9F9202


class cCiMultistream : public cCiSession {
public:
    cCiMultistream(uint16_t SessionId, cCiTransportConnection *Tc);
    virtual ~cCiMultistream();    
    virtual void Process(int Length = 0, const uint8_t *Data = NULL);


};

#endif /* CCIMULTISTREAM_H */

