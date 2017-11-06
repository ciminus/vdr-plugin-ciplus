#ifndef CCIPLUSRESOURCEHANDLER_H
#define CCIPLUSRESOURCEHANDLER_H

#include <vdr/ci.h>
#include "cCiPlusPrivate.h"
#include "cCiPlusApplicationInformation.h"
#include "cCiContentControl.h"
#include "cCiHostLanguageCountry.h"
#include "cCiCamFwUpgrade.h"
#include "cCiPlusHostControl.h"
#include "cCiOperatorProfile.h"
#include "cCiMultistream.h"

class cCiPlusResourceHandler : public cCiResourceHandler {
private:
    cCiPlusPrivate *privateData;
    int ciplus_version;
public:
    cCiPlusResourceHandler(cCiPlusPrivate *privateData, int ciplus_version);
    virtual ~cCiPlusResourceHandler();
    virtual const uint32_t *ResourceIds(void) const;
    virtual cCiSession *GetNewCiSession(uint32_t ResourceId, uint16_t SessionId, cCiTransportConnection *Tc);
};

#endif /* CCIPLUSSPECIFICATION_H */

