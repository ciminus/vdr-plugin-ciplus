#include "cCiPlusResourceHandler.h"
#include "ciplustools.h"
#include <vdr/tools.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

cCiPlusResourceHandler::cCiPlusResourceHandler(cCiPlusPrivate *privateData)
: privateData(privateData) {
}

cCiPlusResourceHandler::~cCiPlusResourceHandler() {
}

const uint32_t *cCiPlusResourceHandler::ResourceIds(void) const {
    // Mandory resources (See Table L.1: Resource Summary, Page 181 of CI Plus Specification V1.2 (2009-04))
    static uint32_t Ids[] = {
      RI_APPLICATION_INFORMATION_CIPLUS,
      RI_CONTENT_CONTROL,
      RI_HOST_LANGUAGE_COUNTRY,
      RI_CAM_UPGRADE,
      0
      };
    return Ids;
}

cCiSession *cCiPlusResourceHandler::GetNewCiSession(uint32_t ResourceId, uint16_t SessionId, cCiTransportConnection* Tc) {
    switch (ResourceId) {
        case RI_APPLICATION_INFORMATION_CIPLUS: return new cCiPlusApplicationInformation(SessionId, Tc);
        case RI_CONTENT_CONTROL:                return new cCiContentControl(SessionId, Tc, privateData);
        case RI_HOST_LANGUAGE_COUNTRY:          return new cCiHostLanguageCountry(SessionId, Tc);
        case RI_CAM_UPGRADE:                    return new cCiCamFwUpgrade(SessionId, Tc);
        default:                                return NULL;
    }
}
