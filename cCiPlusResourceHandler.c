#include "cCiPlusResourceHandler.h"
#include "ciplustools.h"
#include <vdr/tools.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

cCiPlusResourceHandler::cCiPlusResourceHandler(cCiPlusPrivate *privateData, int ciplus_version)
: privateData(privateData), ciplus_version(ciplus_version) {
}

cCiPlusResourceHandler::~cCiPlusResourceHandler() {
}

const uint32_t *cCiPlusResourceHandler::ResourceIds(void) const {
    // Mandory resources (See Table L.1: Resource Summary, Page 181 of CI Plus Specification V1.2 (2009-04))
    static uint32_t IdsV12[] = {
      RI_APPLICATION_INFORMATION_CIPLUS,
      RI_CONTENT_CONTROL,
      RI_HOST_LANGUAGE_COUNTRY,
      RI_CAM_UPGRADE,
      0
      };
    static uint32_t IdsV13[] = {
      RI_APPLICATION_INFORMATION_CIPLUS,
      RI_HOST_CONTROL_V2,
      RI_CONTENT_CONTROL,
      RI_CONTENT_CONTROL_V2,
      RI_HOST_LANGUAGE_COUNTRY,
      RI_CAM_UPGRADE,
      RI_OPERATOR_PROFILE,
      0
      };
    if(ciplus_version == 12)
        return IdsV12;
    return IdsV13;
}

cCiSession *cCiPlusResourceHandler::GetNewCiSession(uint32_t ResourceId, uint16_t SessionId, cCiTransportConnection* Tc) {
    switch (ResourceId) {
        case RI_APPLICATION_INFORMATION_CIPLUS: return new cCiPlusApplicationInformation(SessionId, Tc);
        case RI_HOST_CONTROL_V2:                return new cCiPlusHostControl(SessionId,Tc);
        case RI_CONTENT_CONTROL:                return new cCiContentControl(SessionId, RI_CONTENT_CONTROL, Tc, privateData);
        case RI_CONTENT_CONTROL_V2:             return new cCiContentControl(SessionId, RI_CONTENT_CONTROL_V2, Tc, privateData);
        case RI_HOST_LANGUAGE_COUNTRY:          return new cCiHostLanguageCountry(SessionId, Tc);
        case RI_CAM_UPGRADE:                    return new cCiCamFwUpgrade(SessionId, Tc);
        case RI_OPERATOR_PROFILE:               return new cCiOperatorProfile(SessionId, Tc);
        default:                                return NULL;
    }
}
