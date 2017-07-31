#include "cCiOperatorProfile.h"
#include "ciplustools.h"

cCiOperatorProfile::cCiOperatorProfile(uint16_t SessionId, cCiTransportConnection *Tc)
:cCiSession(SessionId, RI_OPERATOR_PROFILE, Tc) {
    dbgprotocol("Slot %d: new OPERATOR_PROFILE (session id %d)\n", CamSlot()->SlotNumber(), SessionId);
}

cCiOperatorProfile::~cCiOperatorProfile() {
}

void cCiOperatorProfile::Process(int Length, const uint8_t* Data) {
    if (Data) {
        int Tag = GetTag(Length, &Data);
        switch (Tag) {
            case AOT_OPERATOR_STATUS:
            case AOT_OPERATOR_NIT:
            case AOT_OPERATOR_INFO:
            case AOT_OPERATOR_SEARCH_STATUS:
            case AOT_OPERATOR_TUNE: {
                dbgprotocol("Slot %d: <== Operator Profile 0x%06x (%d)\n", CamSlot()->SlotNumber(), Tag, SessionId());
            }
            default: esyslog("ERROR: CAM %d: Operator Profile: unknown tag %06X", CamSlot()->SlotNumber(), Tag);
        }
    }
}
