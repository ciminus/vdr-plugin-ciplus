#include "cCiHostLanguageCountry.h"
#include "ciplustools.h"

cCiHostLanguageCountry::cCiHostLanguageCountry(uint16_t SessionId, cCiTransportConnection* Tc)
:cCiSession(SessionId, RI_HOST_LANGUAGE_COUNTRY, Tc) { 
    dbgprotocol("Slot %d: new HOST_LANGUAGE_COUNTRY (session id %d)\n", CamSlot()->SlotNumber(), SessionId);
}

cCiHostLanguageCountry::~cCiHostLanguageCountry() { }

void cCiHostLanguageCountry::Process(int Length, const uint8_t* Data) {
    if (Data) {
        int Tag = GetTag(Length, &Data);
        switch (Tag) {
            case AOT_HOST_COUNTRY_ENQ: {
                dbgprotocol("Slot %d: <== Host Country (%d)\n", CamSlot()->SlotNumber(), SessionId());
                SendData(AOT_HOST_COUNTRY, 3, lang);
                dbgprotocol("Slot %d: ==> Host Country(%s) (%d)\n", CamSlot()->SlotNumber(), lang, SessionId());
                break;
            }
            case AOT_HOST_LANGUAGE_ENQ: {
                dbgprotocol("Slot %d: <== Host Language (%d)\n", CamSlot()->SlotNumber(), SessionId());
                SendData(AOT_HOST_LANGUAGE, 3, lang);
                dbgprotocol("Slot %d: ==> Host Language(%s) (%d)\n", CamSlot()->SlotNumber(), lang, SessionId());
                break;
            }
            default: esyslog("ERROR: CAM %d: HostLanguageCountry: unknown tag %06X", CamSlot()->SlotNumber(), Tag);
        }
    }
}

