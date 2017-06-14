#include "cCiPlusApplicationInformation.h"
#include "ciplustools.h"

cCiPlusApplicationInformation::cCiPlusApplicationInformation(uint16_t SessionId, cCiTransportConnection *Tc)
: cCiApplicationInformation(SessionId, Tc) {
    SetResourceId(RI_APPLICATION_INFORMATION_CIPLUS);
}

cCiPlusApplicationInformation::~cCiPlusApplicationInformation() {
}

void cCiPlusApplicationInformation::Process(int Length, const uint8_t *Data)
{
    if (Data) {
     int len = Length;
     const uint8_t *data = Data;
     int Tag = GetTag(Length, &Data);
     switch (Tag) {
       case AOT_REQUEST_CICAM_RESET: {
            dbgprotocol("Slot %d: <== Request CICAM Reset (%d)\n", CamSlot()->SlotNumber(), SessionId());
            state = 3;
            CamSlot()->Reset(); // must be the last statement here, because cCamSlot::Reset() deletes all sessions!
            } 
            break;
       default: cCiApplicationInformation::Process(len, data);
       }
     }
  else if (state == 0)
     cCiApplicationInformation::Process(Length, Data);
  else if (state == 2 && !datarate_send) {
     dbgprotocol("Slot %d: ==> Data rate info (%d)\n", CamSlot()->SlotNumber(), SessionId());
     uint8_t datarate = DATA_RATE_96MBITS; // DATA_RATE_72MBITS;
     SendData(AOT_DATA_RATE_INFO, 1, &datarate);
     datarate_send = true;
     }
}
