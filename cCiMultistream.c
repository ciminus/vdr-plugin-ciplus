#include "cCiMultistream.h"
#include "ciplustools.h"

cCiMultistream::cCiMultistream(uint16_t SessionId, cCiTransportConnection *Tc) 
:cCiSession(SessionId, RI_MULTISTREAM, Tc) {
    dsyslog("CAM %d: new MULTISTREAM (session id %d)\n", CamSlot()->SlotNumber(), SessionId);
}

cCiMultistream::~cCiMultistream() {
}

void cCiMultistream::Process(int Length, const uint8_t* Data) {
    if (Data) {
        int Tag = GetTag(Length, &Data);
        int length = 0;
        const uint8_t *data = GetData(Data, length);
        switch (Tag) {
            case AOT_CICAM_MULTISTREAM_CAPABILITY: {
                dsyslog("CAM %d: CI+ Multistream: max TS = %u, max descramblers = %u", CamSlot()->SlotNumber(), data[0], UINT32(&data[1], 2));
                dbgprotocol("Slot %d: <== CICAM_MULTISTREAM_CAPABILITY (%d)\n", CamSlot()->SlotNumber(), SessionId());
                break;
            }
            case AOT_PID_SELECT_REQ: {
                dbgprotocol("Slot %d: <== CAM PID_SELECT_REQ (%d)\n", CamSlot()->SlotNumber(), SessionId());
                break;
            }
            default: esyslog("ERROR: CAM %d: CAM Multistream: unknown tag %06X", CamSlot()->SlotNumber(), Tag);
        }
    }
}