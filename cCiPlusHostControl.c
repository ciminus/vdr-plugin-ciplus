#include "cCiPlusHostControl.h"
#include "ciplustools.h"

cCiPlusHostControl::cCiPlusHostControl(uint16_t SessionId, cCiTransportConnection* Tc)
:cCiSession(SessionId, RI_HOST_CONTROL_V2, Tc)
{
  dbgprotocol("Slot %d: new Host Control (session id %d)\n", CamSlot()->SlotNumber(), SessionId);
}

void cCiPlusHostControl::Process(int Length, const uint8_t* Data)
{
  if (Data) {
     int Tag = GetTag(Length, &Data);
     switch (Tag) {
       case AOT_TUNE:
            dbgprotocol("Slot %d: <== Host Control Tune (%d)\n", CamSlot()->SlotNumber(), SessionId());
            break;
       case AOT_REPLACE:
            dbgprotocol("Slot %d: <== Host Control Replace (%d)\n", CamSlot()->SlotNumber(), SessionId());
            break;
       case AOT_CLEAR_REPLACE:
            dbgprotocol("Slot %d: <== Host Control Clear Replace (%d)\n", CamSlot()->SlotNumber(), SessionId());
            break;
       case AOT_TUNE_BROADCAST_REQ:
            dbgprotocol("Slot %d: <== Host Control Tune Broadcast Req (%d)\n", CamSlot()->SlotNumber(), SessionId());
            break;
       case AOT_ASK_RELEASE_REPLY:
            dbgprotocol("Slot %d: <== Host Control Tune Broadcast Req (%d)\n", CamSlot()->SlotNumber(), SessionId());
            break;
       default: esyslog("ERROR: CAM %d: Host Control: unknown tag %06X", CamSlot()->SlotNumber(), Tag);
       }
     }
}

