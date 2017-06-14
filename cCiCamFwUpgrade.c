#include "cCiCamFwUpgrade.h"
#include "ciplustools.h"

cCiCamFwUpgrade::cCiCamFwUpgrade(uint16_t SessionId, cCiTransportConnection* Tc)
:cCiSession(SessionId, RI_CAM_UPGRADE, Tc) {
    dbgprotocol("Slot %d: new CAM_UPGRADE (session id %d)\n", CamSlot()->SlotNumber(), SessionId);
}

cCiCamFwUpgrade::~cCiCamFwUpgrade() { }

void cCiCamFwUpgrade::Process(int Length, const uint8_t* Data) {
    if (Data) {
        int Tag = GetTag(Length, &Data);
        switch (Tag) {
            case AOT_CAM_FW_UPGRADE: {
                dsyslog("CAM %d: CI+ Firmware Upgrade Command detected...", CamSlot()->SlotNumber());
                dbgprotocol("Slot %d: <== CAM Firmware Upgrade (%d)\n", CamSlot()->SlotNumber(), SessionId());
                SendData(AOT_CAM_FW_UPGRADE_REPLY);
                dbgprotocol("Slot %d: ==> CAM Firmware Upgrade Reply (%d)\n", CamSlot()->SlotNumber(), SessionId());
                break;
            }
            case AOT_CAM_FW_UPGRADE_PROGRESS: {
                dbgprotocol("Slot %d: <== CAM Firmware Upgrade Progress (%d)\n", CamSlot()->SlotNumber(), SessionId());
                SendData(AOT_CAM_FW_UPGRADE_REPLY);
                dbgprotocol("Slot %d: ==> CAM Firmware Upgrade Reply (%d)\n", CamSlot()->SlotNumber(), SessionId());
                break;
            }
            case AOT_CAM_FW_UPGRADE_COMPLETE: {
                dbgprotocol("Slot %d: <== CAM Firmware Upgrade Complete (%d)\n", CamSlot()->SlotNumber(), SessionId());
                SendData(AOT_CAM_FW_UPGRADE_REPLY);
                dbgprotocol("Slot %d: ==> CAM Firmware Upgrade Reply (%d)\n", CamSlot()->SlotNumber(), SessionId());
                break;
            }
            default: esyslog("ERROR: CAM %d: CAM Firmware Upgrade: unknown tag %06X", CamSlot()->SlotNumber(), Tag);
        }
    }
}

