#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <vdr/remux.h>
#include <vdr/tools.h>
#include "cCiContentControl.h"
#include "ciplustools.h"
#include <openssl/aes.h>

void cCiContentControl::cc_open_cnf() {
    const uint8_t data = 0x01;
    SendData(AOT_CC_OPEN_CNF, 1, &data);
}

void cCiContentControl::cc_data_cnf(int Length, const uint8_t* Data) {
    uint8_t dest[2048 * 2];
    int dt_nr;
    int id_bitmask;
    int answ_len;
    unsigned int rp = 0;
    memset(dest, 0, sizeof(dest));
    
    if (Length < 2)
        return;
    id_bitmask = Data[rp++];
    dt_nr = Data[rp++];
    rp += credentials.GetDataLoop(&Data[rp], Length - rp, dt_nr);
    
    if ((unsigned int)Length < rp + 1)
	return;
    
    dt_nr = Data[rp++];

    dest[0] = id_bitmask;
    dest[1] = dt_nr;
    
    answ_len = credentials.ReqDataLoop(&dest[2], &Data[rp], Length - rp, dt_nr);
    if (answ_len <= 0) {
        dbgprotocol("cCiContentControl::cc_data_cnf() -> Cannot request data\n");
        return;
    }

    answ_len += 2;
    SendData(AOT_CC_DATA_CNF, answ_len, dest);
}

void cCiContentControl::cc_sync_cnf() {
    const uint8_t status = 0x00;
    SendData(AOT_CC_SYNC_CNF, 1, &status);
}

void cCiContentControl::cc_sac_data_cnf(int Length, const uint8_t* Data) {
    uint8_t dest[2048];
    uint8_t tmp[Length];
    int id_bitmask, dt_nr;
    unsigned int serial;
    int answ_len;
    int pos = 0;
    unsigned int rp = 0;

    if (Length < 10)
        return;
    
    memcpy(tmp, Data, 8);
    credentials.SAC_Crypt(&tmp[8], &Data[8], Length - 8, AES_DECRYPT);
    Data = tmp;
    
    if(!credentials.SAC_Check_Auth(Data, Length)) {
        dbgprotocol("cCiContentControl::cc_sac_data_cnf() -> Check_auth of message failed\n");
        return;
    }
    serial = UINT32(&Data[rp], 4);
    rp += 8;
    id_bitmask = Data[rp++];
    dt_nr = Data[rp++];
    rp += credentials.GetDataLoop(&Data[rp], Length - rp, dt_nr);
    if((unsigned int)Length < rp + 1)
        return;
    dt_nr = Data[rp++];
    
    /* create answer */
    pos += BYTE32(&dest[pos], serial);
    pos += BYTE32(&dest[pos], 0x01000000);

    dest[pos++] = id_bitmask;
    dest[pos++] = dt_nr;
    
    answ_len = credentials.ReqDataLoop(&dest[pos], &Data[rp], Length - rp, dt_nr);
    if (answ_len <= 0) {
        dbgprotocol("cCiContentControl::cc_sac_data_cnf() -> Cannot req data\n");
        return;
    }
    
    pos += answ_len;
    
    cc_sac_send(AOT_CC_SAC_DATA_CNF, dest, pos);
}

void cCiContentControl::cc_sac_sync_cnf(int Length, const uint8_t* Data) {
    uint8_t dest[64];
    unsigned int serial;
    int pos = 0;

    serial = UINT32(Data, 4);

    pos += BYTE32(&dest[pos], serial);
    pos += BYTE32(&dest[pos], 0x01000000);

    /* status OK */
    dest[pos++] = 0;

    cc_sac_send(AOT_CC_SAC_SYNC_CNF, dest, pos);
}

bool cCiContentControl::cc_sac_send(int tag, uint8_t* data, unsigned int pos) {
    if (pos < 8)
        return false;
    pos += add_padding(&data[pos], pos - 8, 16);
    BYTE16(&data[6], pos - 8);      /* len in header */
    pos += credentials.SAC_Gen_Auth(&data[pos], data, pos);
    credentials.SAC_Crypt(&data[8], &data[8], pos - 8, AES_ENCRYPT);
    SendData(tag, pos, data);
    return true;
}


cCiContentControl::cCiContentControl(uint16_t SessionId, cCiTransportConnection* Tc, cCiPlusPrivate *ciplusPrivate)
:cCiSession(SessionId, RI_CONTENT_CONTROL, Tc), credentials(CamSlot()->GetCamName(), CamSlot()->SlotNumber(), ciplusPrivate, key_register)
{
    dbgprotocol("Slot %d: new Content Control (session id %d)\n", CamSlot()->SlotNumber(), SessionId);
    memset(key_register[REG_EVEN].Cak, 0, 16);
    memset(key_register[REG_EVEN].Civ, 0, 16);
    memset(key_register[REG_ODD].Cak, 0, 16);
    memset(key_register[REG_ODD].Civ, 0, 16);
    SetTsPostProcessor();
    state = 0;
}

cCiContentControl::~cCiContentControl() {
    
}

void cCiContentControl::Process(int Length, const uint8_t* Data) {
    if (Data) {
        int Tag = GetTag(Length, &Data);
        int length = 0;
        const uint8_t *data = GetData(Data, length);
        switch (Tag) {
            case AOT_CC_OPEN_REQ: {
                dbgprotocol("Slot %d: <== Content Control Open Request (%d)\n", CamSlot()->SlotNumber(), SessionId());
                cc_open_cnf();
                dbgprotocol("Slot %d: ==> Content Control Open Cnf (%d)\n", CamSlot()->SlotNumber(), SessionId());
                state = 1; 
                break; 
            }
            case AOT_CC_DATA_REQ: {
                dbgprotocol("Slot %d: <== Content Control Data Request (%d)\n", CamSlot()->SlotNumber(), SessionId());
                cc_data_cnf(length, data);
                dbgprotocol("Slot %d: ==> Content Control Data Cnf (%d)\n", CamSlot()->SlotNumber(), SessionId());
                state = 2; 
                break;
            }
            case AOT_CC_SYNC_REQ: {
                dbgprotocol("Slot %d: <== Content Control Sync Request (%d)\n", CamSlot()->SlotNumber(), SessionId());
                cc_sync_cnf();
                dbgprotocol("Slot %d: ==> Content Control Sync Cnf (%d)\n", CamSlot()->SlotNumber(), SessionId());
                break;
            }
            case AOT_CC_SAC_DATA_REQ: {
                dbgprotocol("Slot %d: <== Content Control SAC Data Request (%d)\n", CamSlot()->SlotNumber(), SessionId());
                cc_sac_data_cnf(length, data);
                dbgprotocol("Slot %d: ==> Content Control SAC Data Cnf (%d)\n", CamSlot()->SlotNumber(), SessionId());
                break;
            }
            case AOT_CC_SAC_SYNC_REQ: {
                dbgprotocol("Slot %d: <== Content Control SAC Sync Request (%d)\n", CamSlot()->SlotNumber(), SessionId());
                cc_sac_sync_cnf(length, data);
                dbgprotocol("Slot %d: ==> Content Control SAC Sync Cnf (%d) ==> CI+ Module ready for decrypt!\n", CamSlot()->SlotNumber(), SessionId());
                state = 3; 
                break;
            }
            default: esyslog("ERROR: CAM %d: Content Control: unknown tag %06X", CamSlot()->SlotNumber(), Tag);
        }
    }
}

bool cCiContentControl::TsPostProcess(uint8_t* tsPacket) {
    if((!tsPacket) || (!TsIsScrambled(tsPacket)))
        return false;
    if(!TsHasPayload(tsPacket)) {
        tsPacket[3] &= ~TS_SCRAMBLING_CONTROL;
        return true;
    }
    int payload_offset = TsPayloadOffset(tsPacket);
    int payload_length = TS_SIZE - payload_offset;
    if(payload_length < 16) { // "Short Block" => Nothing to do, because Payload < 16 Bytes is not encrypted
        tsPacket[3] &= ~TS_SCRAMBLING_CONTROL;
        return true;
    }
    int reg = -1;
    if((tsPacket[3] & 0xc0) == TSC_EVEN)
        reg = REG_EVEN;
    else if((tsPacket[3] & 0xc0) == TSC_ODD)
        reg = REG_ODD;
    else {
        dbgprotocol("cCiContentControl::TsPostProcess(): unsupported \"Transport Scrambling Control\" value (TSC = 0x%02X)\n", (tsPacket[3] & 0xc0));
        return false;
    }
    
    int tsb_length = payload_length % 16; // Length "Terminating short block"
    int encryptedPayload_length = payload_length - tsb_length;
    AES_KEY key;
    uint8_t iv[16];
    memcpy(iv, key_register[reg].Civ, 16);
    AES_set_decrypt_key(key_register[reg].Cak, 128, &key);
    AES_cbc_encrypt(&tsPacket[payload_offset], payloadBuf, encryptedPayload_length, &key, iv, AES_DECRYPT);
    memcpy(&tsPacket[payload_offset], payloadBuf, encryptedPayload_length);
    tsPacket[3] &= ~TS_SCRAMBLING_CONTROL;
    return true;
}
