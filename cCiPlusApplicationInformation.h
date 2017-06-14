#ifndef CCIPLUSAPPLICATIONINFORMATION_H
#define CCIPLUSAPPLICATIONINFORMATION_H

#include <vdr/ci.h>

#define RI_APPLICATION_INFORMATION_CIPLUS     0x00020043

#define AOT_REQUEST_CICAM_RESET     0x9F8023
#define AOT_DATA_RATE_INFO          0x9F8024
#define DATA_RATE_72MBITS           0x00
#define DATA_RATE_96MBITS           0x01

class cCiPlusApplicationInformation : public cCiApplicationInformation {
public:
    cCiPlusApplicationInformation(uint16_t SessionId, cCiTransportConnection *Tc);
    virtual ~cCiPlusApplicationInformation();
    
    void Process(int Length, const uint8_t *Data);
private:
    bool datarate_send = false;

};

#endif /* CCIPLUSAPPLICATIONINFORMATION_H */

