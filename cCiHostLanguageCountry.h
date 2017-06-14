#ifndef CCIHOSTLANGUAGECOUNTRY_H
#define CCIHOSTLANGUAGECOUNTRY_H

#include <vdr/ci.h>

// Resource Identifiers:
#define RI_HOST_LANGUAGE_COUNTRY  0x008D1001

// Host Language & Country
#define AOT_HOST_COUNTRY_ENQ        0x9F8100
#define AOT_HOST_COUNTRY            0x9F8101
#define AOT_HOST_LANGUAGE_ENQ       0x9F8110
#define AOT_HOST_LANGUAGE           0x9F8111



#ifndef CIPLUS_LANGUAGE 
#define CIPLUS_LANGUAGE 'd','e','u'
#endif

class cCiHostLanguageCountry : public cCiSession {
private:
    uint8_t lang[4] = { CIPLUS_LANGUAGE, 0x00 };
public:
  cCiHostLanguageCountry(uint16_t SessionId, cCiTransportConnection *Tc);
  virtual ~cCiHostLanguageCountry();
  virtual void Process(int Length = 0, const uint8_t *Data = NULL);
};

#endif /* CCIHOSTLANGUAGECOUNTRY_H */

