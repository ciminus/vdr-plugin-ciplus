#ifndef CCIPLUSPRIVATE_H
#define CCIPLUSPRIVATE_H

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <stdint.h>

class cCiPlusPrivate {
public:
    cCiPlusPrivate();
    virtual ~cCiPlusPrivate();
    
    bool LoadPrivateData(const char *privateLib);
    
    X509 *GetRootCert(void) { return (*getRootCert)(); }
    X509 *GetCustomerCert(void) { return (*getCustomerCert)(); }
    X509 *GetDeviceCert(void) { return (*getDeviceCert)(); }
    
    RSA *GetRSAPrivateKey(void) { return (*getRsaPrivateKey)(); }
    
    uint8_t *GetDH_p(size_t *length) { return (*getDHp)(length); }
    uint8_t *GetDH_g(size_t *length) { return (*getDHg)(length); }
    
    const uint8_t *GetSacIV(size_t *length) { return (*getSacIV)(length); }
    
    void CalcSacKeys(uint8_t *ks_host, uint8_t *sak, uint8_t *sek) { (*calcSacKeys)(ks_host, sak, sek); }
    void CalcKeyMaterial(uint8_t *kp, uint8_t *km) { (*calcKeyMaterial)(kp, km); }
    
private:
    void *handle = NULL;
    X509 *(*getRootCert)(void) = NULL;
    X509 *(*getCustomerCert)(void) = NULL;
    X509 *(*getDeviceCert)(void) = NULL;
    
    RSA *(*getRsaPrivateKey)(void) = NULL;
    
    uint8_t *(*getDHp)(size_t *) = NULL;
    uint8_t *(*getDHg)(size_t *) = NULL;
    
    const uint8_t *(*getSacIV)(size_t *) = NULL;
    
    void (*calcSacKeys)(uint8_t *, uint8_t *, uint8_t *) = NULL;
    void (*calcKeyMaterial)(uint8_t *, uint8_t *) = NULL;

};

#endif /* CCIPLUSPRIVATE_H */

