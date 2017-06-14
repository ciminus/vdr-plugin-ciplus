#include "cCiPlusPrivate.h"
#include <vdr/tools.h>
#include <dlfcn.h>

cCiPlusPrivate::cCiPlusPrivate() {
}

cCiPlusPrivate::~cCiPlusPrivate() {
    if(handle)
        dlclose(handle);
}

bool cCiPlusPrivate::LoadPrivateData(const char* privateLib) {
    handle = dlopen(privateLib, RTLD_LAZY);
    if(!handle)
        return false;
    
    getRootCert = (X509 *(*)(void))dlsym(handle, "getRootCert");
    getCustomerCert = (X509 *(*)(void))dlsym(handle, "getCustomerCert");
    getDeviceCert = (X509 *(*)(void))dlsym(handle, "getDeviceCert");
    getRsaPrivateKey = (RSA *(*)(void))dlsym(handle, "getRsaPrivateKey");
    getDHp = (uint8_t *(*)(size_t *))dlsym(handle, "getDH_p");
    getDHg = (uint8_t *(*)(size_t *))dlsym(handle, "getDH_g");
    getSacIV = (const uint8_t *(*)(size_t *))dlsym(handle, "getSAC_IV");
    calcSacKeys = (void (*)(uint8_t *, uint8_t *, uint8_t *))dlsym(handle, "calcSacKeys");
    calcKeyMaterial = (void (*)(uint8_t *, uint8_t *))dlsym(handle, "calcKeyMaterial");
    
    return getRootCert && getCustomerCert && getDeviceCert && getRsaPrivateKey &&
            getDHp && getDHg && getSacIV &&
            calcSacKeys && calcKeyMaterial;
}