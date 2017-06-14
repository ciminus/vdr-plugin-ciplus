#ifndef CCIPLUSCREDENTIALS_H
#define CCIPLUSCREDENTIALS_H

#include "cCiPlusPrivate.h"
#include <openssl/x509.h>
#include <linux/limits.h>


// Datatype id's (See Table H.1: Input Parameters in Computations, Page 162 of CI Plus Specification V1.2 (2009-04))
#define DT_BRAND_ID                 1
#define DT_HOST_ID                  5
#define DT_CICAM_ID                 6
#define DT_HOST_BRANDCERT           7
#define DT_CICAM_BRANDCERT          8
#define DT_KP                       12
#define DT_DHPH                     13
#define DT_DHPM                     14
#define DT_HOST_DEVCERT             15
#define DT_CICAM_DEVCERT            16
#define DT_SIGNATURE_A              17
#define DT_SIGNATURE_B              18
#define DT_AUTH_NONCE               19
#define DT_NS_HOST                  20
#define DT_NS_MODULE                21
#define DT_AKH                      22
#define DT_AKM                      23
#define DT_URI_MESSAGE              25
#define DT_PROGRAM_NUMBER           26
#define DT_URI_CONFIRM              27
#define DT_KEY_REGISTER             28
#define DT_URI_VERSIONS             29
#define DT_STATUS_FIELD             30
#define DT_SRM_DATA                 31
#define DT_SRM_CONFIRM              32

// Key register
#define REG_EVEN                    0
#define REG_ODD                     1


// Datatypes
struct cert_ctx {
        X509_STORE *store;

        /* Host */
        X509 *cust_cert;
        X509 *device_cert;

        /* Module */
        X509 *ci_cust_cert;
        X509 *ci_device_cert;
};
    
struct credential_element {
    uint8_t *data;
    uint32_t size;
    bool valid;
};

struct TsDecryptionKeyData {
    uint8_t Cak[16];
    uint8_t Civ[16];
};

#define MAX_CREDENTIAL_ELEMENTS 32

class cCiPlusCredentials {
private:
    char authfile[PATH_MAX];
    cCiPlusPrivate *ciplusPrivate;
    bool ciplusPrivateInitialized;
    
    // Datatype sizes (See Table H.1: Input Parameters in Computations, Page 162 of CI Plus Specification V1.2 (2009-04))
    uint32_t datatype_sizes[MAX_CREDENTIAL_ELEMENTS] = {
	50, 0, 0, 0, 8, 8, 0, 0,
        0, 0, 0, 32, 256, 256, 0, 0,
        256, 256, 32, 8, 8, 32, 32, 0,
        8, 2, 32, 1, 32, 1, 0, 32 };
        
    struct credential_element credentials[MAX_CREDENTIAL_ELEMENTS];
    
    // Diffie-Hellman Shared Key (See 5.3.2 Keys on the Authentication Layer, Page 25 of CI Plus Specification V1.2 (2009-04))
    uint8_t dhsk[256];

    // KS_host
    uint8_t ks_host[32];

    // derived keys for Secure Authenticated Channel (See 5.3.3 Keys on the SAC Layer, Page 26 of CI Plus Specification V1.2 (2009-04))
    uint8_t sek[16];
    uint8_t sak[16];

    // AKH checks - module performs 5 tries to get correct AKH
    unsigned int akh_index;

    // authentication data
    uint8_t *dhp, *dhg;
    size_t dhp_len, dhg_len;
    
    uint8_t dh_exp[256];

    // certificates
    struct cert_ctx cert_ctx;

    // private key of device-cert
    RSA *rsa_device_key;
    
    // keys for Content Control Layer (See 5.3.4 Keys on the Content Control Layer, Page 26 of CI Plus Specification V1.2 (2009-04))
    struct TsDecryptionKeyData * key_register;
    
    void initPrivateData();
    void initAuthFilename(const char *CamName, int CamSlot);
    
    bool get_authdata(uint8_t *host_id, uint8_t *dhsk, uint8_t *akh, unsigned int index);
    bool write_authdata(const uint8_t *host_id, const uint8_t *dhsk, const uint8_t *akh);
    
    // CredentialElement functions
    struct credential_element *getCredentialElement(unsigned int datatype_id);
    unsigned int getCredentialElementBuffer(uint8_t *dest, unsigned int datatype_id);
    unsigned int getCredentialElementReq(uint8_t *dest, unsigned int datatype_id);
    uint8_t *getCredentialElementPtr(unsigned int datatype_id); 
    void invalidateCredentialElement(unsigned int datatype_id);    
    bool setCredentialElement(unsigned int datatype_id, const uint8_t *data, uint32_t size);
    bool setCredentialElement(unsigned int datatype_id, X509 *cert);
    bool credentialElementIsValid(unsigned int datatype_id);
    
    // Certificate functions
    bool validateCertificate(X509 *cert);
    bool importCiCertificates(); 
    bool checkCiCertificates();
    bool initCertCtx();
    
    // Generators (See Figure 5.3: Key Hierarchy, Page 24 of CI Plus Specification V1.2 (2009-04))
    void generate_akh();
    void generate_ns_host();
    void generate_key_seed();
    void generate_SAK_SEK();
    void generate_uri_confirm();
    
    // DH functions
    bool checkDHchallenge();
    bool restartDHchallenge();
    
    // Check if new keys 
    void checkNewKey();
    
    int handleGetData(unsigned int datatype_id);
    int handleReqData(unsigned int datatype_id);
    
public:
    cCiPlusCredentials(const char *CamName, int CamSlot, cCiPlusPrivate *ciplusPrivate, struct TsDecryptionKeyData * key_register);
    virtual ~cCiPlusCredentials();
    
    int GetDataLoop(const uint8_t *data, unsigned int datalen, unsigned int items);
    int ReqDataLoop(uint8_t *dest, const unsigned char *data, unsigned int datalen, unsigned int items);
    
    void SAC_Crypt(uint8_t *dst, const uint8_t *src, unsigned int len, int encrypt);
    bool SAC_Check_Auth(const uint8_t *data, unsigned int len);
    int SAC_Gen_Auth(uint8_t *out, uint8_t *in, unsigned int len);
};

#endif /* CCIPLUSCREDENTIALS_H */

