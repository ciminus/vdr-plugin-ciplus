#include "cCiPlusCredentials.h"
#include "ciplus.h"
#include "ciplustools.h"
#include "crypttools.h"
#include <vdr/tools.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>

bool cCiPlusCredentials::get_authdata(uint8_t* host_id, uint8_t* dhsk, uint8_t* akh, unsigned int index) {
    int fd;
    uint8_t chunk[8 + 256 + 32];
    unsigned int i;

    /* 5 pairs of data only */
    if (index > 5)
            return false;


    fd = open(authfile, O_RDONLY);
    if (fd <= 0) {
            dbgprotocol("Cannot open %s\n", authfile);
            return false;
    }

    for (i = 0; i < 5; i++) {
            if (read(fd, chunk, sizeof(chunk)) != sizeof(chunk)) {
                    dbgprotocol("Cannot read auth_data\n");
                    close(fd);
                    return false;
            }

            if (i == index) {
                    memcpy(host_id, chunk, 8);
                    memcpy(dhsk, &chunk[8], 256);
                    memcpy(akh, &chunk[8 + 256], 32);
                    close(fd);
                    return true;
            }
    }

    close(fd);
    return false;
}

bool cCiPlusCredentials::write_authdata(const uint8_t* host_id, const uint8_t* dhsk, const uint8_t* akh) {
    dbgprotocol("cCiPlusCredentials::write_authdata()\n");
    int fd;
    uint8_t buf[(8 + 256 + 32) * 5];
    unsigned int entries;
    unsigned int i;
    bool ret = false;

    for (entries = 0; entries < 5; entries++) {
        int offset = (8 + 256 + 32) * entries;
        if (!get_authdata(&buf[offset], &buf[offset + 8], &buf[offset + 8 + 256], entries))
                break;

        /* check if we got this pair already */
        if (!memcmp(&buf[offset + 8 + 256], akh, 32)) {
                dbgprotocol("cCiPlusCredentials::write_authdata() => Authdata already stored\n");
                return true;
        }
    }


    fd = open(authfile, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd <= 0) {
        dbgprotocol("cCiPlusCredentials::write_authdata() => Cannot open %s for writing - authdata not stored\n", authfile);
        return false;
    }

    /* store new entry first */
    if (write(fd, host_id, 8) != 8) {
        dbgprotocol("cCiPlusCredentials::write_authdata() => Error in write\n");
        close(fd);
        return ret;
    }

    if (write(fd, dhsk, 256) != 256) {
        dbgprotocol("cCiPlusCredentials::write_authdata() => Error in write\n");
        close(fd);
        return ret;
    }

    if (write(fd, akh, 32) != 32) {
        dbgprotocol("cCiPlusCredentials::write_authdata() => Error in write\n");
        close(fd);
        return ret;
    }

    /* skip the last one if exists */
    if (entries > 3)
        entries = 3;

    for (i = 0; i < entries; i++) {
        int offset = (8 + 256 + 32) * i;
        if (write(fd, &buf[offset], (8 + 256 + 32)) != (8 + 256 + 32)) {
            dbgprotocol("cCiPlusCredentials::write_authdata() => Error in write\n");
            close(fd);
            return ret;
        }
    }

    ret = true;
    close(fd);

    return ret;
}

struct credential_element *cCiPlusCredentials::getCredentialElement(unsigned int datatype_id) {
    if((datatype_id < 1) || (datatype_id > MAX_CREDENTIAL_ELEMENTS)) {
        dbgprotocol("cCiPlusCredentials::getCredentialElement() => Invalid datatyp id %u\n", datatype_id);
        return NULL;
    }
    return &credentials[datatype_id-1];
}

unsigned int cCiPlusCredentials::getCredentialElementBuffer(uint8_t* dest, unsigned int datatype_id) {
    struct credential_element *e = getCredentialElement(datatype_id);
    if(e == NULL)
        return 0;
    if(!e->valid) {
        dbgprotocol("cCiPlusCredentials::getCredentialElementBuffer() => Datatype (datatype id = %u) not valid\n", datatype_id);
        return 0;
    }
    if(!e->data) {
        dbgprotocol("cCiPlusCredentials::getCredentialElementBuffer() => Datatype (datatype id = %u) doesn't exist\n", datatype_id);
        return 0;
    }
    if(dest) {
        memcpy(dest, e->data, e->size);
    }
    return e->size;
}

unsigned int cCiPlusCredentials::getCredentialElementReq(uint8_t* dest, unsigned int datatype_id) {
    unsigned int len = getCredentialElementBuffer(&dest[3], datatype_id);
    if(len == 0) {
        dbgprotocol("cCiPlusCredentials::getCredentialElementReq() => Cannot get element (datatype id = %u)\n", datatype_id);
        return 0;
    }
    dest[0] = datatype_id;
    dest[1] = len >> 8;
    dest[2] = len;
    return 3 + len;
}

uint8_t *cCiPlusCredentials::getCredentialElementPtr(unsigned int datatype_id) {
    struct credential_element *e = getCredentialElement(datatype_id);
    if (e == NULL)
            return NULL;

    if (!e->valid) {
            dbgprotocol("cCiPlusCredentials::getCredentialElementPtr() => Datatype (datatype id = %u) not valid\n", datatype_id);
            return NULL;
    }

    if (!e->data) {
            dbgprotocol("cCiPlusCredentials::getCredentialElementPtr() => Datatype (datatype id = %u) doesn't exist\n", datatype_id);
            return NULL;
    }

    return e->data;
}

void cCiPlusCredentials::invalidateCredentialElement(unsigned int datatype_id) {
    struct credential_element *e = getCredentialElement(datatype_id);
    if (e) {
        if(e->data) {
            free(e->data);
            e->data = NULL;
        }
	memset(e, 0, sizeof(struct credential_element));
    }
}

bool cCiPlusCredentials::setCredentialElement(unsigned int datatype_id, const uint8_t* data, uint32_t size) {
    struct credential_element *e = getCredentialElement(datatype_id);
    if (e == NULL)
	return false;
    
    if ((datatype_sizes[datatype_id - 1] != 0) && (datatype_sizes[datatype_id - 1] != size)) {
        dbgprotocol("cCiPlusCredentials::setCredentialElement() => Size %u of datatype (datatype id = %u) doesn't match\n", size, datatype_id);
        return false;
    }
    if(e->data) {
        free(e->data);
    }
    e->data = (uint8_t *)malloc(size);
    memcpy(e->data, data, size);
    e->size = size;
    e->valid = true;
    return true;
}

bool cCiPlusCredentials::setCredentialElement(unsigned int datatype_id, X509* cert) {   
    if((datatype_id == DT_HOST_BRANDCERT) || (datatype_id == DT_HOST_DEVCERT)) {
        unsigned char *cert_der = NULL;
        int cert_len = i2d_X509(cert, &cert_der);
        if(cert_len <= 0) {
            dbgprotocol("cCiPlusCredentials::setCredentialElement() => Cannot get data (datatype id = %u) in DER format\n", datatype_id);
            return false;
        }
        return setCredentialElement(datatype_id, cert_der, (uint32_t)cert_len);
    } else if ((datatype_id == DT_HOST_ID) || (datatype_id == DT_CICAM_ID)) {
        X509_NAME *subject;
        int nid_cn = OBJ_txt2nid("CN");
        char hostid[20];
        uint8_t bin_hostid[8];
        subject = X509_get_subject_name(cert);
        X509_NAME_get_text_by_NID(subject, nid_cn, hostid, sizeof(hostid));
        if (strlen(hostid) != 16) {
		dbgprotocol("cCiPlusCredentials::setCredentialElement() => Malformed hostid\n");
		return false;
	}
        for(size_t i=0; i<16; i+=2) {
            sscanf(hostid + i, "%02x", (uint32_t*) &bin_hostid[i/2]);
        }
        return setCredentialElement(datatype_id, bin_hostid, sizeof(bin_hostid));
    }
    return false;
}

bool cCiPlusCredentials::credentialElementIsValid(unsigned int datatype_id) {
    struct credential_element *e = getCredentialElement(datatype_id);
    return e && e->valid;
}

bool cCiPlusCredentials::validateCertificate(X509* cert) {
    X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(store_ctx, cert_ctx.store, cert, NULL);
    X509_STORE_CTX_set_verify_cb(store_ctx, verify_cb);
    X509_STORE_CTX_set_flags(store_ctx, X509_V_FLAG_IGNORE_CRITICAL);
    int ret = X509_verify_cert(store_ctx);
    if (ret != 1)
        dbgprotocol("cCiPlusCredentials::validateCertificate() => %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx)));
    X509_STORE_CTX_free(store_ctx);
    return ret == 1;
}

bool cCiPlusCredentials::importCiCertificates() {
    X509 *brandCert;
    X509 *devCert;
    uint8_t buf[2048];
    uint8_t buf2[2048];
    const unsigned char *bufptr = buf;
    const unsigned char *buf2ptr = buf2;
    unsigned int len;
    
    len = getCredentialElementBuffer(buf, DT_CICAM_BRANDCERT);
    brandCert = d2i_X509(NULL, &bufptr, len);
    if(!brandCert) {
        dbgprotocol("cCiPlusCredentials::importCiCertificates() => Cannot read BrandCert\n");
        cert_ctx.ci_cust_cert = NULL;
        return false;
    } else {
        if(!validateCertificate(brandCert)) {
            dbgprotocol("cCiPlusCredentials::importCiCertificates() => Cannot vaildate BrandCert\n");
            X509_free(brandCert);
            cert_ctx.ci_cust_cert = NULL;
            return false;
        } else {
            X509_STORE_add_cert(cert_ctx.store, brandCert);
            cert_ctx.ci_cust_cert = brandCert;
        }
    }
    
    len = getCredentialElementBuffer(buf2, DT_CICAM_DEVCERT);
    devCert = d2i_X509(NULL, &buf2ptr, len);
    if(!devCert) {
        dbgprotocol("cCiPlusCredentials::importCiCertificates() => Cannot read DevCert\n");
        cert_ctx.ci_device_cert = NULL;
        return false;
    } else {
        if(!validateCertificate(devCert)) {
            dbgprotocol("cCiPlusCredentials::importCiCertificates() => Cannot vaildate DevCert\n");
            X509_free(devCert);
            cert_ctx.ci_device_cert = NULL;
            return false;
        } else {
            X509_STORE_add_cert(cert_ctx.store, devCert);
            cert_ctx.ci_device_cert = devCert;
        }
    }
    return true;
}

bool cCiPlusCredentials::checkCiCertificates() {
    if(!ciplusPrivateInitialized)
        return false;
    if(!credentialElementIsValid(DT_CICAM_BRANDCERT)) {
        return false;
    }
    if(!credentialElementIsValid(DT_CICAM_DEVCERT)) {
        return false;
    }
    if(!importCiCertificates())
        return false;
    if(!setCredentialElement(DT_CICAM_ID, cert_ctx.ci_device_cert))
        return false;
    return true;
}

bool cCiPlusCredentials::initCertCtx() {
    if(!cert_ctx.store) {
        cert_ctx.store = X509_STORE_new();
        if (cert_ctx.store) {
            X509_STORE_add_cert(cert_ctx.store, ciplusPrivate->GetRootCert());
            X509 *customer = ciplusPrivate->GetCustomerCert();
            X509 *device = ciplusPrivate->GetDeviceCert();
            if(validateCertificate(customer)) {
                X509_STORE_add_cert(cert_ctx.store, customer);
                cert_ctx.cust_cert = customer;
            } else {
                dbgprotocol("cCiPlusCredentials::initCertCtx() => Invalid Customer Certificate!\n");
                return false;
            }
            if(validateCertificate(device)) {
                X509_STORE_add_cert(cert_ctx.store, device);
                cert_ctx.device_cert = device;
            } else {
                dbgprotocol("cCiPlusCredentials::initCertCtx() => Invalid Device Certificate!\n");
                return false;
            }          
        } else {
            dbgprotocol("cCiPlusCredentials::initCertCtx() => Can't create X509 Store!\n");
            return false;
        }
    }
    return true;
}

void cCiPlusCredentials::generate_akh() {
    uint8_t akh[32];
    SHA256_CTX sha;

    SHA256_Init(&sha);
    SHA256_Update(&sha, getCredentialElementPtr(DT_CICAM_ID), getCredentialElementBuffer(NULL, DT_CICAM_ID));
    SHA256_Update(&sha, getCredentialElementPtr(DT_HOST_ID), getCredentialElementBuffer(NULL, DT_HOST_ID));
    SHA256_Update(&sha, dhsk, 256);
    SHA256_Final(akh, &sha);

    setCredentialElement(DT_AKH, akh, sizeof(akh));
}

void cCiPlusCredentials::generate_ns_host() {
    uint8_t buf[8];
    get_random(buf, sizeof(buf));
    setCredentialElement(DT_NS_HOST, buf, sizeof(buf));
}

void cCiPlusCredentials::generate_key_seed() {
    SHA256_CTX sha;

    SHA256_Init(&sha);
    SHA256_Update(&sha, &dhsk[240], 16);
    SHA256_Update(&sha, getCredentialElementPtr(DT_AKH), getCredentialElementBuffer(NULL, DT_AKH));
    SHA256_Update(&sha, getCredentialElementPtr(DT_NS_HOST), getCredentialElementBuffer(NULL, DT_NS_HOST));
    SHA256_Update(&sha, getCredentialElementPtr(DT_NS_MODULE), getCredentialElementBuffer(NULL, DT_NS_MODULE));
    SHA256_Final(ks_host, &sha);
}

void cCiPlusCredentials::generate_SAK_SEK() {
    ciplusPrivate->CalcSacKeys(ks_host, sak, sek);
}

void cCiPlusCredentials::generate_uri_confirm() {
    SHA256_CTX sha;
    uint8_t uck[32];
    uint8_t uri_confirm[32];

    /* calculate UCK (uri confirmation key) */
    SHA256_Init(&sha);
    SHA256_Update(&sha, sak, 16);
    SHA256_Final(uck, &sha);

    /* calculate uri_confirm */
    SHA256_Init(&sha);
    SHA256_Update(&sha, getCredentialElementPtr(DT_URI_MESSAGE), getCredentialElementBuffer(NULL, DT_URI_MESSAGE));
    SHA256_Update(&sha, uck, 32);
    SHA256_Final(uri_confirm, &sha);

    setCredentialElement(DT_URI_CONFIRM, uri_confirm, 32);
}

bool cCiPlusCredentials::checkDHchallenge() {
    if(!ciplusPrivateInitialized)
        return false;
    if(!credentialElementIsValid(DT_AUTH_NONCE)) {
        dbgprotocol("cCiPlusCredentials::checkDHchallenge() => Element AUTH_NONCE invalid\n");
        return false;
    }
    if(!credentialElementIsValid(DT_CICAM_ID)) {
        dbgprotocol("cCiPlusCredentials::checkDHchallenge() => Element CICAM_ID invalid\n");
        return false;
    }
    if(!credentialElementIsValid(DT_DHPM)) {
        dbgprotocol("cCiPlusCredentials::checkDHchallenge() => Element DHPM invalid\n");
        return false;
    }
    if(!credentialElementIsValid(DT_SIGNATURE_B)) {
        dbgprotocol("cCiPlusCredentials::checkDHchallenge() => Element SIGNATURE_B invalid\n");
        return false;
    }
    dh_mod_exp(dhsk, 256, getCredentialElementPtr(DT_DHPM), 256, dhp, dhp_len, dh_exp, 256);
    generate_akh();
    akh_index = 5;
    write_authdata(getCredentialElementPtr(DT_HOST_ID), dhsk, getCredentialElementPtr(DT_AKH));
    return true;
}

bool cCiPlusCredentials::restartDHchallenge() {
    if(!ciplusPrivateInitialized)
        return false;
    uint8_t dhph[256], sign_A[256];
    if(!setCredentialElement(DT_HOST_BRANDCERT, cert_ctx.cust_cert)) {
        esyslog("cCiPlusCredentials::restartDHchallenge() => Cannot store CustomerCert in elements.");
    }
    if(!setCredentialElement(DT_HOST_DEVCERT, cert_ctx.device_cert)) {
        esyslog("cCiPlusCredentials::restartDHchallenge() => Cannot store DeviceCert in elements.");
    }
    if(!setCredentialElement(DT_HOST_ID, cert_ctx.device_cert)) {
        esyslog("cCiPlusCredentials::restartDHchallenge() => Cannot store Host_ID in elements.");
    }
    
    invalidateCredentialElement(DT_CICAM_ID);
    invalidateCredentialElement(DT_DHPM);
    invalidateCredentialElement(DT_SIGNATURE_B);
    invalidateCredentialElement(DT_AKH);
    
    
    dh_gen_exp(dh_exp, 256, dhg, dhg_len, dhp, dhp_len);
    dh_mod_exp(dhph, sizeof(dhph), dhg, dhg_len, dhp, dhp_len, dh_exp, 256);
    setCredentialElement(DT_DHPH, dhph, sizeof(dhph));
    
    dh_dhph_signature(sign_A, getCredentialElementPtr(DT_AUTH_NONCE), dhph, rsa_device_key);
    setCredentialElement(DT_SIGNATURE_A, sign_A, sizeof(sign_A));
    return true;
}

void cCiPlusCredentials::checkNewKey() {
    uint8_t km[32];
    uint8_t *kp;
    uint8_t reg;
    
    if (!credentialElementIsValid(DT_KP)) {
        return;
    }
        
    if (!credentialElementIsValid(DT_KEY_REGISTER)) {
        return;
    }
    
    kp = getCredentialElementPtr(DT_KP);
    getCredentialElementBuffer(&reg, DT_KEY_REGISTER);
    
    ciplusPrivate->CalcKeyMaterial(kp, km);
    memcpy(key_register[reg].Cak, km, 16);
    memcpy(key_register[reg].Civ, &km[16], 16);
    
    invalidateCredentialElement(DT_KP);
    invalidateCredentialElement(DT_KEY_REGISTER); 
}

int cCiPlusCredentials::handleGetData(unsigned int datatype_id) {
    switch (datatype_id) {
	case DT_CICAM_BRANDCERT:
	case DT_DHPM:
	case DT_CICAM_DEVCERT:
	case DT_SIGNATURE_B:
            /* this results in CICAM_ID when cert-chain is verified and ok */
            if(!checkCiCertificates())
                break;
            /* generate DHSK & AKH */
            checkDHchallenge();
            break;
	case DT_AUTH_NONCE:        /* auth_nonce - triggers new dh keychallenge - invalidates DHSK & AKH */
            /* generate DHPH & Signature_A */
            restartDHchallenge();
            break;
	case DT_NS_MODULE:        /* Ns_module - triggers SAC key calculation */
            generate_ns_host();
            generate_key_seed();
            generate_SAK_SEK();
            break;

	/* SAC data messages */
        //case DT_CICAM_ID:
	case DT_KEY_REGISTER:
        case DT_KP:
            checkNewKey();
            break;
        case DT_PROGRAM_NUMBER:
            break;
	case DT_URI_MESSAGE:                //uri_message
            generate_uri_confirm();
            break;
	default:
		break;
    }
    return 0;
}

int cCiPlusCredentials::handleReqData(unsigned int datatype_id) {
    switch (datatype_id) {
	case DT_AKH: {
            uint8_t akh[32], host_id[8];
            memset(akh, 0, sizeof(akh));
            if (akh_index != 5) {
                if (!get_authdata(host_id, dhsk, akh, akh_index++))
                    akh_index = 5;
                if (!setCredentialElement(DT_AKH, akh, 32))
                    dbgprotocol("cCiPlusCredentials::handleReqData() => Cannot set AKH in elements\n");
                if (!!setCredentialElement(DT_HOST_ID, host_id, 8))
                    dbgprotocol("cCiPlusCredentials::handleReqData() => Cannot set host_id in elements\n");
            }
        }
	default:
		break;
    }

    return 0;
}

cCiPlusCredentials::cCiPlusCredentials(uint32_t resourceId, const char *CamName, int CamSlot, cCiPlusPrivate *ciplusPrivate, struct TsDecryptionKeyData * key_register)
: ciplusPrivate(ciplusPrivate), key_register(key_register) {
    uint8_t buf[32], host_id[8];
    for(unsigned int i=0; i<MAX_CREDENTIAL_ELEMENTS; i++) {
        credentials[i].data = NULL;
    }
    
    initAuthFilename(CamName, CamSlot);
    
    memset(dhsk, 0, sizeof(dhsk));
    memset(ks_host, 0, sizeof(ks_host));
    memset(sek, 0, sizeof(sek));
    memset(sak, 0, sizeof(sak));
    
    
    dhp = NULL;
    dhg = NULL;
    dhp_len = dhg_len = 0;
    memset(dh_exp, 0, sizeof(dh_exp));
    
    cert_ctx.ci_cust_cert = NULL;
    cert_ctx.ci_device_cert = NULL;
    cert_ctx.cust_cert = NULL;
    cert_ctx.device_cert = NULL;
    cert_ctx.store = NULL;
    
    rsa_device_key = NULL;
    
    memset(buf, 0, 1);
    setCredentialElement(DT_STATUS_FIELD, buf, 1);
    memset(buf, 0, 32);
    if(resourceId == 0x008C1002)
        buf[31] = 0x3; // use uri mask 0x3 if cc v2 is used
    else
        buf[31] = 0x1;
    
    setCredentialElement(DT_URI_VERSIONS, buf, 32);
    akh_index = 0;
    if (!get_authdata(host_id, dhsk, buf, akh_index)) {
        memset(buf, 0, sizeof(buf));
        akh_index = 5;
    }
    setCredentialElement(DT_AKH, buf, 32);
    setCredentialElement(DT_HOST_ID, host_id, 8);
    
    initPrivateData();
}

cCiPlusCredentials::~cCiPlusCredentials() {
    for(unsigned int i=1; i<=MAX_CREDENTIAL_ELEMENTS; i++) {
        invalidateCredentialElement(i);
    }
}

void cCiPlusCredentials::initPrivateData() {
    bool ictx = initCertCtx();
    rsa_device_key = ciplusPrivate->GetRSAPrivateKey();
    dhp = ciplusPrivate->GetDH_p(&dhp_len);
    dhg = ciplusPrivate->GetDH_g(&dhg_len);
    
    ciplusPrivateInitialized = ictx && rsa_device_key && dhp && dhg;
}

void cCiPlusCredentials::initAuthFilename(const char* CamName, int CamSlot) {
    if(CamName && (strlen(cacheDir)  < (PATH_MAX - 22))) {
        uint32_t crc = crc32(0, (const Bytef *)CamName, strlen(CamName));
        snprintf(authfile, PATH_MAX, "%s/%08X.auth", cacheDir, crc);
        return;
    }
    if(strlen(cacheDir) < PATH_MAX-20) {
        snprintf(authfile, PATH_MAX, "%s/slot%02d.auth", cacheDir, CamSlot);
        return;
    }
    snprintf(authfile, PATH_MAX, "/tmp/slot%02d.auth", CamSlot);
}

int cCiPlusCredentials::GetDataLoop(const uint8_t *data, unsigned int datalen, unsigned int items) {
    unsigned int i;
    int dt_id, dt_len;
    unsigned int pos = 0;
    
    for (i = 0; i < items; i++) {
        if (pos + 3 > datalen)
                return 0;

        dt_id = data[pos++];
        dt_len = data[pos++] << 8;
        dt_len |= data[pos++];

        if (pos + dt_len > datalen)
                return 0;

        setCredentialElement(dt_id, &data[pos], dt_len);

        handleGetData(dt_id);

        pos += dt_len;
    }

    return pos;
}

int cCiPlusCredentials::ReqDataLoop(uint8_t *dest, const unsigned char* data, unsigned int datalen, unsigned int items) {
    int dt_id;
    unsigned int i;
    int pos = 0;
    int len;
    
    if (items > datalen)
        return -1;

    for (i = 0; i < items; i++) {
        dt_id = *data++;
        handleReqData(dt_id);    /* check if there is any action needed before we answer */
        len = getCredentialElementReq(dest, dt_id);
        if (len == 0) {
            dbgprotocol("cCiPlusCredentials::ReqDataLoop() -> Cannot get element %d\n", dt_id);
            return -1;
        }
        pos += len;
        dest += len;
    }

    return pos;
}

void cCiPlusCredentials::SAC_Crypt(uint8_t* dst, const uint8_t* src, unsigned int len, int encrypt) {
    AES_KEY key;
    uint8_t iv[16];
    size_t IV_len = 0;
    const uint8_t *IV = ciplusPrivate->GetSacIV(&IV_len);
    memcpy(iv, IV, IV_len);
    if (encrypt)
        AES_set_encrypt_key(sek, 128, &key);
    else
        AES_set_decrypt_key(sek, 128, &key);
    AES_cbc_encrypt(src, dst, len, &key, iv, encrypt);
}

bool cCiPlusCredentials::SAC_Check_Auth(const uint8_t* data, unsigned int len) {
    struct aes_xcbc_mac_ctx ctx;
    uint8_t calced_signature[16];

    if (len < 16)
        return false;

    aes_xcbc_mac_init(&ctx, sak);
    aes_xcbc_mac_process(&ctx, (uint8_t *)"\x04", 1);        /* header len */
    aes_xcbc_mac_process(&ctx, data, len - 16);
    aes_xcbc_mac_done(&ctx, calced_signature);

    if (memcmp(&data[len - 16], calced_signature, 16)) {
        dbgprotocol("cCiPlusCredentials::SAC_Check_Auth() -> Signature wrong\n");
        return false;
    }
    return true;
}

int cCiPlusCredentials::SAC_Gen_Auth(uint8_t* out, uint8_t* in, unsigned int len) {
    struct aes_xcbc_mac_ctx ctx;

    aes_xcbc_mac_init(&ctx, sak);
    aes_xcbc_mac_process(&ctx, (uint8_t *)"\x04", 1);        /* header len */
    aes_xcbc_mac_process(&ctx, in, len);
    aes_xcbc_mac_done(&ctx, out);

    return 16;
}

