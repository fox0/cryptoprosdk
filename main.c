//#[cfg(all(target_family = "unix", target_pointer_width = "64"))]
#define UNIX 1
#define HAVE_LIMITS_H 1
#define HAVE_STDINT_H 1
#define SIZEOF_VOID_P 8

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <WinCryptEx.h>
#include <cades.h>

#define CERT_ENCODING_TYPE PKCS_7_ASN_ENCODING | X509_ASN_ENCODING
#define CERT_HASH_ALGORITHM szOID_CP_GOST_R3411


void *open_store(const char *store_name) {
    if (strlen(store_name) == 0) {
        return NULL;
    }
    return CertOpenSystemStoreA(0, store_name);
}

int close_store(void *store) {
    if (!store) {
        return 0;
    }
    return CertCloseStore(store, 0);
}

void *find_certificate_by_thumbprint(void *store, const char *thumbprint) {
    if (!store || strlen(thumbprint) != 40) {
        return NULL;
    }

    unsigned int hash_len = 20;
    unsigned char hash[hash_len];
    if (!CryptStringToBinaryA(
            thumbprint,
            strlen(thumbprint),
            CRYPT_STRING_HEX,
            hash,
            &hash_len,
            NULL,
            NULL
    )) {
        return NULL;
    }

    DATA_BLOB para = {.cbData = hash_len, .pbData = hash};
    PCCERT_CONTEXT result = CertFindCertificateInStore(
            store,
            CERT_ENCODING_TYPE,
            0,
            CERT_FIND_HASH,
            &para,
            NULL
    );
    return (void *) result;
}


void sign(void *cert_context, const unsigned char *data) {
    CRYPT_SIGN_MESSAGE_PARA signPara = {sizeof(signPara)};
    signPara.dwMsgEncodingType = CERT_ENCODING_TYPE;
    signPara.pSigningCert = (PCCERT_CONTEXT) cert_context;
    signPara.HashAlgorithm.pszObjId = CERT_HASH_ALGORITHM;

    CADES_SIGN_MESSAGE_PARA para = {sizeof(para)};
    para.pSignMessagePara = &signPara;

    const BYTE *pbToBeSigned[] = {&data[0]};
    DWORD cbToBeSigned[] = {strlen((const char *) data)};

    PCRYPT_DATA_BLOB pSignedMessage = 0;
    if (!CadesSignMessage(
            &para,
            TRUE, // detached
            1,
            pbToBeSigned,
            cbToBeSigned,
            &pSignedMessage
    )) {
        printf("error 0x%x\n", GetLastError());
        return;
    }

    for (size_t i = 0; i < pSignedMessage->cbData; i++) {
        printf("%d ", pSignedMessage->pbData[i]);
    }

//    std::vector < BYTE > message(pSignedMessage->cbData);
//    std::copy(pSignedMessage->pbData,
//              pSignedMessage->pbData + pSignedMessage->cbData, message.begin());
//
//    if (!CadesFreeBlob(pSignedMessage)) {
//        std::cout << "CadesFreeBlob() failed" << std::endl;
//        return empty;
//    }
}


// /opt/cprocsp/bin/amd64/certmgr certmgr --list --thumbprint 046255290b0eb1cdd1797d9ab8c81f699e3687f3
int main() {
    const char *store_name = "MY";
    const char *thumbprint = "046255290b0eb1cdd1797d9ab8c81f699e3687f3";

    int r;

    void *store = open_store(store_name);
    assert(store);

    void *cert_context = find_certificate_by_thumbprint(store, thumbprint);
    assert(cert_context);

    sign(cert_context, (const unsigned char *) "Trixie is Best Pony!");

    r = close_store(store);
    assert(r);
}
