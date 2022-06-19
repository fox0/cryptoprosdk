//#[cfg(all(target_family = "unix", target_pointer_width = "64"))]
#define UNIX 1
#define HAVE_LIMITS_H 1
#define HAVE_STDINT_H 1
#define SIZEOF_VOID_P 8

#include <assert.h>

////////////////

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <WinCryptEx.h>
#include <cades.h>

#define CERT_ENCODING_TYPE PKCS_7_ASN_ENCODING | X509_ASN_ENCODING
#define CERT_HASH_ALGORITHM szOID_CP_GOST_R3411

#define PRINT_LAST_ERROR printf("[src/wrap.c:%d] error 0x%x\n", __LINE__, GetLastError())


void *wrapFindCertificateByThumbprint(void *hCertStore, const char *pszString) {
    const DWORD cchString = strlen(pszString);
    if (!hCertStore || cchString != 40) {
        return NULL;
    }
    const DWORD dwFlags = CRYPT_STRING_HEX;
    DWORD hashLen = 20;
    BYTE pbBinary[hashLen];
    if (!CryptStringToBinaryA(pszString, cchString, dwFlags, pbBinary/*out*/, &hashLen/*out*/, NULL, NULL)) {
        PRINT_LAST_ERROR;
        return NULL;
    }
    const DWORD dwCertEncodingType = CERT_ENCODING_TYPE;
    const DWORD dwFindFlags = 0;
    const DWORD dwFindType = CERT_FIND_HASH;
    DATA_BLOB p = {
            .cbData = hashLen,
            .pbData = pbBinary
    };
    CERT_CONTEXT *r = CertFindCertificateInStore(hCertStore, dwCertEncodingType, dwFindFlags, dwFindType, &p, NULL);
    if (!r) {
        PRINT_LAST_ERROR;
    }
    return (void *) r;
}

DATA_BLOB *wrapSign(void *pSigningCert, const unsigned char *data, const unsigned int dataLen) {
    if (!pSigningCert || !data || dataLen == 0) {
        return NULL;
    }
    CRYPT_SIGN_MESSAGE_PARA p2 = {
            .cbSize = sizeof(p2),
            .dwMsgEncodingType = CERT_ENCODING_TYPE,
            .pSigningCert = (PCCERT_CONTEXT) pSigningCert,
            .HashAlgorithm.pszObjId = CERT_HASH_ALGORITHM
    };
    CADES_SIGN_MESSAGE_PARA p = {
            .dwSize = sizeof(p),
            .pSignMessagePara = &p2
    };
    const BOOL fDetachedSignature = TRUE;
    const DWORD cToBeSigned = 1;
    const BYTE *rgpbToBeSigned[] = {&data[0]};
    DWORD rgcbToBeSigned[] = {dataLen};
    DATA_BLOB *r = 0;
    if (!CadesSignMessage(&p, fDetachedSignature, cToBeSigned, rgpbToBeSigned, rgcbToBeSigned, &r/*out*/)) {
        PRINT_LAST_ERROR;
        return NULL;
    }
    return r;
}


// /opt/cprocsp/bin/amd64/certmgr certmgr --list --thumbprint 046255290b0eb1cdd1797d9ab8c81f699e3687f3
int main() {
    const char *pszSubsystemProtocol = "MY";
    const char *pszString = "046255290b0eb1cdd1797d9ab8c81f699e3687f3";

    int r;
    void *hCertStore = CertOpenSystemStoreA(0, pszSubsystemProtocol);
    assert(hCertStore);
    void *pCertContext = wrapFindCertificateByThumbprint(hCertStore, pszString);
    assert(pCertContext);

    DATA_BLOB *pBlob = wrapSign(
            pCertContext,
            (const unsigned char *) "Trixie is Best Pony!",
            strlen("Trixie is Best Pony!")
    );
    assert(pBlob);

// for (size_t i = 0; i < r->cbData; i++) {
//     printf("%d ", r->pbData[i]);
// }
//    std::vector < BYTE > message(r->cbData);
//    std::copy(r->pbData,
//              r->pbData + r->cbData, message.begin());
//
//    if (!CadesFreeBlob(r)) {
//        std::cout << "CadesFreeBlob() failed" << std::endl;
//        return empty;
//    }

    r = CadesFreeBlob(pBlob);
    assert(r);
    r = CertFreeCertificateContext(pCertContext);
    assert(r);
    r = CertCloseStore(hCertStore, 0);
    assert(r);
}
