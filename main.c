//#[cfg(all(target_family = "unix", target_pointer_width = "64"))]
#define UNIX 1
#define HAVE_LIMITS_H 1
#define HAVE_STDINT_H 1
#define SIZEOF_VOID_P 8

#include <stdarg.h>
#include <WinCryptEx.h>
#include <cades.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>


// /opt/cprocsp/bin/amd64/certmgr certmgr --list --thumbprint 046255290b0eb1cdd1797d9ab8c81f699e3687f3
int main() {
    const char *store = "MY";
    const char *thumbprint = "046255290b0eb1cdd1797d9ab8c81f699e3687f3";

    int r;

    void *cert_store = CertOpenSystemStoreA(0, store);
    assert(cert_store);

    unsigned int hash_len = 20;
    unsigned char hash[hash_len];
    r = CryptStringToBinaryA(
            thumbprint,
            strlen(thumbprint),
            CRYPT_STRING_HEX,
            hash,
            &hash_len,
            NULL,
            NULL
    );
    assert(r);

    CRYPT_INTEGER_BLOB para = {
            .cbData = hash_len,
            .pbData = hash
    };

    PCCERT_CONTEXT cert_context = CertFindCertificateInStore(
            cert_store,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            &para,
            NULL
    );
    assert(cert_context);

    r = CertCloseStore(cert_store, 0);
    assert(r);
}
