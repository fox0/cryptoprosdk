//#[cfg(all(target_family = "unix", target_pointer_width = "64"))]
#define UNIX 1
#define HAVE_LIMITS_H 1
#define HAVE_STDINT_H 1
#define SIZEOF_VOID_P 8

#include <stdarg.h>
#include <string.h>
//#include <stdio.h>
#include <assert.h>
#include <WinCryptEx.h>


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
    if (!store) {
        return NULL;
    }
    if (strlen(thumbprint) != 40) {
        return NULL;
    }

    unsigned int hash_len = 20;
    unsigned char hash[hash_len];
    int r = CryptStringToBinaryA(
            thumbprint,
            strlen(thumbprint),
            CRYPT_STRING_HEX,
            hash,
            &hash_len,
            NULL,
            NULL
    );
    if (r == 0) {
        return NULL;
    }

    DATA_BLOB para = {.cbData = hash_len, .pbData = hash};
    PCCERT_CONTEXT result = CertFindCertificateInStore(
            store,
            PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            &para,
            NULL
    );
    return (void *) result;
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


    r = close_store(store);
    assert(r);
}
