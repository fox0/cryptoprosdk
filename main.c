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


void get_hash_from_hex(const char *thumbprint) {
    unsigned int thumbprint_len = strlen(thumbprint);
    unsigned int result_len = 20;
    unsigned char result[result_len];

    int r = CryptStringToBinaryA(
            thumbprint,
            thumbprint_len,
            CRYPT_STRING_HEX,
            result,
            &result_len,
            NULL,
            NULL
    );
    printf("r=%d\n", r);
    for (size_t i = 0; i < result_len; i++) {
        printf("%d\n", result[i]);
    }
}

int main() {
    get_hash_from_hex("046255290b0eb1cdd1797d9ab8c81f699e3687f3");
}
