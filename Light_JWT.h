#ifndef __LIGHT_JWT_H__
#define __LIGHT_JWT_H__

#include <stdio.h>
#include <string.h>

#include "Arduino.h"
#include "time.h"
#include <stdint.h>

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#ifdef __cplusplus
extern "C"
{
#endif

    enum JWT_ALG_type
    {
        JWT_ALG_RS256,
        JWT_ALG_ES256
    };

#define BASE64_URL

    class LightJWT
    {
    public:
        String base64UrlEncodeRaw(String textToEncode);

        /* Get Header as stringify JSON by Algorithm */
        static String getHeader(JWT_ALG_type algType);

        /* Get Payload as stringify JSON */
        static String getPayload(
            String issuer,
            String audience,
            String scope,
            unsigned long expirationInSecond);

        /* Generate JWT */
        static String JWT(
            JWT_ALG_type algType,
            String payload,
            const char *privateKey);

        static unsigned long getCurrentEpochTimeInSeconds();

        /* binary_to_base64:
         *   Description:
         *     Converts a single byte from a binary value to the corresponding base64 character
         *   Parameters:
         *     v - Byte to convert
         *   Returns:
         *     ascii code of base64 character. If byte is >= 64, then there is not corresponding base64 character
         *     and 255 is returned
         */
        unsigned char binary_to_base64(unsigned char v);

        /* base64_to_binary:
         *   Description:
         *     Converts a single byte from a base64 character to the corresponding binary value
         *   Parameters:
         *     c - Base64 character (as ascii code)
         *   Returns:
         *     6-bit binary value
         */
        unsigned char base64_to_binary(unsigned char c);

        /* encode_base64_length:
         *   Description:
         *     Calculates length of base64 string needed for a given number of binary bytes
         *   Parameters:
         *     input_length - Amount of binary data in bytes
         *   Returns:
         *     Number of base64 characters needed to encode input_length bytes of binary data
         */
        unsigned int encode_base64_length(unsigned int input_length);

        /* decode_base64_length:
         *   Description:
         *     Calculates number of bytes of binary data in a base64 string
         *     Variant that does not use input_length no longer used within library, retained for API compatibility
         *   Parameters:
         *     input - Base64-encoded null-terminated string
         *     input_length (optional) - Number of bytes to read from input pointer
         *   Returns:
         *     Number of bytes of binary data in input
         */
        unsigned int decode_base64_length(unsigned char input[]);
        unsigned int decode_base64_length(unsigned char input[], unsigned int input_length);

        /* encode_base64:
         *   Description:
         *     Converts an array of bytes to a base64 null-terminated string
         *   Parameters:
         *     input - Pointer to input data
         *     input_length - Number of bytes to read from input pointer
         *     output - Pointer to output string. Null terminator will be added automatically
         *   Returns:
         *     Length of encoded string in bytes (not including null terminator)
         */
        unsigned int encode_base64(unsigned char input[], unsigned int input_length, unsigned char output[]);

        /* decode_base64:
         *   Description:
         *     Converts a base64 null-terminated string to an array of bytes
         *   Parameters:
         *     input - Pointer to input string
         *     input_length (optional) - Number of bytes to read from input pointer
         *     output - Pointer to output array
         *   Returns:
         *     Number of bytes in the decoded binary
         */
        unsigned int decode_base64(unsigned char input[], unsigned char output[]);
        unsigned int decode_base64(unsigned char input[], unsigned int input_length, unsigned char output[]);
    };

#ifdef __cplusplus
}
#endif

#endif /* __LIGHT_JWT_H__ */