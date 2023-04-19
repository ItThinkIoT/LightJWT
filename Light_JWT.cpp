#include "Light_JWT.h"

// base64_encode copied from https://github.com/ReneNyffenegger/cpp-base64
static const char base64url_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

String LightJWT::base64UrlEncodeRaw(String textToEncode)
{
    String base64url_encoded;

    const unsigned char *bytes_to_encode = (const unsigned char *)textToEncode.c_str();
    unsigned int in_len = textToEncode.length();

    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] =
                ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] =
                ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
            {
                base64url_encoded += base64url_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
        {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] =
            ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] =
            ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
        {
            base64url_encoded += base64url_chars[char_array_4[j]];
        }
    }

    return base64url_encoded;
}

unsigned long LightJWT::getCurrentEpochTimeInSeconds()
{
    time_t now;
    struct tm timeinfo;
    if (!getLocalTime(&timeinfo))
    {
        // Serial.println("Failed to obtain time");
        return (0);
    }
    time(&now);
    return now;
}

String LightJWT::getHeader(JWT_ALG_type algType)
{
    String header = "{\"alg\":\"{{ALG}}\",\"typ\":\"JWT\"}";
    switch (algType)
    {
    case JWT_ALG_RS256:
        header.replace("{{ALG}}", "RS256");
        break;
    case JWT_ALG_ES256:
        header.replace("{{ALG}}", "ES256");
        break;
    default:
        header.replace("{{ALG}}", "RS256");
        break;
    }

    return header;
}

String LightJWT::getPayload(String issuer,
                            String audience,
                            String scope,
                            unsigned long expirationInSecond)
{
    String payload = "{\"iss\":\"{{ISS}}\",\"aud\":\"{{AUD}}\",\"scope\":\"{{SCOPE}}\",\"iat\":{{IAT}},\"exp\":{{EXP}}}";

    unsigned long iat = LightJWT().getCurrentEpochTimeInSeconds(); /* 1657550511 */

    payload.replace("{{ISS}}", issuer);
    payload.replace("{{AUD}}", audience);
    payload.replace("{{SCOPE}}", scope);
    payload.replace("{{IAT}}", String(iat));
    payload.replace("{{EXP}}", String((iat + expirationInSecond)));

    return payload;
}

String LightJWT::JWT(
    JWT_ALG_type algType,
    String payload,
    const char *privateKey)
{
    /* Header */
    String header = LightJWT().base64UrlEncodeRaw(LightJWT()
                                                      .getHeader(algType));

    /* Payload */
    payload = LightJWT().base64UrlEncodeRaw(payload);

    // Serial.print("--------- Payload: ");
    // Serial.println(payload);

    String headerPayload = String(header + "." + payload);

    /* Sign */

    /* Get SHA256 of header+payload: sha256_b64h_b64p = SHA256(header_base64url . payload_base64url) */
    unsigned char sha256_b64h_b64p[32] = {0};
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts_ret(&sha_ctx, 0);

    // Serial.print("headerPayload: ");
    // Serial.println(headerPayload);
    // Serial.println("-----------");

    size_t headerPayloadSize = headerPayload.length();
    unsigned char uHeaderPayload[headerPayloadSize];
    strcpy((char *)uHeaderPayload, headerPayload.c_str());

    // unsigned char uHeaderPayload[headerPayloadSize] = {0};
    // std::copy(headerPayload.c_str(), headerPayload.c_str() + headerPayload.length(), uHeaderPayload);
    // Serial.print("uHeaderPayload: ");
    // Serial.println((char*)uHeaderPayload);

    mbedtls_sha256_update_ret(&sha_ctx, uHeaderPayload, headerPayloadSize);
    mbedtls_sha256_finish_ret(&sha_ctx, sha256_b64h_b64p);

    mbedtls_sha256_free(&sha_ctx);

    // Serial.print("sha256_b64h_b64p: ");
    // Serial.println((char *)(sha256_b64h_b64p));
    // Serial.println(LightJWT().base64UrlEncodeRaw((char *)(sha256_b64h_b64p)));

    /* Load Private Key */
    // Serial.print("privateKey: ");
    // Serial.println(privateKey);

    size_t privateKeySize = strlen(privateKey);
    unsigned char uPrivateKey[privateKeySize];
    strcpy((char *)uPrivateKey, privateKey);

    // Serial.print("uPrivateKey: ");
    // Serial.println((char*)uPrivateKey);

    mbedtls_pk_context pkContext;
    mbedtls_pk_init(&pkContext);

    mbedtls_pk_parse_key(
        &pkContext,
        uPrivateKey,
        privateKeySize + 1,
        NULL, 0);

    // auto ecContext = mbedtls_pk_ec(pkContext);

    String sign;

    switch (algType)
    {
    case JWT_ALG_RS256:
    {
        auto rsa = mbedtls_pk_rsa(pkContext);

        if (rsa == NULL)
        {
            // Serial.println("RSA Context is invalid");
            return String("INVALID-RSA-CONTEXT");
        }

        int keyValid = mbedtls_rsa_check_privkey(rsa);
        // Serial.print("keyValid: ");
        // Serial.println(keyValid);
        if (keyValid != 0)
            return String("INVALID-PRIVATE-KEY");

        // Serial.println("Encrypting sha256_b64h_b64p...");
        unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
        int success = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 32, sha256_b64h_b64p, buf);
        // Serial.print("Encrypted? ");
        // Serial.println(success);
        if (success != 0)
            return String("CAN-NOT-SIGN");

        unsigned char signature[LightJWT().encode_base64_length(rsa->len)];

        LightJWT().encode_base64(buf, rsa->len, signature);

        // Serial.print("signature(b64): ");
        // Serial.println((char *)signature);

        sign = String((char *)signature);

        mbedtls_rsa_free(rsa);
        mbedtls_pk_free(&pkContext);

        break;
    }
    case JWT_ALG_ES256:
    {
        auto ecdsa = mbedtls_pk_ec(pkContext);

        if (ecdsa == NULL)
        {
            // Serial.println("ECDSA Context is invalid");
            return String("INVALID-ECDSA-CONTEXT");
        }

        // Serial.println("Encrypting sha256_b64h_b64p...");
        unsigned char signature[64];
        size_t signatureLength;
        mbedtls_mpi r, s;

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        
        int ret = mbedtls_ecdsa_sign_det(&ecdsa->grp, &r, &s, &ecdsa->d, sha256_b64h_b64p, 32, MBEDTLS_MD_SHA256);
        if (ret != 0)
        {
            return String("CAN-NOT-SIGN");
        }

        // Write the signature in P1363 format
        mbedtls_mpi_write_binary(&r, signature, mbedtls_mpi_size(&r));
        mbedtls_mpi_write_binary(&s, signature + mbedtls_mpi_size(&r), mbedtls_mpi_size(&s));
        signatureLength = mbedtls_mpi_size(&r) + mbedtls_mpi_size(&s);

        /* mbedtls_ecdsa_write_signature writes signature out as DER format */
        // int success = mbedtls_ecdsa_write_signature(ecdsa, MBEDTLS_MD_SHA256, sha256_b64h_b64p, 32, buf, &signatureLength, NULL, NULL);

        /* Print signature as hex */
        // Serial.print("signature (hex) (" + String(signatureLength) + ") : [");
        // for (size_t i = 0; i < signatureLength; i++)
        // {
        //     Serial.printf("%02x", signature[i]);
        // }
        // Serial.println("]");

        unsigned char _signature[LightJWT().encode_base64_length(signatureLength)];

        LightJWT().encode_base64(signature, signatureLength, _signature);

        // Serial.print("signature(b64): ");
        // Serial.println((char *)_signature);

        sign = String((char *)_signature);

        mbedtls_ecdsa_free(ecdsa);
        mbedtls_pk_free(&pkContext);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);

        break;
    }

    default:
        return String("INVALID-ALG-TYPE");
    }

    return String(headerPayload + "." + sign);
}

unsigned char LightJWT::binary_to_base64(unsigned char v)
{
    // Capital letters - 'A' is ascii 65 and base64 0
    if (v < 26)
        return v + 'A';

    // Lowercase letters - 'a' is ascii 97 and base64 26
    if (v < 52)
        return v + 71;

    // Digits - '0' is ascii 48 and base64 52
    if (v < 62)
        return v - 4;

#ifdef BASE64_URL
    // '-' is ascii 45 and base64 62
    if (v == 62)
        return '-';
#else
    // '+' is ascii 43 and base64 62
    if (v == 62)
        return '+';
#endif

#ifdef BASE64_URL
    // '_' is ascii 95 and base64 62
    if (v == 63)
        return '_';
#else
    // '/' is ascii 47 and base64 63
    if (v == 63)
        return '/';
#endif

    return 64;
}

unsigned char LightJWT::base64_to_binary(unsigned char c)
{
    // Capital letters - 'A' is ascii 65 and base64 0
    if ('A' <= c && c <= 'Z')
        return c - 'A';

    // Lowercase letters - 'a' is ascii 97 and base64 26
    if ('a' <= c && c <= 'z')
        return c - 71;

    // Digits - '0' is ascii 48 and base64 52
    if ('0' <= c && c <= '9')
        return c + 4;

#ifdef BASE64_URL
    // '-' is ascii 45 and base64 62
    if (c == '-')
        return 62;
#else
    // '+' is ascii 43 and base64 62
    if (c == '+')
        return 62;
#endif

#ifdef BASE64_URL
    // '_' is ascii 95 and base64 62
    if (c == '_')
        return 63;
#else
    // '/' is ascii 47 and base64 63
    if (c == '/')
        return 63;
#endif

    return 255;
}

unsigned int LightJWT::encode_base64_length(unsigned int input_length)
{
    return (input_length + 2) / 3 * 4;
}

unsigned int LightJWT::decode_base64_length(unsigned char input[])
{
    return decode_base64_length(input, -1);
}

unsigned int LightJWT::decode_base64_length(unsigned char input[], unsigned int input_length)
{
    unsigned char *start = input;

    while (base64_to_binary(input[0]) < 64 && (unsigned int)(input - start) < input_length)
    {
        ++input;
    }

    input_length = (unsigned int)(input - start);
    return input_length / 4 * 3 + (input_length % 4 ? input_length % 4 - 1 : 0);
}

unsigned int LightJWT::encode_base64(unsigned char input[], unsigned int input_length, unsigned char output[])
{
    unsigned int full_sets = input_length / 3;

    // While there are still full sets of 24 bits...
    for (unsigned int i = 0; i < full_sets; ++i)
    {
        output[0] = binary_to_base64(input[0] >> 2);
        output[1] = binary_to_base64((input[0] & 0x03) << 4 | input[1] >> 4);
        output[2] = binary_to_base64((input[1] & 0x0F) << 2 | input[2] >> 6);
        output[3] = binary_to_base64(input[2] & 0x3F);

        input += 3;
        output += 4;
    }

    switch (input_length % 3)
    {
    case 0:
        output[0] = '\0';
        break;
    case 1:
        output[0] = binary_to_base64(input[0] >> 2);
        output[1] = binary_to_base64((input[0] & 0x03) << 4);
        output[2] = '=';
        output[3] = '=';
        output[4] = '\0';
        break;
    case 2:
        output[0] = binary_to_base64(input[0] >> 2);
        output[1] = binary_to_base64((input[0] & 0x03) << 4 | input[1] >> 4);
        output[2] = binary_to_base64((input[1] & 0x0F) << 2);
        output[3] = '=';
        output[4] = '\0';
        break;
    }

    return encode_base64_length(input_length);
}

unsigned int LightJWT::decode_base64(unsigned char input[], unsigned char output[])
{
    return decode_base64(input, -1, output);
}

unsigned int LightJWT::decode_base64(unsigned char input[], unsigned int input_length, unsigned char output[])
{
    unsigned int output_length = decode_base64_length(input, input_length);

    // While there are still full sets of 24 bits...
    for (unsigned int i = 2; i < output_length; i += 3)
    {
        output[0] = base64_to_binary(input[0]) << 2 | base64_to_binary(input[1]) >> 4;
        output[1] = base64_to_binary(input[1]) << 4 | base64_to_binary(input[2]) >> 2;
        output[2] = base64_to_binary(input[2]) << 6 | base64_to_binary(input[3]);

        input += 4;
        output += 3;
    }

    switch (output_length % 3)
    {
    case 1:
        output[0] = base64_to_binary(input[0]) << 2 | base64_to_binary(input[1]) >> 4;
        break;
    case 2:
        output[0] = base64_to_binary(input[0]) << 2 | base64_to_binary(input[1]) >> 4;
        output[1] = base64_to_binary(input[1]) << 4 | base64_to_binary(input[2]) >> 2;
        break;
    }

    return output_length;
}
