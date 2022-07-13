# LightJWT

This is a helper library to create Json Web Token [JWT](https://jwt.io/) 

### Suported Algorithms
  
- RS256

### Features

- Create JWT
- Base64(UrlSafe) Encode&Decode

### Dependencies

- Arduino
- mbedtls

### References

- [RFC 7516 - JSON Web Encryption (JWE)](https://www.rfc-editor.org/info/rfc7516)
- [Google oAuth2 Token JWT](https://developers.google.com/identity/protocols/oauth2/service-account#httprest)
- [Crypto - Base64 arduino](https://github.com/Densaugeo/base64_arduino)
- [Crypto - mbedtls github](https://github.com/Mbed-TLS/mbedtls)
- [Crypto - RSA PKCS1v15](https://armmbed.github.io/mbed-crypto/html/api/ops/sign.html#c.PSA_ALG_RSA_PKCS1V15_SIGN_RAW)
- [Crypto - SHA256 on esp32](https://techtutorialsx.com/2018/05/10/esp32-arduino-mbed-tls-using-the-sha-256-algorithm/)
- [Crypto - RS256 on esp32](https://forums.mbed.com/t/rsa-sha-256-encrypt-string-on-esp32/12483)

### TODOs

- [ ] Add examples in **./examples**
  - [ ] create JWT
  - [ ] base64 encode
  - [ ] base64 decode
- [ ] Verify JWT
  - [ ] Sign
  - [ ] Expiration
- [ ] Create JWT with custom fields

MIT license, all text above must be included in any redistribution
