# Change log for [raaz].

## [0.1.0] - Pending

- Alignment optimisation for hashing bytestrings (TODO)
- Num instance from LengthUnit removed Monoid instance added
  (Commit: 65264e5a89874bab70d0aded3777829209ac5ce2)

## [0.0.2] - July 25, 2016.

This release comes with very little changes.

* Encoding: translation between formats using the `translate`
  combinator
* Encoding formats: base64
* Bug fix in base16 character verification (Commit: d6eca4c37b0b)
* Dropped `isSuccessful` from export list of Equality.

## [0.0.1] - June 21, 2016.

* Basic cryptographic types.
* Hashes: sha1, sha256, sha512, sha224, sha384 and their HMACs
* Ciphers: AES-CBC with key-sizes 128, 192 and 256
* Encoding formats: base16

[0.0.1]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.0.1>
[0.0.2]: <http://github.com/raaz-crypto/raaz/releases/tag/v0.0.2>
[raaz]:  <http://github.com/raaz-crypto/raaz/>
