# URL-safe Compact Encrypter

![Travis (.org)](https://img.shields.io/travis/TiGR/compact-encrypter.svg)
![PHP from Packagist](https://img.shields.io/badge/php-7.4%2B-blue.svg)
![Packagist Version](https://img.shields.io/packagist/v/TiGR/compact-encrypter.svg)
![GitHub](https://img.shields.io/github/license/TiGR/compact-encrypter.svg)

Simple compact encrypter

## Installation

```
composer require tigr/compact-encrypter
```

## Why?

It provides very concise encrypted URL-safe data. For instance, it could be used
to create self-contained tokens that would contain all the necessary information inside.

## How does it work?

1. No intermediate base64 or hex encoding, all data is raw binary.
2. No JSON, use pack()/unpack().
3. Use URL-safe version of base64 (drop trailing '=', replace '/+' with '-_').
4. For hashing, use SHA1 instead of SHA256. I know, I know, but for real-world
   purposes SHA1 is still good enough.
5. Allow dropping Mac (validation hash) whatsoever if you want it really short.
