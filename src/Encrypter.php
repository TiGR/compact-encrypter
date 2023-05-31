<?php

namespace TiGR\CompactEncrypter;

use RuntimeException;

final class Encrypter
{
    public const SUPPORTED_KEY_SIZES = [
        'AES-128-CBC' => 16,
        'AES-256-CBC' => 32,
    ];

    protected string $key;

    protected string $cipher;

    public function __construct(string $key, string $cipher = 'AES-128-CBC')
    {
        if (!self::supported($key, $cipher)) {
            if (!self::isCipherSupported($cipher)) {
                throw new RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
            }

            throw new RuntimeException(sprintf('Invalid key length (%d) for %s cipher.', strlen($key), $cipher));
        }

        $this->key = $key;
        $this->cipher = $cipher;
    }

    /**
     * Determine if the given key and cipher combination is valid.
     */
    public static function supported(string $key, string $cipher): bool
    {
        return self::isCipherSupported($cipher) and self::SUPPORTED_KEY_SIZES[$cipher] === strlen($key);
    }

    private static function isCipherSupported(string $cipher): bool
    {
        return isset(self::SUPPORTED_KEY_SIZES[$cipher]);
    }

    /**
     * Create a new encryption key for the given cipher.
     */
    public static function generateKey(string $cipher): string
    {
        return random_bytes(self::SUPPORTED_KEY_SIZES[$cipher]);
    }

    /**
     * Encrypt the given value.
     */
    public function encrypt($value, $serialize = true, bool $useMac = true): string
    {
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));

        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        $value = openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv
        );

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        // Once we get the encrypted value we'll go ahead and base64_encode the input
        // vector and create the MAC for the encrypted value so we can then verify
        // its authenticity. Then, we'll JSON the data into the "payload" array.
        if ($useMac) {
            $mac = $this->hash($iv, $value);
            $pack = pack('a20a16a*', $mac, $iv, $value);
        } else {
            $pack = pack('a16a*', $iv, $value);
        }

        return $this->base64_encode($pack);
    }

    /**
     * Encrypt a string without serialization.
     */
    public function encryptString(string $value, bool $useMac = true): string
    {
        return $this->encrypt($value, false, $useMac);
    }

    /**
     * Decrypt the given value.
     */
    public function decrypt(string $payload, bool $unserialize = true, bool $useMac = true)
    {
        $payloadData = $this->getPayload($payload, $useMac);

        // Here we will decrypt the value. If we are able to successfully decrypt it
        // we will then unserialize it and return it out to the caller. If we are
        // unable to decrypt this value we will throw out an exception message.
        $decrypted = openssl_decrypt(
            $payloadData['value'], $this->cipher, $this->key, OPENSSL_RAW_DATA, $payloadData['iv']
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
    }

    /**
     * Decrypt the given string without unserialization.
     */
    public function decryptString(string $payload, bool $useMac = true): string
    {
        return $this->decrypt($payload, false, $useMac);
    }

    /**
     * Get the encryption key.
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Create a MAC for the given value.
     */
    protected function hash(string $iv, string $value): string
    {
        return hash_hmac('sha1', $iv.$value, $this->key, true);
    }

    /**
     * Get the JSON array from the given payload.
     */
    protected function getPayload(string $payload, bool $useMac = true): array
    {
        $payloadData = @unpack(($useMac ? 'a20mac/' : '').'a16iv/a*value', $this->base64_decode($payload));

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if ($payloadData === false or !$this->isValidPayload($payloadData, $useMac)) {
            throw new DecryptException('The payload is invalid.');
        }

        if ($useMac and !$this->isValidMac($payloadData)) {
            throw new DecryptException('The MAC is invalid.');
        }

        return $payloadData;
    }

    /**
     * Verify that the encryption payload is valid.
     */
    protected function isValidPayload(array $payload, bool $useMac = true): bool
    {
        if (!isset($payload['iv'], $payload['value'])) {
            return false;
        }

        if ($useMac and !(isset($payload['mac']) and strlen($payload['mac']) === 20)) {
            return false;
        }

        if (strlen($payload['iv']) !== openssl_cipher_iv_length($this->cipher)) {
            return false;
        }

        if (strlen($payload['value']) % 16 !== 0) {
            return false;
        }

        return true;
    }

    /**
     * Determine if the MAC for the given payload is valid.
     */
    protected function isValidMac(array $payload): bool
    {
        return hash_equals($payload['mac'], $this->hash($payload['iv'], $payload['value']));
    }

    /**
     * URL-safe base64_encode
     */
    private function base64_encode(string $data): string
    {
        return strtr(rtrim(base64_encode($data), '='), '+/', '-_');
    }

    /**
     * URL-safe base64_decode
     */
    private function base64_decode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }
}
