<?php /** @noinspection PhpUnhandledExceptionInspection */

namespace TiGR\CompactEncrypter\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use TiGR\CompactEncrypter\DecryptException;
use TiGR\CompactEncrypter\Encrypter;

/**
 * Class EncrypterTest
 *
 * @package TiGR\Encrypter\Tests
 * @covers \TiGR\CompactEncrypter\Encrypter
 */
final class EncrypterTest extends TestCase
{
    public function testEncryption()
    {
        $e = new Encrypter(str_repeat('a', 16));
        $encrypted = $e->encrypt('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $e = new Encrypter(str_repeat('a', 16));
        $encrypted = $e->encryptString('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testEncryptionUsingBase64EncodedKey()
    {
        $e = new Encrypter(random_bytes(16));
        $encrypted = $e->encrypt('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithCustomCipher()
    {
        $e = new Encrypter(str_repeat('b', 32), 'AES-256-CBC');
        $encrypted = $e->encrypt('bar');
        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));
        $e = new Encrypter(random_bytes(32), 'AES-256-CBC');
        $encrypted = $e->encrypt('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testDoNoAllowLongerKey()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid key length (32) for AES-128-CBC cipher.');
        new Encrypter(str_repeat('z', 32));
    }

    public function testWithBadKeyLength()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid key length (5) for AES-128-CBC cipher.');
        new Encrypter(str_repeat('a', 5));
    }

    public function testWithBadKeyLengthAlternativeCipher()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
        new Encrypter(str_repeat('a', 16), 'AES-256-CFB8');
    }

    public function testWithUnsupportedCipher()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
        new Encrypter(str_repeat('c', 16), 'AES-256-CFB8');
    }

    public function testExceptionThrownWhenPayloadIsInvalid()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('The payload is invalid.');
        $e = new Encrypter(str_repeat('a', 16));
        $payload = $e->encrypt('foo');
        $payload = substr($payload, 0, -3);
        $e->decrypt($payload);
    }

    public function testExceptionThrownWithDifferentKey()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('The MAC is invalid.');
        $a = new Encrypter(str_repeat('a', 16));
        $b = new Encrypter(str_repeat('b', 16));
        $b->decrypt($a->encrypt('baz'));
    }

    public function testNoMac()
    {
        $encrypter = $this->encryptRandomBytes($encrypted, $data, 8, false);
        $this->assertEquals($data, $encrypter->decryptString($encrypted, false));
    }

    public function testEncryptedLength()
    {
        $this->encryptRandomBytes($encrypted, $data);

        $this->assertNotEquals($encrypted, $data);
        $this->assertEquals(70, strlen($encrypted));

        $this->encryptRandomBytes($encrypted, $data, 8, false);

        $this->assertEquals(43, strlen($encrypted));
    }

    /**
     * @
     */
    public function testBadMac()
    {
        $encrypter = $this->encryptRandomBytes($encrypted, $data);
        $this->expectExceptionMessage('The MAC is invalid.');
        $encrypter->decryptString(str_shuffle($encrypted));
    }

    public function testUnencryptable()
    {
        $encrypter = $this->encryptRandomBytes($encrypted, $data, 8, false);
        $this->expectExceptionMessage('Could not decrypt the data.');
        $encrypter->decryptString(substr($encrypted, 0, -16).str_shuffle(substr($encrypted, -16)), false);
    }

    private function getEncrypter(string $cipher = 'AES-256-CBC', string $key = null): Encrypter
    {
        return new Encrypter($key ?: Encrypter::generateKey($cipher), $cipher);
    }

    private function encryptRandomBytes(
        string &$encrypted = null,
        string &$data = null,
        int $bytes = 8,
        bool $useMac = true
    ): Encrypter {
        $data = random_bytes($bytes);

        if (!isset($encrypter)) {
            $encrypter = $this->getEncrypter();
        }

        $encrypted = $encrypter->encryptString($data, $useMac);

        return $encrypter;
    }
}
