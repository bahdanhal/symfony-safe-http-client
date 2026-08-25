<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient\Tests;

use Bahdan\SafeHttpClient\Exception\UnsafeUrlException;
use Bahdan\SafeHttpClient\DnsResolverInterface;
use Bahdan\SafeHttpClient\UrlGuard;
use PHPUnit\Framework\TestCase;

final class UrlGuardTest extends TestCase
{
    private UrlGuard $urlGuard;

    protected function setUp(): void
    {
        $this->urlGuard = new UrlGuard(new class implements DnsResolverInterface {
            public function resolveMany(array $hosts): array
            {
                return array_fill_keys($hosts, ['93.184.216.34']);
            }
        });
    }

    public function testNormalizeValidUrl(): void
    {
        $normalized = $this->urlGuard->normalize('example.com/path?arg=1');
        self::assertSame('https://example.com/path?arg=1', $normalized);
    }

    public function testNormalizeRejectsEmptyString(): void
    {
        $this->expectException(UnsafeUrlException::class);
        $this->expectExceptionMessage('Enter a website URL.');
        $this->urlGuard->normalize('   ');
    }

    public function testNormalizeRejectsPrivateIp(): void
    {
        $this->expectException(UnsafeUrlException::class);
        $this->expectExceptionMessage('Private, reserved, and local network targets are not allowed.');
        $this->urlGuard->normalize('http://127.0.0.1');
    }

    public function testNormalizeRejectsLocalhost(): void
    {
        $this->expectException(UnsafeUrlException::class);
        $this->expectExceptionMessage('Local and internal hostnames are not allowed.');
        $this->urlGuard->normalize('http://localhost:8080');
    }

    /** @param string $url */
    #[\PHPUnit\Framework\Attributes\DataProvider('provideAmbiguousNumericHosts')]
    public function testNormalizeRejectsAmbiguousNumericIpNotation(string $url): void
    {
        $this->expectException(UnsafeUrlException::class);
        $this->expectExceptionMessage('Non-canonical numeric IP addresses are not allowed.');
        $this->urlGuard->normalize($url);
    }

    /** @return iterable<string, array{string}> */
    public static function provideAmbiguousNumericHosts(): iterable
    {
        yield 'dotted octal loopback' => ['http://0177.0.0.1'];
        yield 'dotted hexadecimal loopback' => ['http://0x7f.0x0.0x0.0x1'];
        yield 'single integer loopback' => ['http://2130706433'];
    }

    public function testNormalizeRejectsCredentials(): void
    {
        $this->expectException(UnsafeUrlException::class);
        $this->expectExceptionMessage('URLs containing credentials are not allowed.');
        $this->urlGuard->normalize('http://user:pass@example.com');
    }

    public function testRedirectValidationRejectsCredentials(): void
    {
        $this->expectException(UnsafeUrlException::class);
        $this->expectExceptionMessage('URLs containing credentials are not allowed.');
        $this->urlGuard->assertSafe('https://user:secret@example.com/private');
    }

    /**
     * @param string $ip
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('provideBlockedIps')]
    public function testRejectsBlockedIps(string $ip): void
    {
        self::assertTrue($this->urlGuard->isIpBlocked($ip), "Expected IP $ip to be blocked.");
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideBlockedIps(): iterable
    {
        yield 'current network 0.0.0.0' => ['0.0.0.0'];
        yield 'current network 0.1.2.3' => ['0.1.2.3'];
        yield 'loopback 127.0.0.1' => ['127.0.0.1'];
        yield 'private 10.0.0.1' => ['10.0.0.1'];
        yield 'cgnat 100.64.0.1' => ['100.64.0.1'];
        yield 'cgnat 100.127.255.254' => ['100.127.255.254'];
        yield 'alibaba imds' => ['100.100.100.200'];
        yield 'aws imds 169.254.169.254' => ['169.254.169.254'];
        yield 'private 172.16.0.1' => ['172.16.0.1'];
        yield 'private 192.168.1.1' => ['192.168.1.1'];
        yield 'multicast 224.0.0.1' => ['224.0.0.1'];
        yield 'broadcast 255.255.255.255' => ['255.255.255.255'];
        yield 'ipv6 loopback ::1' => ['::1'];
        yield 'ipv6 unspecified ::' => ['::'];
        yield 'ipv6 link local fe80::1' => ['fe80::1'];
        yield 'ipv6 unique local fc00::1' => ['fc00::1'];
        yield 'aws imdsv6' => ['fd00:ec2::254'];
        yield 'ipv4 mapped loopback' => ['::ffff:127.0.0.1'];
        yield 'ipv4 mapped imds' => ['::ffff:169.254.169.254'];
    }
}
