<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient\Tests;

use Bahdan\SafeHttpClient\Exception\UnsafeUrlException;
use Bahdan\SafeHttpClient\UrlGuard;
use PHPUnit\Framework\TestCase;

final class UrlGuardTest extends TestCase
{
    private UrlGuard $urlGuard;

    protected function setUp(): void
    {
        $this->urlGuard = new UrlGuard();
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

    public function testNormalizeRejectsCredentials(): void
    {
        $this->expectException(UnsafeUrlException::class);
        $this->expectExceptionMessage('URLs containing credentials are not allowed.');
        $this->urlGuard->normalize('http://user:pass@example.com');
    }
}
