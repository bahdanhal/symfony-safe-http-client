<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient\Tests;

use Bahdan\SafeHttpClient\SafeHttpFetcher;
use Bahdan\SafeHttpClient\UrlGuard;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class SafeHttpFetcherTest extends TestCase
{
    public function testResolveUrlHandlesRelativeAndAbsolute(): void
    {
        $httpClient = new MockHttpClient();
        $guard = new UrlGuard();
        $fetcher = new SafeHttpFetcher($httpClient, $guard);

        self::assertSame(
            'https://example.com/other',
            $fetcher->resolveUrl('https://example.com/base/path', '/other')
        );

        self::assertSame(
            'https://example.com/base/sub',
            $fetcher->resolveUrl('https://example.com/base/path', 'sub')
        );

        self::assertSame(
            'https://other.org/page',
            $fetcher->resolveUrl('https://example.com/base', 'https://other.org/page')
        );
    }

    public function testFetchExecutesSuccessfully(): void
    {
        $mockResponse = new MockResponse('<html>OK</html>', [
            'http_code' => 200,
            'response_headers' => ['Content-Type' => 'text/html'],
        ]);
        $httpClient = new MockHttpClient($mockResponse);
        $guard = new readonly class extends UrlGuard {
            public function assertSafe(string $url): string
            {
                return '93.184.216.34';
            }
        };

        $fetcher = new SafeHttpFetcher($httpClient, $guard);
        $result = $fetcher->fetch('https://example.com');

        self::assertSame(200, $result['status']);
        self::assertSame('<html>OK</html>', $result['body']);
        self::assertNull($result['error']);
    }
}
