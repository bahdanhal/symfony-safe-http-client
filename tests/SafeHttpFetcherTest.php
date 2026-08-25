<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient\Tests;

use Bahdan\SafeHttpClient\DnsResolverInterface;
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

        self::assertSame(
            'https://example.com/dir/sub/',
            $fetcher->resolveUrl('https://example.com/dir/', 'sub/')
        );

        self::assertSame(
            'https://example.com/dir/?page=2#results',
            $fetcher->resolveUrl('https://example.com/dir/item', './?page=2#results')
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

    public function testFetchManyProcessesConcurrently(): void
    {
        $mockResponse1 = new MockResponse('<html>Page 1</html>', [
            'http_code' => 200,
            'response_headers' => ['Content-Type' => 'text/html'],
        ]);
        $mockResponse2 = new MockResponse('<html>Page 2</html>', [
            'http_code' => 200,
            'response_headers' => ['Content-Type' => 'text/html'],
        ]);
        $httpClient = new MockHttpClient([$mockResponse1, $mockResponse2]);
        $resolver = new class implements DnsResolverInterface {
            /** @var list<list<string>> */
            public array $batches = [];

            public function resolveMany(array $hosts): array
            {
                $this->batches[] = $hosts;

                return array_fill_keys($hosts, ['93.184.216.34']);
            }
        };
        $guard = new UrlGuard($resolver);

        $fetcher = new SafeHttpFetcher($httpClient, $guard);
        $results = $fetcher->fetchMany(['https://example.com/p1', 'https://example.com/p2']);

        self::assertCount(2, $results);
        self::assertSame(200, $results['https://example.com/p1']['status']);
        self::assertSame('<html>Page 1</html>', $results['https://example.com/p1']['body']);
        self::assertSame(200, $results['https://example.com/p2']['status']);
        self::assertSame('<html>Page 2</html>', $results['https://example.com/p2']['body']);
        self::assertCount(1, $resolver->batches);
        self::assertSame(['example.com'], $resolver->batches[0]);
    }

    public function testFetchRejectsCredentialBearingRedirectBeforeSecondRequest(): void
    {
        $requestCount = 0;
        $httpClient = new MockHttpClient(static function () use (&$requestCount): MockResponse {
            ++$requestCount;

            return new MockResponse('', [
                'http_code' => 302,
                'response_headers' => ['Location' => 'https://user:secret@example.com/private'],
            ]);
        });
        $guard = new UrlGuard(new class implements DnsResolverInterface {
            public function resolveMany(array $hosts): array
            {
                return array_fill_keys($hosts, ['93.184.216.34']);
            }
        });

        $result = (new SafeHttpFetcher($httpClient, $guard))->fetch('https://example.com');

        self::assertSame(1, $requestCount);
        self::assertSame(0, $result['status']);
        self::assertSame('URLs containing credentials are not allowed.', $result['error']);
    }

    public function testEnforcesMaxBodyBytesLimit(): void
    {
        $largeBody = str_repeat('A', 500);
        $mockResponse = new MockResponse($largeBody, [
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

        // maxBodyBytes = 100
        $fetcher = new SafeHttpFetcher($httpClient, $guard, 10, 100);
        $result = $fetcher->fetch('https://example.com');

        self::assertSame(0, $result['status']);
        self::assertStringContainsString('Response body exceeded the configured size limit', (string) $result['error']);
    }
}
