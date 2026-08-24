<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient;

use Bahdan\SafeHttpClient\Exception\UnsafeUrlException;

readonly class UrlGuard
{
    public function normalize(string $input): string
    {
        $input = trim($input);
        if ($input === '') {
            throw new UnsafeUrlException('Enter a website URL.');
        }

        if (!preg_match('#^https?://#i', $input)) {
            $input = 'https://' . $input;
        }

        $parts = parse_url($input);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw new UnsafeUrlException('The URL is not valid.');
        }

        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new UnsafeUrlException('Only HTTP and HTTPS URLs are supported.');
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new UnsafeUrlException('URLs containing credentials are not allowed.');
        }

        $host = strtolower(rtrim($parts['host'], '.'));
        $this->assertPublicHost($host);

        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $path = $parts['path'] ?? '/';
        $path = $path === '' ? '/' : $path;
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';

        return $scheme . '://' . $host . $port . $path . $query;
    }

    public function assertSafe(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw new UnsafeUrlException('A redirect pointed to an invalid URL.');
        }

        if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            throw new UnsafeUrlException('A redirect used an unsupported protocol.');
        }

        return $this->assertPublicHost(strtolower(rtrim($parts['host'], '.')));
    }

    private function assertPublicHost(string $host): string
    {
        $rawHost = trim($host, '[]');
        if (filter_var($rawHost, FILTER_VALIDATE_IP)) {
            if (filter_var($rawHost, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                throw new UnsafeUrlException('Private, reserved, and local network targets are not allowed.');
            }

            return $rawHost;
        }

        if ($host === 'localhost' || str_ends_with($host, '.localhost') || !str_contains($host, '.')) {
            throw new UnsafeUrlException('Local and internal hostnames are not allowed.');
        }

        $records = dns_get_record($host, DNS_A | DNS_AAAA);
        if ($records === false || $records === []) {
            throw new UnsafeUrlException('The hostname could not be resolved.');
        }

        foreach ($records as $record) {
            $ip = $record['ip'] ?? $record['ipv6'] ?? null;
            if ($ip === null || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                throw new UnsafeUrlException('Private, reserved, and local network targets are not allowed.');
            }
        }

        return $records[0]['ip'] ?? $records[0]['ipv6'];
    }
}
