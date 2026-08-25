<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient;

use Bahdan\SafeHttpClient\Exception\UnsafeUrlException;

readonly class UrlGuard
{
    private DnsResolverInterface $dnsResolver;

    public function __construct(?DnsResolverInterface $dnsResolver = null)
    {
        $this->dnsResolver = $dnsResolver ?? new AsyncDnsResolver();
    }

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
        return $this->assertSafeMany([$url])[$url];
    }

    /**
     * Resolves all hostnames concurrently and returns one pinned address per URL.
     *
     * @param list<string> $urls
     * @return array<string, string>
     */
    public function assertSafeMany(array $urls): array
    {
        /** @var array<string, string> $hosts */
        $hosts = [];
        /** @var array<string, string> $resolved */
        $resolved = [];

        foreach ($urls as $url) {
            $host = $this->validatedHost($url);
            $rawHost = trim($host, '[]');
            $this->assertCanonicalIpNotation($rawHost);
            if (filter_var($rawHost, FILTER_VALIDATE_IP)) {
                if ($this->isIpBlocked($rawHost)) {
                    throw new UnsafeUrlException('Private, reserved, and local network targets are not allowed.');
                }
                $resolved[$url] = $rawHost;
                continue;
            }

            if ($host === 'localhost' || str_ends_with($host, '.localhost') || !str_contains($host, '.')) {
                throw new UnsafeUrlException('Local and internal hostnames are not allowed.');
            }
            $hosts[$url] = $host;
        }

        $recordsByHost = $this->dnsResolver->resolveMany(array_values(array_unique($hosts)));
        foreach ($hosts as $url => $host) {
            $records = $recordsByHost[$host] ?? [];
            if ($records === []) {
                throw new UnsafeUrlException('The hostname could not be resolved.');
            }
            foreach ($records as $ip) {
                if ($this->isIpBlocked($ip)) {
                    throw new UnsafeUrlException('Private, reserved, and local network targets are not allowed.');
                }
            }
            $resolved[$url] = $records[0];
        }

        return $resolved;
    }

    private function validatedHost(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw new UnsafeUrlException('A redirect pointed to an invalid URL.');
        }

        if (!in_array(strtolower($parts['scheme']), ['http', 'https'], true)) {
            throw new UnsafeUrlException('A redirect used an unsupported protocol.');
        }

        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new UnsafeUrlException('URLs containing credentials are not allowed.');
        }

        return strtolower(rtrim($parts['host'], '.'));
    }

    /**
     * @var list<array{0: string, 1: int}>
     */
    private const array IPV4_BLOCKED_RANGES = [
        ['0.0.0.0', 8],          // Current network (RFC 1122)
        ['10.0.0.0', 8],         // Private-Use (RFC 1918)
        ['100.64.0.0', 10],      // Carrier-Grade NAT (RFC 6598)
        ['127.0.0.0', 8],        // Loopback (RFC 1122)
        ['169.254.0.0', 16],     // Link-Local / Cloud IMDS (RFC 3927)
        ['172.16.0.0', 12],      // Private-Use (RFC 1918)
        ['192.0.0.0', 24],       // IETF Protocol Assignments (RFC 6890)
        ['192.0.2.0', 24],       // TEST-NET-1 (RFC 5737)
        ['192.168.0.0', 16],     // Private-Use (RFC 1918)
        ['198.18.0.0', 15],      // Network benchmark tests (RFC 2544)
        ['198.51.100.0', 24],    // TEST-NET-2 (RFC 5737)
        ['203.0.113.0', 24],     // TEST-NET-3 (RFC 5737)
        ['224.0.0.0', 4],        // Multicast (RFC 5771)
        ['240.0.0.0', 4],        // Reserved for future use (RFC 1112)
        ['255.255.255.255', 32], // Limited Broadcast
    ];

    /**
     * @var list<array{0: string, 1: int}>
     */
    private const array IPV6_BLOCKED_RANGES = [
        ['::', 128],             // Unspecified
        ['::1', 128],            // Loopback
        ['fc00::', 7],           // Unique Local Address (RFC 4193)
        ['fe80::', 10],          // Link-Local (RFC 4291)
        ['ff00::', 8],           // Multicast (RFC 4291)
        ['2001:db8::', 32],      // Documentation (RFC 3849)
    ];

    private function assertPublicHost(string $host): string
    {
        $rawHost = trim($host, '[]');
        $this->assertCanonicalIpNotation($rawHost);
        if (filter_var($rawHost, FILTER_VALIDATE_IP)) {
            if ($this->isIpBlocked($rawHost)) {
                throw new UnsafeUrlException('Private, reserved, and local network targets are not allowed.');
            }

            return $rawHost;
        }

        if ($host === 'localhost' || str_ends_with($host, '.localhost') || !str_contains($host, '.')) {
            throw new UnsafeUrlException('Local and internal hostnames are not allowed.');
        }

        $records = $this->dnsResolver->resolveMany([$host])[$host] ?? [];
        if ($records === []) {
            throw new UnsafeUrlException('The hostname could not be resolved.');
        }

        foreach ($records as $ip) {
            if ($this->isIpBlocked($ip)) {
                throw new UnsafeUrlException('Private, reserved, and local network targets are not allowed.');
            }
        }

        return $records[0];
    }

    private function assertCanonicalIpNotation(string $host): void
    {
        if (
            filter_var($host, FILTER_VALIDATE_IP) === false
            && preg_match('/^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$/i', $host) === 1
        ) {
            throw new UnsafeUrlException('Non-canonical numeric IP addresses are not allowed.');
        }
    }

    public function isIpBlocked(string $ip): bool
    {
        if ($ip === '100.100.100.200') {
            // Alibaba Cloud IMDS
            return true;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $in6 = @inet_pton($ip);
            if ($in6 === false) {
                return true;
            }

            // Check if IPv4-mapped IPv6 (::ffff:0:0/96)
            if (str_starts_with($in6, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF")) {
                $ipv4 = inet_ntop(substr($in6, 12, 4));
                if ($ipv4 !== false) {
                    return $this->isIpBlocked($ipv4);
                }
            }

            foreach (self::IPV6_BLOCKED_RANGES as [$subnet, $mask]) {
                if ($this->matchIpv6Subnet($in6, $subnet, $mask)) {
                    return true;
                }
            }

            return false;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $long = ip2long($ip);
            if ($long === false) {
                return true;
            }
            $ipDec = (float) sprintf('%u', $long);

            foreach (self::IPV4_BLOCKED_RANGES as [$subnet, $mask]) {
                $subnetLong = ip2long($subnet);
                if ($subnetLong === false) {
                    continue;
                }
                $subnetDec = (float) sprintf('%u', $subnetLong);
                $maskBits = $mask === 0 ? 0 : ((~0 << (32 - $mask)) & 0xFFFFFFFF);
                $maskDec = (float) sprintf('%u', $maskBits);

                if (((int) $ipDec & (int) $maskDec) === ((int) $subnetDec & (int) $maskDec)) {
                    return true;
                }
            }

            return false;
        }

        return true;
    }

    private function matchIpv6Subnet(string $in6, string $subnetStr, int $mask): bool
    {
        $subnetIn6 = inet_pton($subnetStr);
        if ($subnetIn6 === false) {
            return false;
        }
        $bytes = intdiv($mask, 8);
        $bits = $mask % 8;

        if ($bytes > 0 && substr($in6, 0, $bytes) !== substr($subnetIn6, 0, $bytes)) {
            return false;
        }
        if ($bits > 0) {
            $maskByte = (~0 << (8 - $bits)) & 0xFF;
            $in6Byte = ord($in6[$bytes]);
            $subByte = ord($subnetIn6[$bytes]);
            if (($in6Byte & $maskByte) !== ($subByte & $maskByte)) {
                return false;
            }
        }

        return true;
    }
}
