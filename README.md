# Symfony Safe HTTP Client

An SSRF-safe HTTP client wrapper on top of Symfony `HttpClient` with DNS resolution pinning and subnet validation.

[Packagist](https://packagist.org/packages/bahdan/symfony-safe-http-client) · [GitHub](https://github.com/bahdanhal/symfony-safe-http-client)

## Features

- **SSRF Defense**: Validates URLs against private IP ranges (RFC 1918, RFC 4193), link-local addresses, and cloud instance metadata (`169.254.169.254`).
- **DNS Resolution Pinning**: Resolves hostnames before request dispatch and pins the IP to prevent DNS rebinding attacks.
- **Concurrent DNS**: Resolves unique batch hostnames concurrently through Amp instead of serial native DNS calls.
- **Safety Limits**: Configurable body size limits, redirect limits, and request timeouts.
- **Port Allowlist**: Allows only HTTP ports 80 and 443 by default to prevent cross-protocol SSRF.
- **Batch Requests**: Concurrently fetch and safely resolve multiple URLs.
- **DI-Friendly Contract**: Type-hint `SafeHttpFetcherInterface` in application services.

## Installation

```bash
composer require bahdan/symfony-safe-http-client
```

## Usage

```php
use Bahdan\SafeHttpClient\SafeHttpFetcher;
use Bahdan\SafeHttpClient\UrlGuard;
use Symfony\Component\HttpClient\HttpClient;

$guard = new UrlGuard();
$fetcher = new SafeHttpFetcher(HttpClient::create(), $guard);

$result = $fetcher->fetch('https://example.com');
echo $result['body'];
```

Implement `DnsResolverInterface` and pass it to `UrlGuard` to use a custom resolver while retaining subnet validation and connection pinning.

Applications that intentionally fetch from another HTTP port can opt in explicitly:

```php
$guard = new UrlGuard(allowedPorts: [80, 443, 8080, 8443]);
```

## How DNS rebinding protection works

The guard resolves every hostname before a request, rejects the request if any returned address belongs to a private, loopback, link-local, reserved, multicast, documentation, or cloud metadata range, and returns one validated public address. `SafeHttpFetcher` passes that address through Symfony HttpClient's `resolve` option. The socket therefore connects to the exact address that was validated while the original hostname remains in the URL for TLS SNI and certificate verification. Redirect targets repeat the full validation and pinning process.

Canonical IPv4 and IPv6 literals are checked directly. Ambiguous legacy numeric forms such as dotted octal and hexadecimal addresses are rejected instead of being delegated to platform-dependent DNS parsing.

## Symfony dependency injection

The package is framework-agnostic, so it does not force a bundle into applications that only need the library. Register it with standard Symfony service configuration:

```yaml
# config/services.yaml
services:
  Bahdan\SafeHttpClient\UrlGuard: ~

  Bahdan\SafeHttpClient\SafeHttpFetcher:
    arguments:
      $httpClient: '@http_client'

  Bahdan\SafeHttpClient\SafeHttpFetcherInterface:
    alias: Bahdan\SafeHttpClient\SafeHttpFetcher
```

Application services can now depend on `Bahdan\SafeHttpClient\SafeHttpFetcherInterface` and replace the implementation in tests.

## License

MIT
