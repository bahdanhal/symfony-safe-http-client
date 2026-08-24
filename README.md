# Symfony Safe HTTP Client

An SSRF-safe HTTP client wrapper on top of Symfony `HttpClient` with DNS resolution pinning and subnet validation.

## Features

- **SSRF Defense**: Validates URLs against private IP ranges (RFC 1918, RFC 4193), link-local addresses, and cloud instance metadata (`169.254.169.254`).
- **DNS Resolution Pinning**: Resolves hostnames before request dispatch and pins the IP to prevent DNS rebinding attacks.
- **Safety Limits**: Configurable body size limits, redirect limits, and request timeouts.
- **Batch Requests**: Concurrently fetch and safely resolve multiple URLs.

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

## License

MIT
