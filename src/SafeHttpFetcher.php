<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient;

use Symfony\Contracts\HttpClient\HttpClientInterface;

class SafeHttpFetcher
{
    private const USER_AGENT = 'BahdanToolbox/1.0 (+https://bahdanhal.pl/)';

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly UrlGuard $urlGuard,
        private readonly int $timeoutSeconds = 10,
        private readonly int $maxBodyBytes = 2_097_152,
    ) {
    }

    /**
     * @return array{
     *     requested_url: string,
     *     final_url: string,
     *     status: int,
     *     headers: array<string, list<string>>,
     *     body: string,
     *     content_type: string,
     *     duration_ms: int,
     *     redirects: list<array{url: string, status: int, location: ?string}>,
     *     error: ?string
     * }
     */
    public function fetch(string $url, int $maxRedirects = 8): array
    {
        $started = (int) hrtime(true);
        $requestedUrl = $url;
        $redirects = [];

        try {
            for ($hop = 0; $hop <= $maxRedirects; ++$hop) {
                $resolvedIp = $this->urlGuard->assertSafe($url);
                $response = $this->httpClient->request('GET', $url, $this->options($url, $resolvedIp));

                $status = $response->getStatusCode();
                /** @var array<string, list<string>> $headers */
                $headers = $response->getHeaders(false);
                $location = $headers['location'][0] ?? null;

                if ($status >= 300 && $status < 400 && is_string($location)) {
                    $redirects[] = ['url' => $url, 'status' => $status, 'location' => $location];
                    $url = $this->resolveUrl($url, $location);
                    continue;
                }

                $body = $response->getContent(false);
                $contentType = strtolower($headers['content-type'][0] ?? '');

                return [
                    'requested_url' => $requestedUrl,
                    'final_url' => $url,
                    'status' => $status,
                    'headers' => $headers,
                    'body' => $body,
                    'content_type' => $contentType,
                    'duration_ms' => $this->duration($started),
                    'redirects' => $redirects,
                    'error' => null,
                ];
            }

            throw new \RuntimeException('Too many redirects.');
        } catch (\Throwable $exception) {
            return [
                'requested_url' => $requestedUrl,
                'final_url' => $url,
                'status' => 0,
                'headers' => [],
                'body' => '',
                'content_type' => '',
                'duration_ms' => $this->duration($started),
                'redirects' => $redirects,
                'error' => $exception->getMessage(),
            ];
        }
    }

    /**
     * @param list<string> $urls
     * @return array<string, array{
     *     requested_url: string,
     *     final_url: string,
     *     status: int,
     *     headers: array<string, list<string>>,
     *     body: string,
     *     content_type: string,
     *     duration_ms: int,
     *     redirects: list<array{url: string, status: int, location: ?string}>,
     *     error: ?string
     * }> Results keyed by requested URL.
     */
    public function fetchMany(array $urls, int $maxRedirects = 8): array
    {
        $requestedUrls = array_values(array_unique($urls));
        /** @var array<string, FetchHopState> $states */
        $states = [];
        foreach ($requestedUrls as $url) {
            $states[$url] = new FetchHopState($url, $url, (int) hrtime(true));
        }

        for ($hop = 0; $hop <= $maxRedirects; ++$hop) {
            $responses = [];
            foreach ($states as $key => $state) {
                if ($state->done) {
                    continue;
                }
                try {
                    $resolvedIp = $this->urlGuard->assertSafe($state->currentUrl);
                    $responses[$key] = $this->httpClient->request('GET', $state->currentUrl, $this->options($state->currentUrl, $resolvedIp));
                } catch (\Throwable $exception) {
                    $state->result = $this->errorResult($state->requestedUrl, $state->currentUrl, $state->started, $state->redirects, $exception->getMessage());
                    $state->done = true;
                }
            }

            if ($responses === []) {
                break;
            }

            foreach ($responses as $key => $response) {
                $state = $states[$key];
                try {
                    $status = $response->getStatusCode();
                    /** @var array<string, list<string>> $headers */
                    $headers = $response->getHeaders(false);
                    $location = $headers['location'][0] ?? null;
                    if ($status >= 300 && $status < 400 && is_string($location)) {
                        $state->redirects[] = [
                            'url' => $state->currentUrl,
                            'status' => $status,
                            'location' => $location,
                        ];
                        $state->currentUrl = $this->resolveUrl($state->currentUrl, $location);
                        continue;
                    }

                    $state->result = [
                        'requested_url' => $state->requestedUrl,
                        'final_url' => $state->currentUrl,
                        'status' => $status,
                        'headers' => $headers,
                        'body' => $response->getContent(false),
                        'content_type' => strtolower($headers['content-type'][0] ?? ''),
                        'duration_ms' => $this->duration($state->started),
                        'redirects' => $state->redirects,
                        'error' => null,
                    ];
                    $state->done = true;
                } catch (\Throwable $exception) {
                    $state->result = $this->errorResult(
                        $state->requestedUrl,
                        $state->currentUrl,
                        $state->started,
                        $state->redirects,
                        $exception->getMessage()
                    );
                    $state->done = true;
                }
            }
        }

        $results = [];
        foreach ($states as $key => $state) {
            $results[$key] = $state->result ?? $this->errorResult(
                $state->requestedUrl,
                $state->currentUrl,
                $state->started,
                $state->redirects,
                'Too many redirects.'
            );
        }

        return $results;
    }

    public function resolveUrl(string $base, string $reference): string
    {
        if (preg_match('#^https?://#i', $reference)) {
            return $reference;
        }

        $baseParts = parse_url($base);
        if (!is_array($baseParts) || !isset($baseParts['scheme'], $baseParts['host'])) {
            return $reference;
        }

        $origin = $baseParts['scheme'] . '://' . $baseParts['host'] . (isset($baseParts['port']) ? ':' . $baseParts['port'] : '');
        if (str_starts_with($reference, '//')) {
            return $baseParts['scheme'] . ':' . $reference;
        }
        if (str_starts_with($reference, '/')) {
            return $origin . $reference;
        }
        if (str_starts_with($reference, '?')) {
            return $origin . ($baseParts['path'] ?? '/') . $reference;
        }

        $directory = preg_replace('#/[^/]*$#', '/', $baseParts['path'] ?? '/');
        $path = $directory . $reference;
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);
            } else {
                $segments[] = $segment;
            }
        }

        return $origin . '/' . implode('/', $segments);
    }

    private function duration(int $started): int
    {
        return (int) round((hrtime(true) - $started) / 1_000_000);
    }

    /**
     * @return array<string, mixed>
     */
    private function options(string $url, string $resolvedIp): array
    {
        $host = (string) parse_url($url, PHP_URL_HOST);

        return [
            'headers' => [
                'User-Agent' => self::USER_AGENT,
                'Accept' => 'text/html,application/xhtml+xml,application/xml,text/xml;q=0.9,*/*;q=0.5',
            ],
            'max_redirects' => 0,
            'timeout' => $this->timeoutSeconds,
            'max_duration' => $this->timeoutSeconds,
            'verify_peer' => true,
            'verify_host' => true,
            'resolve' => [$host => $resolvedIp],
            'on_progress' => function (int $downloaded, int $downloadSize): void {
                if ($downloaded > $this->maxBodyBytes || $downloadSize > $this->maxBodyBytes) {
                    throw new \RuntimeException('Response body exceeded the configured size limit.');
                }
            },
        ];
    }

    /**
     * @param list<array{url: string, status: int, location: ?string}> $redirects
     * @return array{
     *     requested_url: string,
     *     final_url: string,
     *     status: int,
     *     headers: array<string, list<string>>,
     *     body: string,
     *     content_type: string,
     *     duration_ms: int,
     *     redirects: list<array{url: string, status: int, location: ?string}>,
     *     error: ?string
     * }
     */
    private function errorResult(string $requestedUrl, string $currentUrl, int $started, array $redirects, string $message): array
    {
        return [
            'requested_url' => $requestedUrl,
            'final_url' => $currentUrl,
            'status' => 0,
            'headers' => [],
            'body' => '',
            'content_type' => '',
            'duration_ms' => $this->duration($started),
            'redirects' => $redirects,
            'error' => $message,
        ];
    }
}
