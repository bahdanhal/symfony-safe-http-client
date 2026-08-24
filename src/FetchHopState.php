<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient;

/**
 * @internal
 */
final class FetchHopState
{
    /**
     * @param list<array{url: string, status: int, location: ?string}> $redirects
     * @param array{
     *     requested_url: string,
     *     final_url: string,
     *     status: int,
     *     headers: array<string, list<string>>,
     *     body: string,
     *     content_type: string,
     *     duration_ms: int,
     *     redirects: list<array{url: string, status: int, location: ?string}>,
     *     error: ?string
     * }|null $result
     */
    public function __construct(
        public string $requestedUrl,
        public string $currentUrl,
        public int $started,
        public array $redirects = [],
        public bool $done = false,
        public ?array $result = null,
    ) {
    }
}
