<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient;

interface SafeHttpFetcherInterface
{
    /** @return array<string, mixed> */
    public function fetch(string $url, int $maxRedirects = 8): array;

    /**
     * @param list<string> $urls
     * @return array<string, array<string, mixed>>
     */
    public function fetchMany(array $urls, int $maxRedirects = 8): array;
}
