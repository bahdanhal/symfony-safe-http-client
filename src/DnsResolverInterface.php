<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient;

interface DnsResolverInterface
{
    /**
     * @param list<string> $hosts
     * @return array<string, list<string>>
     */
    public function resolveMany(array $hosts): array;
}
