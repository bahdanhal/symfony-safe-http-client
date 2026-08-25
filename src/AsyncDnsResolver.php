<?php

declare(strict_types=1);

namespace Bahdan\SafeHttpClient;

use Amp\Dns\DnsRecord;
use Amp\Future;

use function Amp\async;
use function Amp\Dns\resolve;

final readonly class AsyncDnsResolver implements DnsResolverInterface
{
    public function resolveMany(array $hosts): array
    {
        /** @var array<string, Future<list<string>>> $futures */
        $futures = [];
        foreach (array_values(array_unique($hosts)) as $host) {
            $futures[$host] = async(static function () use ($host): array {
                try {
                    return array_values(array_unique(array_map(
                        static fn (DnsRecord $record): string => $record->getValue(),
                        resolve($host),
                    )));
                } catch (\Throwable) {
                    return [];
                }
            });
        }

        /** @var array<string, list<string>> $results */
        $results = Future\await($futures);

        return $results;
    }
}
