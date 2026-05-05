<?php

namespace GameCrypto\Modules;

use InvalidArgumentException;

class MailModule extends AbstractSoapModule
{
    public function send(string $player, string $subject, string $body): string
    {
        return $this->executeSegments(['send', 'mail', $player, $subject, $body]);
    }

    public function sendMoney(string $player, string $subject, string $body, int $copper): string
    {
        if ($copper < 0) {
            throw new InvalidArgumentException('Money amount cannot be negative.');
        }

        return $this->executeSegments(['send', 'money', $player, $subject, $body, $copper]);
    }

    /**
     * @param array<int|string, int> $items
     */
    public function sendItems(string $player, string $subject, string $body, array $items): string
    {
        return $this->executeSegments([
            'send',
            'items',
            $player,
            $subject,
            $body,
            ...$this->normalizeItems($items),
        ]);
    }

    /**
     * @param array<int|string, int> $items
     */
    public function sendItemsAndMoney(string $player, string $subject, string $body, array $items, int $copper): string
    {
        if ($copper < 0) {
            throw new InvalidArgumentException('Money amount cannot be negative.');
        }

        return $this->executeSegments([
            'send',
            'items',
            $player,
            $subject,
            $body,
            ...$this->normalizeItems($items),
            $copper,
        ]);
    }

    /**
     * @param array<int|string, int> $items
     * @return list<string>
     */
    private function normalizeItems(array $items): array
    {
        $segments = [];

        foreach ($items as $itemId => $count) {
            if (is_string($itemId)) {
                $segments[] = $count > 1 ? sprintf('%s:%d', $itemId, $count) : $itemId;
                continue;
            }

            if ($count < 1) {
                throw new InvalidArgumentException('Each sent item must have a quantity of at least 1.');
            }

            $segments[] = $count > 1 ? sprintf('%d:%d', $itemId, $count) : (string) $itemId;
        }

        return $segments;
    }
}