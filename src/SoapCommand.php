<?php

namespace GameCrypto;

use InvalidArgumentException;
use Stringable;

class SoapCommand
{
    /**
     * @var list<string>
     */
    private array $segments;

    /**
     * @param list<string> $segments
     */
    private function __construct(array $segments)
    {
        if ($segments === []) {
            throw new InvalidArgumentException('A SOAP command requires at least one segment.');
        }

        $this->segments = $segments;
    }

    public static function raw(string $command): self
    {
        $command = trim($command);

        if ($command === '') {
            throw new InvalidArgumentException('A raw SOAP command cannot be empty.');
        }

        return new self([$command]);
    }

    /**
     * @param iterable<string|int|float|bool|Stringable|null> $segments
     */
    public static function fromSegments(iterable $segments): self
    {
        $normalizedSegments = [];

        foreach ($segments as $segment) {
            if ($segment === null) {
                continue;
            }

            $value = trim((string) $segment);

            if ($value === '') {
                continue;
            }

            $normalizedSegments[] = self::quoteIfNeeded($value);
        }

        return new self($normalizedSegments);
    }

    public function append(string|int|float|bool|Stringable|null $segment): self
    {
        if ($segment === null) {
            return $this;
        }

        $value = trim((string) $segment);

        if ($value === '') {
            return $this;
        }

        $segments = $this->segments;
        $segments[] = self::quoteIfNeeded($value);

        return new self($segments);
    }

    public function toCommandString(): string
    {
        if (count($this->segments) === 1) {
            return $this->segments[0];
        }

        return implode(' ', $this->segments);
    }

    private static function quoteIfNeeded(string $value): string
    {
        $escapedValue = str_replace(['\\', '"'], ['\\\\', '\\"'], $value);

        if ($escapedValue === '' || preg_match('/\s|"/', $escapedValue) === 1) {
            return sprintf('"%s"', $escapedValue);
        }

        return $escapedValue;
    }
}