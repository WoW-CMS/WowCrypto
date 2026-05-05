<?php

namespace GameCrypto\Contracts;

interface AccountPayloadFormatterInterface
{
    /**
     * Builds an emulator-specific credential payload for the host application.
     *
     * The payload is shaped for CMS-side account creation flows that:
     * - check duplicates in the `account` table
     * - insert emulator-specific credential columns
     * - link the created account through the auth table primary key
     *
     * @return array<string, mixed>
     */
    public function formatPayload(string $username, string $password, ?string $email = null): array;
}