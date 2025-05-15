<?php

namespace GameCrypto\Enums;

enum EncryptionType: string
{
    case SHA_PASS_HASH = 'sha_pass_hash';
    case SRP6_V1 = 'srp6_v1';
    case SRP6_V2 = 'srp6_v2';
    case BNET = 'bnet';
}