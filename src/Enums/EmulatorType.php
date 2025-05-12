<?php

namespace GameCrypto\Enums;

enum EmulatorType: string
{
    case MANGOS = 'mangos';
    case TRINITY_CORE = 'trinity_core';
    case AZEROTH_CORE = 'azeroth_core';
    case CMANGOS = 'cmangos';
    case SKYFIRE = 'skyfire';
}