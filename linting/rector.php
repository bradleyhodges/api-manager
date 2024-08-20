<?php
    declare(strict_types=1);

    use Rector\Config\RectorConfig;
    use Rector\Set\ValueObject\SetList;

    return static function (RectorConfig $rectorConfig): void {
        $rectorConfig->paths([
            __DIR__ . '/../',
        ]);

        // Optionally, exclude certain directories
        $rectorConfig->skip([
            'vendor',
            'linting',
        ]);

        // Apply a comprehensive set of rules for high-quality, type-safe, and secure code
        $rectorConfig->sets([
            SetList::CODE_QUALITY,
            SetList::PHP_80,           // Example: Upgrade to PHP 8.0 syntax
            SetList::TYPE_DECLARATION, // Enforce type declarations
            SetList::DEAD_CODE,        // Remove dead code
            SetList::PRIVATIZATION,    // Privatize properties and methods where possible
            SetList::CODING_STYLE,     // Enforce coding style consistency
            SetList::SECURITY,         // Apply security best practices
            SetList::EARLY_RETURN,     // Use early return to reduce nesting
            SetList::NAMING,           // Improve naming conventions
        ]);
    };
?>