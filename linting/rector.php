<?php
    declare(strict_types=1);

    use Rector\Config\RectorConfig;
    use Rector\Set\ValueObject\SetList;

    return static function (RectorConfig $rectorConfig): void {
        // Specify the paths to the directories containing the code to be linted
        $rectorConfig->paths([
            __DIR__ . '/../',
        ]);

        // Skip all 'linting' and 'vendor' directories in all paths
        $rectorConfig->skip([
            '**/vendor/*',
            '**/linting/*',
        ]);
        
        // Import the names of the classes and functions to be used in the rules
        $rectorConfig->importNames();

        // Enable parallel processing of the code to be linted
        $rectorConfig->parallel();

        // Apply a comprehensive set of rules for high-quality, type-safe, and secure code
        $rectorConfig->sets([
            SetList::CODE_QUALITY,       // Improve code quality
            SetList::PHP_83,             // Upgrade to PHP 8.0 syntax
            SetList::TYPE_DECLARATION,   // Enforce type declarations
            SetList::DEAD_CODE,          // Remove dead code
            SetList::PRIVATIZATION,      // Privatize properties and methods
            SetList::CODING_STYLE,       // Enforce coding style consistency
            SetList::EARLY_RETURN,       // Use early return to reduce nesting
            SetList::NAMING,             // Improve naming conventions
            SetList::STRICT_BOOLEANS,    // Enforce strict boolean comparisons
            SetList::CARBON,             // Replace datetime with carbon
        ]);
    };
?>