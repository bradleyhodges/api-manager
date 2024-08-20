<?php
    /**
     * Sanitizes, trims, and optionally truncates a string. 
     * Returns null if the input is empty after sanitization.
     *
     * @param string|null $data The data to sanitize and process. Can be null.
     * @param int|null $maxLength Optional maximum length for truncation. Must be a positive integer if provided.
     * 
     * @return string|null Returns the sanitized and processed string, or null if the string is empty after sanitization.
     * 
     * @throws InvalidArgumentException if $maxLength is not null and not a positive integer.
     * @throws RuntimeException if the mbstring extension is required but not available.
     * @throws InvalidArgumentException if the input data is not valid UTF-8 or exceeds the allowed maximum length.
     */
    function sanitize(?string $data, ?int $maxLength = null): ?string
    {
        // Validate maxLength if provided
        if ($maxLength !== null && (!is_int($maxLength) || $maxLength <= 0)) {
            throw new InvalidArgumentException('maxLength must be a positive integer if provided.');
        }

        // Check if mbstring extension is available if multi-byte safe truncation is needed
        if ($maxLength !== null && !function_exists('mb_substr')) {
            throw new RuntimeException('The mbstring extension is required for safe truncation but is not enabled.');
        }

        // Sanitize and trim the input data
        $data = trim($data ?? ''); // Null coalescing operator to ensure $data is a string

        // Return null if the sanitized string is empty
        if ($data === '') {
            return null;
        }

        // Validate that the string is valid UTF-8
        if (!mb_check_encoding($data, 'UTF-8')) {
            throw new InvalidArgumentException('Invalid UTF-8 encoding detected.');
        }

        // Set a maximum allowed length to prevent excessively large inputs
        $maxAllowedLength = 10000; // Define a reasonable maximum input length
        if (strlen($data) > $maxAllowedLength) {
            throw new InvalidArgumentException(sprintf('Input data exceeds the maximum allowed length of %d characters.', $maxAllowedLength));
        }

        // If maxLength is specified, truncate the string safely using mb_substr
        if ($maxLength !== null) {
            return mb_substr($data, 0, $maxLength);
        }

        return $data;
    }

    // Ensure the mbstring extension is loaded for string truncation
    if (!extension_loaded('mbstring')) {
        throw new RuntimeException('The mbstring extension is required but not enabled.');
    }
?>