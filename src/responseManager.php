<?php

    namespace APIManager\Classes;

    use Throwable;
    use JsonException;

    /**
     * Class ApiResponseManager
     *
     * Manages global messages, errors, CORS, and handles API responses following JSON:API specification.
     * Provides features for logging, security, validation, and robust error handling.
     *
     * @example
     * $responseManager = new ApiResponseManager($corsHandler, $errorErrorLogger);
     * $responseManager->addGlobalMessage("Operation successful.");
     * $responseManager->respondToClient(true, ["type" => "success"]);
     */
    class ApiResponseManager
    {
        /**
         * Array to store global messages.
         * @var array<string>
         */
        private array $globalMessages = [];

        /**
         * Array to store global errors.
         * @var array<string>
         */
        private array $globalErrors = [];

        private ErrorLogger $errorLogger;

        private CORS $cors;

        /**
         * Constructor to initialize the logger and CORS handler.
         *
         * @param CORS $cors The CORS handler instance.
         * @param ErrorLogger $errorLogger The logger instance.
         */
        public function __construct(CORS $cors, ErrorLogger $errorLogger)
        {
            $this->cors = $cors;
            $this->errorLogger = $errorLogger;
        }

        /**
         * Adds a message to the global messages array.
         *
         * @param string $message The message to add.
         */
        public function addGlobalMessage(string $message): void
        {
            // Sanitize input before storing
            $sanitizedMessage = Sanitize::sanitizeString($message);
            $this->globalMessages[] = $sanitizedMessage;
        }

        /**
         * Adds an error to the global errors array.
         *
         * @param string $error The error to add.
         */
        public function addGlobalError(string $error): void
        {
            // Sanitize input before storing
            $sanitizedError = Sanitize::sanitizeString($error);
            $this->globalErrors[] = $sanitizedError;
        }

        /**
         * Handles CORS for the current request using the configured CORS handler.
         * This method should be called at the start of any request handling.
         *
         * @param array|null $allowedOrigins Allowed origins for CORS.
         * @param bool $allowCredentials Whether to allow credentials in CORS requests.
         * @param array $allowedMethods Allowed HTTP methods.
         * @param array $allowedHeaders Allowed headers in CORS requests.
         * @param array $exposedHeaders Exposed headers in CORS responses.
         * @param int $maxAge Max age for preflight cache.
         */
        public function handleCORS(
            ?array $allowedOrigins = null,
            bool $allowCredentials = false,
            array $allowedMethods = ['GET', 'POST', 'OPTIONS'],
            array $allowedHeaders = ['Content-Type', 'Authorization'],
            array $exposedHeaders = [],
            int $maxAge = 86400
        ): void {
            $this->cors->handleCORS($allowedOrigins, $allowCredentials, $allowedMethods, $allowedHeaders, $exposedHeaders, $maxAge);
        }

        /**
         * Responds to the client with a JSON-encoded response following JSON:API spec.
         *
         * @param bool $success Indicates whether the response represents a successful outcome.
         * @param array<string, mixed> $data The data to include in the response, compliant with JSON:API.
         * @param array<string>|null $messages An array of messages to include in the response.
         * @param array<string>|null $errors An array of errors to include in the response.
         * @param int|null $statusCode The HTTP status code for the response.
         */
        public function respondToClient(
            bool $success = true,
            array $data = [],
            ?array $messages = null,
            ?array $errors = null,
            ?int $statusCode = null
        ): never {
            // Validate and sanitize data
            $validatedData = $this->validateAndSanitizeData($data);

            // Merge global messages and errors with those passed in the function (if any)
            $allMessages = array_merge($this->globalMessages, $messages ?? []);
            $allErrors = array_merge($this->globalErrors, $errors ?? []);

            // Set the response code based on status or success/failure
            $statusCode = $statusCode ?? ($success ? 200 : 400);
            http_response_code($statusCode);

            // Prepare the JSON:API compliant response object
            $response = [
                'data' => $validatedData,
                'meta' => [
                    'success' => $success,
                    'messages' => $allMessages,
                ],
                'errors' => $allErrors,
            ];

            // Log the response
            $this->errorLogger->logInfo('API Response');

            // Set security-related headers
            $this->setSecurityHeaders();

            // Set the content type
            header('Content-Type: application/vnd.api+json');
            
            // Encode response as JSON and handle potential JSON encoding errors
            try {
                $jsonResponse = json_encode($response, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
                echo $jsonResponse;
            } catch (JsonException $jsonException) {
                $this->errorLogger->logError('JSON encoding failed', ['error' => $jsonException->getMessage()]);
                $this->respondWithError(500, 'Internal Server Error');
            }

            exit(); // Terminate the script after the response
        }

        /**
         * Bail out and respond to the client with a failure response.
         *
         * This method is useful when you need to stop the execution and respond with an error.
         *
         * @param int|null $statusCode The HTTP status code for the response. Defaults to 400.
         */
        public function bailOut(?int $statusCode = 400): never
        {
            // Log the bailout
            $this->errorLogger->warning('Bailing out', [
                'status' => $statusCode,
                'messages' => $this->globalMessages,
                'errors' => $this->globalErrors,
            ]);

            // Ensure that globalMessages and globalErrors are initialized as arrays
            $this->globalMessages = $this->globalMessages ?? [];
            $this->globalErrors = $this->globalErrors ?? [];

            // Check if both arrays are empty
            if ($this->globalMessages === [] && $this->globalErrors === []) {
                // If none are present, provide a default message
                $this->addGlobalMessage("The API Controller received an instruction to bail out but was not provided a reason.");
            }

            // Respond to the client with failure, using the global messages and errors
            $this->respondToClient(
                false, // failure
                [],    // no data
                $this->globalMessages, // messages
                $this->globalErrors,   // errors
                $statusCode            // response code
            );
        }

        /**
         * Validates and sanitizes the input data array.
         *
         * @param array<string, mixed> $data The data to validate and sanitize.
         * @return array<string, mixed> The sanitized and validated data.
         */
        protected function validateAndSanitizeData(array $data): array
        {
            // Iterate through the data array and sanitize/validate each value
            $sanitizedData = [];
            foreach ($data as $key => $value) {
                // Example validation and sanitization logic, can be extended
                if (is_string($value)) {
                    $sanitizedData[$key] = Sanitize::sanitizeString($value);
                } elseif (is_array($value)) {
                    $sanitizedData[$key] = $this->validateAndSanitizeData($value); // Recursively sanitize arrays
                } else {
                    $sanitizedData[$key] = $value; // Other data types can be handled here
                }
            }
            
            return $sanitizedData;
        }

        /**
         * Sets security headers for the response.
         */
        private function setSecurityHeaders(): void
        {
            header('Content-Type: application/vnd.api+json');
            header('X-Content-Type-Options: nosniff'); // Prevent MIME type sniffing
            header('X-Frame-Options: DENY'); // Prevent clickjacking
            header('X-XSS-Protection: 1; mode=block'); // Prevent reflected XSS attacks
            header('Referrer-Policy: no-referrer'); // Referrer policy for security
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains'); // Enforce HTTPS for a year

            // Content-Security-Policy (CSP) can be customized for more security
            header("Content-Security-Policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';");
        }

        /**
         * Responds with a standard JSON:API error object.
         *
         * @param int $statusCode The HTTP status code for the error.
         * @param string $detail The detail message for the error.
         */
        private function respondWithError(int $statusCode, string $detail): never
        {
            http_response_code($statusCode);
            $errorResponse = [
                'errors' => [
                    [
                        'status' => (string)$statusCode,
                        'detail' => $detail,
                    ]
                ],
            ];

            try {
                echo json_encode($errorResponse, JSON_THROW_ON_ERROR);
            } catch (JsonException $jsonException) {
                error_log('Failed to encode error response: ' . $jsonException->getMessage());
                echo '{"errors":[{"detail":"An internal server error occurred."}]}';
            }

            exit(); // Terminate the script after the error response
        }
    }

    // // Example usage with CORS handler and validation
    // $corsHandler = new CORSHandler();
    // $responseManager = new ApiResponseManager($corsHandler);
    // $responseManager->handleCORS(['https://example.com'], true);
    // $responseManager->addGlobalMessage("This is a test message.");
    // $responseManager->respondToClient(true, ["type" => "test"]);
?>