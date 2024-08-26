<?php

    namespace APIManager;

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
     * $responseManager->addMessage("Operation successful.");
     * $responseManager->respond(true, ["type" => "success"]);
     */
    class ApiResponseManager
    {
        public $cors;

        /**
         * Array to store global messages.
         * @var array<string>
         */
        public array $globalMessages = [];

        /**
         * Array to store global errors.
         * @var array<string>
         */
        public array $globalErrors = [];

        /**
         * The CORS handler instance.
         * @var CORS
         */
        private ErrorLogger $errorLogger;

        /**
         * The API manager instance.
         */
        private APIManager $apiManager;

        /**
         * ApiResponseManager constructor.
         * Initializes the response manager with an error logger and API manager instance.
         * 
         * @param ErrorLogger $errorLogger The logger instance to use for error logging.
         * @param APIManager $apiManager The API manager instance to use for API operations.
         */
        public function __construct(ErrorLogger $errorLogger, APIManager $apiManager)
        {
            $this->errorLogger = $errorLogger;
            $this->apiManager = $apiManager;
        }

        /**
         * Sets the CORS handler instance to use for handling CORS requests.
         *
         * @param CORS $cors The CORS handler instance to use.
         */
        public function setCORSHandler(CORS $cors): void
        {
        }

        /**
         * Adds a message to the global messages array.
         *
         * @param string|array $message The message to add. It can be either a string or an array.
         * 
         * @example $responseManager->addMessage("Operation successful.");
         */
        public function addMessage(string|array $message): void
        {
            // Check if the message is an array
            if (is_array($message)) {
                // Sanitize each element in the array using the API manager
                $sanitizedMessages = array_map([$this->apiManager, 'sanitizeInput'], $message);

                // Merge the sanitized messages with the global messages array
                $this->globalMessages = array_merge($this->globalMessages, $sanitizedMessages);
            } else {
                // Sanitize a single string message
                $sanitizedMessage = $this->apiManager->sanitizeInput($message);

                // Add the sanitized message to the global messages array
                $this->globalMessages[] = $sanitizedMessage;
            }
        }

        /**
         * Adds an error to the global errors array.
         *
         * @param array $error The error to add, consistent with JSON:API specification.
         * 
         * @example $responseManager->addError(['status' => '400', 'title' => 'Bad Request', 'detail' => 'Invalid input.']);
         * @example $responseManager->addError(['status' => '500', 'title' => 'Internal Server Error', 'detail' => 'An unexpected error occurred.']);
         */
        public function addError(array $error): void
        {
            // Sanitize required fields in the error object
            $sanitizedError = [
                'status' => isset($error['status']) ? $this->apiManager->sanitizeInput($error['status']) : null,
                'code' => isset($error['code']) ? $this->apiManager->sanitizeInput($error['code']) : null,
                'title' => isset($error['title']) ? $this->apiManager->sanitizeInput($error['title']) : null,
                'detail' => isset($error['detail']) ? $this->apiManager->sanitizeInput($error['detail']) : null,
                'source' => $error['source'] ?? null,
                'meta' => $error['meta'] ?? null,
            ];

            // Sanitize any links if present
            if (isset($error['links']) && is_array($error['links'])) {
                $sanitizedError['links'] = array_map([Sanitize::class, 'sanitizeString'], $error['links']);
            }

            // Add the sanitized error to the global errors array
            $this->globalErrors[] = array_filter($sanitizedError, fn($value): bool => !is_null($value));
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
         * Responds to the client with an empty response (no content).
         *
         * @param int $statusCode The HTTP status code for the response. Defaults to 204 (No Content).
         * 
         * @example $responseManager->sendEmptyResponse(204);
         */
        public function sendEmptyResponse(int $statusCode = 204): never
        {
            // Set the content type
            header('Content-Type: application/vnd.api+json');

            // Set the response code
            http_response_code($statusCode);

            // Set security-related headers
            $this->setSecurityHeaders();

            // Log the response
            $this->errorLogger->logInfo('API Response');

            // Exit
            exit();
        }

        /**
         * Responds to the client with a JSON-encoded response following JSON:API spec.
         *
         * @param bool $success Indicates whether the response represents a successful outcome.
         * @param array<string, mixed> $data The data to include in the response, compliant with JSON:API.
         * @param int|null $statusCode The HTTP status code for the response.
         * @param array<string>|null $messages An optional array of messages to include in the response.
         * @param array<string>|null $errors An optional array of errors to include in the response.
         */
        public function respond(
            bool $success = true,
            array $data = [],
            ?int $statusCode = null,
            ?array $messages = null,
            ?array $errors = null
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
            // Ensure that globalMessages and globalErrors are initialized as arrays
            $this->globalMessages = $this->globalMessages ?? [];
            $this->globalErrors = $this->globalErrors ?? [];

            // Check if both arrays are empty
            if ($this->globalMessages === [] && $this->globalErrors === []) {
                // If none are present, provide a default message
                $this->addMessage("The API Controller received an instruction to bail out but was not provided a reason.");
            }

            // Respond to the client with failure, using the global messages and errors
            $this->respond(
                false, // failure
                [],    // no data
                $statusCode // response code
            );
        }
        
        /**
         * Checks if the response can continue based on the global errors array.
         *
         * @return bool Whether the response can continue.
         */
        public function canContinue(): bool
        {
            return empty($this->globalErrors);
        }

        /**
         * Handles continuance based on the presence of errors.
         * 
         * If there are errors present, the script will bail out with the provided status code.
         * 
         * @param int|null $statusCode The HTTP status code to use when bailing out. Defaults to 400.
         */
        public function handleContinuance(?int $statusCode = 400): void
        {
            // Check if the response can continue (based on whether or not there are errors present)
            if (!$this->canContinue()) {
                // If there are errors, bail out with the provided status code
                $this->bailOut($statusCode);
            }
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
                    $sanitizedData[$key] = $this->apiManager->sanitizeInput($value);
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
    // $responseManager->addMessage("This is a test message.");
    // $responseManager->respond(true, ["type" => "test"]);
?>