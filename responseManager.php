<?php
    /**
     * Class ApiResponseManager
     *
     * Manages global messages and errors and handles responses to the client.
     *
     * This class is designed to manage global messages and errors and respond to the client
     * with structured JSON responses. It ensures security headers are set for each response 
     * and provides the ability to bail out with an error response when necessary.
     *
     * @example
     * $responseManager = new ApiResponseManager();
     * $responseManager->addGlobalMessage("Operation successful.");
     * $responseManager->respondToClient(true, ["result" => "success"]);
     *
     * @example
     * $responseManager = new ApiResponseManager();
     * $responseManager->addGlobalError("Invalid data provided.");
     * $responseManager->bailOut(422); // Unprocessable Entity
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

        /**
         * Adds a message to the global messages array.
         *
         * @param string $message The message to add.
         * @return void
         */
        public function addGlobalMessage(string $message): void
        {
            $this->globalMessages[] = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
        }

        /**
         * Adds an error to the global errors array.
         *
         * @param string $error The error to add.
         * @return void
         */
        public function addGlobalError(string $error): void
        {
            $this->globalErrors[] = htmlspecialchars($error, ENT_QUOTES, 'UTF-8');
        }

        /**
         * Responds to the client with a JSON-encoded response.
         *
         * @param bool $success Indicates whether the response represents a successful outcome.
         * @param array<string, mixed> $data The data to include in the response.
         * @param string $dataObjectName The key name to use for the data in the response.
         * @param array<string>|null $messages An array of messages to include in the response.
         * @param array<string>|null $errors An array of errors to include in the response.
         * @param int|null $statusCode The HTTP status code for the response.
         * @return never
         */
        public function respondToClient(
            bool $success = true,
            array $data = [],
            string $dataObjectName = 'data',
            ?array $messages = null,
            ?array $errors = null,
            ?int $statusCode = null
        ): never {
            // Merge global messages and errors with those passed in the function (if any)
            $allMessages = array_merge($this->globalMessages, $messages ?? []);
            $allErrors = array_merge($this->globalErrors, $errors ?? []);

            // Set the response code based on status or success/failure
            if ($statusCode !== null) {
                http_response_code($statusCode);
            } elseif ($success) {
                http_response_code(200); // Standard success code
            } else {
                http_response_code(400); // Standard error code
            }

            // Prepare the response object
            $response = [
                'success' => $success,
                $dataObjectName => $data,
                'messages' => $allMessages,
                'errors' => $allErrors
            ];

            // Set security-related headers
            header('Content-Type: application/json');
            header('Access-Control-Allow-Origin: *'); // This should be configured carefully in production
            header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE'); // Allowed HTTP methods
            header('X-Content-Type-Options: nosniff'); // Prevent MIME type sniffing
            header('X-Frame-Options: DENY'); // Prevent clickjacking
            header('X-XSS-Protection: 1; mode=block'); // Prevent reflected XSS attacks
            header('Referrer-Policy: no-referrer'); // Referrer policy for security
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains'); // Enforce HTTPS for a year

            // Encode response as JSON and handle potential JSON encoding errors
            $jsonResponse = json_encode($response, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            
            echo $jsonResponse;
            exit(); // Terminate the script after the response
        }

        /**
         * Bail out and respond to the client with a failure response.
         *
         * This method is useful when you need to stop the execution and respond with an error.
         *
         * @param int|null $statusCode The HTTP status code for the response. Defaults to 400.
         * @return never
         */
        public function bailOut(?int $statusCode = 400): never
        {
            // Check if there are any global messages or errors
            if (empty($this->globalMessages) && empty($this->globalErrors)) {
                // If none are present, provide a default message
                $this->addGlobalMessage("The API Controller received an instruction to bail out but was not provided a reason.");
            }

            // Respond to the client with failure, using the global messages and errors
            $this->respondToClient(
                false, // failure
                [],    // no data
                'data',
                $this->globalMessages, // messages
                $this->globalErrors,   // errors
                $statusCode            // response code
            );
        }
    }

    // Initialize the response manager
    $responseManager = new ApiResponseManager();
?>