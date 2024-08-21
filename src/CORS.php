<?php
    namespace APIManager;

    use APIManager\ApiResponseManager;
    use APIManager\ErrorLogger;
    use Throwable;
    
    /**
     * CORS class to manage Cross-Origin Resource Sharing (CORS) in a secure and RFC-compliant manner.
     * This class provides methods to handle CORS requests and integrates optional logging functionality.
     */
    class CORS
    {
        /**
         * @var ErrorLogger $errorLog Logger instance for error logging.
         */
        private ErrorLogger $errorLogger;  // Correct the type to ErrorLogger
        
        /**
         * @var ApiResponseManager $responseManager Response manager instance for sending HTTP responses.
         */
        private ?ApiResponseManager $apiResponseManager = null;

        /**
         * CORS constructor.
         * Initializes the CORS handler with an error logger instance.
         *
         * @param ErrorLogger $errorLogger The logger instance to use for error logging.
         */
        public function __construct(ErrorLogger $errorLogger)
        {
            $this->errorLogger = $errorLogger;
        }

        /**
         * Sets the response manager instance to use for sending HTTP responses.
         *
         * @param ApiResponseManager $responseManager The response manager instance to use.
         */
        public function setResponseManager(ApiResponseManager $apiResponseManager): void
        {
            $this->apiResponseManager = $apiResponseManager;
        }

        /**
         * Handles Cross-Origin Resource Sharing (CORS) requests in an RFC-compliant manner.
         * Sends the necessary headers to allow cross-origin requests from approved origins.
         * 
         * @param array|null $allowedOrigins An array of allowed origins. If null or empty, no origins are allowed.
         *                                   The origins must be fully qualified domain names (e.g., https://example.com).
         * @param bool $allowCredentials Whether to allow credentials (cookies, authorization headers, etc.).
         * @param array $allowedMethods The allowed HTTP methods for CORS requests (e.g., ['GET', 'POST']).
         * @param array $allowedHeaders The allowed custom headers for CORS requests (e.g., ['Content-Type', 'Authorization']).
         * @param array $exposedHeaders The headers that are safe to expose to the client (e.g., ['X-Custom-Header']).
         * @param int $maxAge The time in seconds that the results of a preflight request can be cached (default: 86400).
         * @throws Exception If an unsupported HTTP method is requested during preflight OPTIONS checks.
         * @throws RuntimeException If headers have already been sent before calling this function.
         */
        public function handleCORS(
            ?array $allowedOrigins = null,
            bool $allowCredentials = false,
            array $allowedMethods = ['GET', 'POST', 'OPTIONS'],
            array $allowedHeaders = ['Content-Type', 'Authorization'],
            array $exposedHeaders = [],
            int $maxAge = 86400
        ): void {
            try {
                // Check if headers have already been sent and if the required headers are present
                if (!$this->checkHeaders()) {
                    return;
                }
    
                // Sanitize and validate the Origin header
                $origin = filter_var($_SERVER['HTTP_ORIGIN'], FILTER_VALIDATE_URL);
                if ($origin === false) {
                    $this->logError("Invalid origin format: " . $_SERVER['HTTP_ORIGIN']);
                    $this->apiResponseManager->addError(['status' => '400', 'title' => 'Bad Request', 'detail' => 'The origin header is invalid']);
                    $this->apiResponseManager->respond(false, [], 400);
                }
    
                // Check if the origin is in the allowed list
                if (in_array($origin, $allowedOrigins ?? [], true)) {
                    header('Access-Control-Allow-Origin: ' . $origin);
                    if ($allowCredentials) {
                        header('Access-Control-Allow-Credentials: true');
                    }
                    
                    if ($exposedHeaders !== []) {
                        header('Access-Control-Expose-Headers: ' . implode(', ', $exposedHeaders));
                    }
    
                    $this->handlePreflightRequest($allowedMethods, $allowedHeaders, $maxAge);
                } else {
                    $this->logError("Disallowed CORS origin: " . $origin);
                    $this->apiResponseManager->addError(['status' => '403', 'title' => 'Forbidden', 'detail' => 'The origin is not allowed to make this request']);
                    $this->apiResponseManager->respond(false, [], 403);
                    return;
                }
            } catch (Throwable $throwable) {
                $this->logCritical($throwable);
                $this->apiResponseManager->addError(['status' => '500', 'title' => 'Internal server error occurred', 'detail' => 'An internal server error occurred']);
                $this->apiResponseManager->respond(false, [], 500);
            }
        }

        /**
         * Checks if headers have already been sent and if the required headers are present.
         *
         * @return bool True if the headers are present and not sent; false otherwise.
         * @throws RuntimeException If headers have already been sent.
         */
        private function checkHeaders(): bool
        {
            // Check if headers have already been sent
            if (headers_sent()) {
                // Log an error and throw an exception if headers have already been sent
                $this->logError("Headers already sent, cannot set CORS headers.");

                // Throw a runtime exception to indicate that headers have already been sent
                throw new RuntimeException("Headers already sent, cannot set CORS headers.");
            }

            // Check if the required headers are present
            if (!isset($_SERVER['HTTP_ORIGIN']) || !isset($_SERVER['REQUEST_METHOD'])) {
                // Log an error and add a global message if the required headers are missing
                $this->apiResponseManager->addMessage('CORS headers were not set as the HTTP_ORIGIN and/or HTTP_REQUEST_METHOD headers were not present with the request');
                return false;
            }

            // Return true if the required headers are present
            return true;
        }

        private function handlePreflightRequest(array $allowedMethods, array $allowedHeaders, int $maxAge): void
        {
            if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                header('Access-Control-Allow-Methods: ' . implode(', ', $allowedMethods));
                header('Access-Control-Allow-Headers: ' . implode(', ', $allowedHeaders));
                header('Access-Control-Max-Age: ' . $maxAge);
                $this->apiResponseManager->sendEmptyResponse(200);
                exit;
            }
        }

        /**
         * Logs an error message using the provided logger or error_log as fallback.
         *
         * @param string $message The error message to log.
         */
        private function logError(string $message): void
        {
            if ($this->errorLogger instanceof errorLog) {
                $this->errorLogger->logError($message);
            } else {
                error_log($message);
            }
        }

        /**
         * Logs a critical error (typically an exception) using the provided logger or error_log as fallback.
         *
         * @param Throwable $throwable The exception to log.
         */
        private function logCritical(Throwable $throwable): void
        {
            if ($this->errorLogger instanceof errorLog) {
                $this->errorLogger->logCritical($throwable);
            } else {
                error_log($throwable->getMessage() . ' in ' . $throwable->getFile() . ' on line ' . $throwable->getLine());
            }
        }
    }
?>