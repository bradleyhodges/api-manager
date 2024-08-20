<?php
    use Carbon\Carbon;

    /**
     * CORSHandler class to manage Cross-Origin Resource Sharing (CORS) in a secure and RFC-compliant manner.
     * This class provides methods to handle CORS requests and integrates optional logging functionality.
     */
    class CORSHandler
    {
        private ?ErrorLogger $errorLogger;

        /**
         * CORSHandler constructor.
         * Initializes the class with an optional logger.
         *
         * @param ErrorLogger|null $errorLogger An optional logger instance. If null, default to error_log.
         */
        public function __construct(?ErrorLogger $errorLogger = null)
        {
            $this->errorLogger = $errorLogger;
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
                $scriptName = basename(__FILE__);  // Retrieve the name of the current script
                $timestamp = Carbon::now()->format('Y-m-d H:i:s');  // Get the current timestamp

                // Ensure that headers have not been sent already
                if (headers_sent()) {
                    $this->logError("Headers already sent, cannot set CORS headers.");
                    throw new RuntimeException("Headers already sent, cannot set CORS headers.");
                }

                // If allowedOrigins is not provided or is empty, default to an empty array (no allowed origins).
                $allowedOrigins = $allowedOrigins ?? [];

                // Ensure the $_SERVER superglobal contains the required keys
                if (!isset($_SERVER['HTTP_ORIGIN']) || !isset($_SERVER['REQUEST_METHOD'])) {
                    $this->logError("Missing HTTP_ORIGIN or REQUEST_METHOD in the request.");
                    http_response_code(400);  // Bad Request
                    exit('Bad Request: Missing required headers.');
                }

                // Sanitize the Origin header
                $origin = filter_var($_SERVER['HTTP_ORIGIN'], FILTER_SANITIZE_URL);

                // Check if the origin is in the allowed list
                if (in_array($origin, $allowedOrigins, true)) {
                    // Allow requests from this origin
                    header('Access-Control-Allow-Origin: ' . $origin);

                    if ($allowCredentials) {
                        header('Access-Control-Allow-Credentials: true');
                    }

                    // Set headers for exposed headers
                    if ($exposedHeaders !== []) {
                        header('Access-Control-Expose-Headers: ' . implode(', ', $exposedHeaders));
                    }

                    // Handle preflight requests (OPTIONS method)
                    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                        // Respond with allowed methods
                        header('Access-Control-Allow-Methods: ' . implode(', ', $allowedMethods));

                        // Respond with allowed headers
                        header('Access-Control-Allow-Headers: ' . implode(', ', $allowedHeaders));

                        // Set max age for caching the preflight response
                        header('Access-Control-Max-Age: ' . $maxAge);

                        // Preflight response does not have content
                        http_response_code(204);
                        exit(0);
                    }
                } else {
                    $this->logError("Disallowed CORS origin: " . $origin);

                    // If the origin is not allowed, send a 403 Forbidden response
                    http_response_code(403);
                    exit('Origin not allowed');
                }
            } catch (Exception $exception) {
                $this->logCritical($exception);
                http_response_code(500);  // Internal Server Error
                exit('An internal server error occurred.');
            }
        }

        /**
         * Logs an error message using the provided logger or error_log as fallback.
         *
         * @param string $message The error message to log.
         */
        private function logError(string $message): void
        {
            if ($this->errorLogger) {
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
            if ($this->errorLogger) {
                $this->errorLogger->logCritical($throwable);
            } else {
                error_log($throwable->getMessage() . ' in ' . $throwable->getFile() . ' on line ' . $throwable->getLine());
            }
        }
    }

    /**
     * Example usage:
     * 
     * // Create a CORSHandler instance with default logging to error_log
     * $corsHandler = new CORSHandler();
     * $corsHandler->handleCORS(
     *     ['https://example.com', 'https://another-allowed-origin.com'],
     *     true,  // Allow credentials
     *     ['GET', 'POST', 'OPTIONS'],  // Allowed methods
     *     ['Content-Type', 'Authorization'],  // Allowed headers
     *     ['X-Custom-Header'],  // Exposed headers
     *     3600  // Max age for preflight cache
     * );
     * 
     * // Create a CORSHandler instance with a custom logger
     * $customLogger = new ErrorLogger();
     * $corsHandlerWithLogger = new CORSHandler($customLogger);
     * $corsHandlerWithLogger->handleCORS(['https://example.com', 'https://another-allowed-origin.com']);
     * 
     * // No origins allowed (default behavior) and default to error_log
     * $corsHandler->handleCORS();
     */
?>
