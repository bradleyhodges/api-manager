<?php
    namespace APIManager;

    use APIManager\responseManager;
    use APIManager\errorLog;
    use Throwable;
    
    /**
     * CORS class to manage Cross-Origin Resource Sharing (CORS) in a secure and RFC-compliant manner.
     * This class provides methods to handle CORS requests and integrates optional logging functionality.
     */
    class CORS
    {
        private ?errorLog $errorLog;
        
        private responseManager $responseManager;    

        /**
         * CORS constructor.
         * Initializes the class with a logger and a response manager.
         *
         * @param responseManager $responseManager An instance of the response manager.
         * @param errorLog $errorLog The logger instance.
         */
        public function __construct(responseManager $responseManager, ?errorLog $errorLog)
        {
            $this->responseManager = $responseManager;
            $this->errorLog = $errorLog;
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
                $this->checkHeaders();
    
                // Sanitize and validate the Origin header
                $origin = filter_var($_SERVER['HTTP_ORIGIN'], FILTER_VALIDATE_URL);
                if ($origin === false) {
                    $this->logError("Invalid origin format: " . $_SERVER['HTTP_ORIGIN']);
                    $this->responseManager->respondWithError(400, "Bad Request: Invalid origin format.");
                    return;
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
                    $this->responseManager->respondWithError(403, "Forbidden: Origin not allowed.");
                    return;
                }
            } catch (Throwable $throwable) {
                $this->logCritical($throwable);
                $this->responseManager->respondWithError(500, "Internal server error occurred.");
            }
        }

        
    private function checkHeaders(): void
        {
            if (headers_sent()) {
                $this->logError("Headers already sent, cannot set CORS headers.");
                throw new RuntimeException("Headers already sent, cannot set CORS headers.");
            }

            if (!isset($_SERVER['HTTP_ORIGIN']) || !isset($_SERVER['REQUEST_METHOD'])) {
                $this->logError("Missing HTTP_ORIGIN or REQUEST_METHOD in the request.");
                $this->responseManager->respondWithError(400, "Bad Request: Missing required headers.");
                exit;
            }
        }

        private function handlePreflightRequest(array $allowedMethods, array $allowedHeaders, int $maxAge): void
        {
            if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
                header('Access-Control-Allow-Methods: ' . implode(', ', $allowedMethods));
                header('Access-Control-Allow-Headers: ' . implode(', ', $allowedHeaders));
                header('Access-Control-Max-Age: ' . $maxAge);
                $this->responseManager->respondWithNoContent();
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
            if ($this->errorLog instanceof errorLog) {
                $this->errorLog->logError($message);
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
            if ($this->errorLog instanceof errorLog) {
                $this->errorLog->logCritical($throwable);
            } else {
                error_log($throwable->getMessage() . ' in ' . $throwable->getFile() . ' on line ' . $throwable->getLine());
            }
        }
    }
?>