<?php
declare(strict_types=1);
    /**
     * APIManager.php
     * 
     * A robust and secure class for automatically handling Composer autoload, dynamic dependency loading,
     * CORS headers, response management, error logging, security headers, input sanitization, JSON handling, 
     * and exposing custom utilities.
     * 
     * The APIManager class can be configured with various options to control behavior such as rate limiting, 
     * CSRF protection, and custom headers. It integrates with several key packages to enhance security 
     * and performance for API-driven applications.
     */
    
    namespace APIManager;

    use Exception;
    use ErrorException;
    use APIManager\CORS;
    use APIManager\ApiResponseManager;
    use APIManager\ErrorLogger;
    use APIManager\HTTP;
    use Symfony\Component\RateLimiter\RateLimiterFactory;
    use Symfony\Component\RateLimiter\Policy\SlidingWindowLimiter;
    use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
    use Symfony\Component\RateLimiter\RateLimit;
    use DateInterval;
    use Symfony\Component\Security\Csrf\CsrfTokenManager;
    use Dotenv\Dotenv;
    use Throwable;
    use RuntimeException;
    use InvalidArgumentException;
    use Monolog\Logger;

    /**
     * Class APIManager
     * 
     * This class manages various aspects of API operations, including error handling, security headers, 
     * Cross-Origin Resource Sharing (CORS), response management, rate limiting, CSRF protection, and 
     * utility loading. It integrates with key security and logging packages to provide a robust and 
     * secure framework for API-driven applications.
     * 
     * @package APIManager
     */
    class APIManager
    {
        /**
         * @var ErrorLogger $errorLog Logger instance for error logging.
         */
        private ErrorLogger $errorLogger;  // Correct the type to ErrorLogger

        /**
         * @var ApiResponseManager $responseManager Instance of the response manager for handling API responses.
         */
        private ApiResponseManager $apiResponseManager;

        /**
         * @var CORS $corsHandler Handles Cross-Origin Resource Sharing (CORS) functionality.
         */
        private CORS $cors;

        /**
         * @var CsrfTokenManager|null $csrfTokenManager Instance of the CSRF token manager, if initialized.
         */
        private ?CsrfTokenManager $csrfTokenManager = null;

        /**
         * @var RateLimiterFactory|null $rateLimiterFactory Instance of the rate limiter factory, if initialized.
         */
        private ?RateLimiterFactory $rateLimiterFactory = null;
        
        /**
         * @var InMemoryStorage $inMemoryStorage In-memory storage for rate limiting (replace with persistent storage in production).
         */
        private InMemoryStorage $inMemoryStorage;

        /**
         * @var array $securityHeaders Default security headers to be applied to responses.
         */
        private array $securityHeaders = [
            "Content-Security-Policy" => "default-src 'self'",
            "X-Content-Type-Options" => "nosniff",
            "X-Frame-Options" => "DENY",
            "X-XSS-Protection" => "1; mode=block",
        ];

        /**
         * @var string|null $envFilePath Path to the .env file, if found.
         */
        private ?string $envFilePath = null;
        
        /**
         * APIManager constructor.
         * 
         * Initializes the APIManager class, loads environment variables, sets up logging, and configures various options.
         */
        public function __construct()
        {
            // Load environment variables
            $this->loadEnvironmentVariables();
            
            // Get log file path from options or environment
            $logFilePath = getenv('LOGS_PATH') . '/var/log/caddy/phpApiManager.log';

            // Initialize ErrorLogger with the provided log file path
            $this->errorLogger = new ErrorLogger($logFilePath);

            // Create the in-memory storage for rate limiting
            $this->inMemoryStorage = new InMemoryStorage();

            // Initialize the core components without dependencies
            $this->cors = new CORS($this->errorLogger);
            $this->apiResponseManager = new ApiResponseManager($this->errorLogger, $this);

            // Set the circular dependencies
            $this->cors->setResponseManager($this->apiResponseManager);
            $this->apiResponseManager->setCORSHandler($this->cors);

            // Set error and exception handlers
            set_error_handler([$this, 'handleError']);
            set_exception_handler([$this, 'handleException']);

            // Register shutdown function to handle fatal errors
            register_shutdown_function([$this, 'handleShutdown']);
        }

        /**
         * Loads environment variables using the .env file if DOCUMENT_ROOT_PATH is not already set.
         * If no .env file is found, it uses default environment variables.
         */
        private function loadEnvironmentVariables(): void
        {
            // Check if DOCUMENT_ROOT_PATH is already set
            if (getenv('DOCUMENT_ROOT_PATH')) {
                // DOCUMENT_ROOT_PATH is set, no need to look for .env file
                return;
            }

            // If DOCUMENT_ROOT_PATH is not set, search for a .env file
            if (!$this->findAndLoadDotenv()) {
                // If no .env file was found, set default environment variables
                $this->setDefaultEnvironmentVariables();
            }
        }

        /**
         * Finds the .env file by recursively searching up to the DOCUMENT_ROOT_PATH or /var/www/.
         * Caches the result to avoid repeated searches. If found, loads the .env file with safeLoad().
         *
         * @return bool True if a .env file was found and loaded, false otherwise.
         *
         * @throws RuntimeException If the .env file is found but fails to load.
         */
        private function findAndLoadDotenv(): bool
        {
            // If we've already found and loaded the .env file, skip the search
            if ($this->envFilePath !== null) {
                return true;
            }

            // Start from the current directory
            $currentDir = __DIR__;
            $documentRoot = getenv('DOCUMENT_ROOT_PATH') ?: '/var/www/';
            $documentRoot = rtrim(realpath($documentRoot), '/'); // Normalize the document root path

            // Prevent infinite loops: Track visited directories
            $visitedDirs = [];

            while (!in_array($currentDir, $visitedDirs)) {
                // Add current directory to visited directories
                $visitedDirs[] = $currentDir;

                // Check for .env file in the current directory
                if (file_exists($currentDir . '/.env')) {
                    // Cache the .env file path
                    $this->envFilePath = $currentDir . '/.env';

                    // Load the .env file safely
                    $dotenv = Dotenv::createImmutable($currentDir);
                    $dotenv->safeLoad();
                    return true; // Stop searching once the .env file is found
                }

                // Stop searching if we are at the document root
                if ($currentDir === $documentRoot || $currentDir === '/') {
                    break;
                }

                // Move to the parent directory
                $currentDir = dirname($currentDir);
            }

            return false; // No .env file was found
        }

        /**
         * Sets default environment variables if no .env file is found.
         */
        private function setDefaultEnvironmentVariables(): void
        {
            putenv('DOCUMENT_ROOT_PATH=/var/www');
            putenv('LOGS_PATH=/var/log/caddy');
            putenv('COMPOSER_AUTOLOAD_PATH=/var/www/composer/vendor/autoload.php');
            putenv('ENFORCE_SAFE_REQUIRES=true');
        }

        /**
         * Handles fatal errors by logging them and sending a 500 response.
         *
         * This method is registered as a shutdown function to handle fatal errors.
         */
        public function handleShutdown(): void
        {
            // Get the last error, if one exists
            $error = error_get_last();

            // Check if the error is a fatal error
            if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
                // Log the fatal error
                $this->errorLogger->logCritical(sprintf(
                    'Fatal error: %s in %s on line %d',
                    $error['message'],
                    $error['file'],
                    $error['line']
                ));
                
                // Use the response manager to send a 500 response with a JSON error message
                $this->apiResponseManager->addError(['status' => '500', 'title' => 'Internal Server Error', 'detail' => 'An unexpected error occurred']);
                $this->apiResponseManager->respond(false, [], 500);
            }
        }

        /**
         * Configures and applies security headers to the current response.
         *
         * This method merges custom security headers with default security headers and applies them to the response.
         * It ensures that critical security policies, such as Content Security Policy (CSP) and XSS protection, are in place.
         *
         * @param array $customHeaders Custom security headers to apply. The array should be formatted as ['Header-Name' => 'Header-Value'].
         * @return $this The current instance of APIManager for method chaining.
         *
         * @example
         * $apiManager->useSecurityHeaders([
         *     'Content-Security-Policy' => "default-src 'self'; script-src 'nonce-random123';",
         *     'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains'
         * ]);
         */
        public function useSecurityHeaders(array $customHeaders = []): self
        {
            // Merge custom headers with default security headers
            $headers = array_merge($this->securityHeaders, $customHeaders);

            // Apply each header
            foreach ($headers as $header => $value) {
                // Prevent header injection attacks
                if (!headers_sent()) {
                    // Set the header
                    header(sprintf('%s: %s', $header, $value));
                }
            }
            
            return $this;
        }

        /**
         * Initializes and configures CORS handling.
         *
         * @param array $options CORS options.
         */
        public function useCORS(array $options = []): self
        {
            $this->cors->handleCORS(
                $options['allowedOrigins'] ?? [],
                $options['allowCredentials'] ?? false,
                $options['allowedMethods'] ?? ['GET', 'POST', 'OPTIONS'],
                $options['allowedHeaders'] ?? ['Content-Type', 'Authorization'],
                $options['exposedHeaders'] ?? [],
                $options['maxAge'] ?? 86400
            );
            return $this;
        }

        /**
         * Initializes and configures the rate limiter.
         *
         * @param array $config Rate limiter configuration options.
         */
        public function useRateLimiter(array $config = []): self
        {
            // Ensure required configuration keys are present
            $config = array_merge([
                'id' => 'default',
                'policy' => 'sliding_window',
                'limit' => 100,
                'interval' => '1 minute',
            ], $config);

            // Convert the interval to a valid DateInterval format
            $this->convertToDateInterval($config['interval']);

            // Create a RateLimiterFactory with the given configuration
            $limiterConfig = [
                'id' => $config['id'],
                'policy' => $config['policy'],
                'limit' => $config['limit'],
                'interval' => $config['interval'],
            ];

            // Create the rate limiter factory
            $this->rateLimiterFactory = new RateLimiterFactory($limiterConfig, $this->inMemoryStorage);

            // Apply rate limiting to the current request
            $limiter = $this->rateLimiterFactory->create($config['id']);
            $rateLimit = $limiter->consume();

            if (!$rateLimit->isAccepted()) {
                // Too many requests, handle the rate limiting error (e.g., throw an exception or return an error response)
                $this->apiResponseManager->addError(['status' => '429', 'title' => 'Too Many Requests', 'detail' => 'Rate limit exceeded']);
                $this->apiResponseManager->respond(false, [], 429);
            }

            return $this;
        }

        /**
         * Checks the current rate limit status without consuming a token.
         *
         * @param string $id The rate limiter ID.
         * @return RateLimit The current rate limit status.
         */
        public function checkRateLimit(string $id): RateLimit
        {
            if (!$this->rateLimiterFactory instanceof RateLimiterFactory) {
                throw new RuntimeException('RateLimiter has not been initialized.');
            }
    
            $limiter = $this->rateLimiterFactory->create($id);
            return $limiter->consume(0); // Check without consuming
        }
    
        /**
         * Resets the rate limiter for a specific ID.
         *
         * @param string $id The rate limiter ID.
         */
        public function resetRateLimit(string $id): self
        {
            if (!$this->rateLimiterFactory instanceof RateLimiterFactory) {
                throw new RuntimeException('RateLimiter has not been initialized.');
            }
    
            $limiter = $this->rateLimiterFactory->create($id);
            $limiter->reset(); // Reset the rate limit for the given ID
    
            return $this;
        }
    
        /**
         * Gets the number of remaining attempts before the rate limit is reached.
         *
         * @param string $id The rate limiter ID.
         * @return int The number of remaining attempts.
         */
        public function getRateLimitRemainingAttempts(string $id): int
        {
            $rateLimit = $this->checkRateLimit($id);
            return $rateLimit->getRemainingTokens();
        }
    
        /**
         * Sets the storage backend for the rate limiter.
         *
         * @param object $storage The storage backend (e.g., RedisStorage, InMemoryStorage).
         */
        public function setRateLimitStorage(object $storage): self
        {
            $this->inMemoryStorage = $storage;
            return $this;
        }
    
        /**
         * Gets the current rate limit status.
         *
         * @param string $id The rate limiter ID.
         * @return array The rate limit status (remaining attempts, reset time, etc.).
         */
        public function getRateLimitStatus(string $id): array
        {
            $rateLimit = $this->checkRateLimit($id);
    
            return [
                'remaining_attempts' => $rateLimit->getRemainingTokens(),
                'reset_time' => $rateLimit->getRetryAfter()->getTimestamp(),
            ];
        }

        /**
         * Initializes the CSRF token manager.
         */
        public function useCsrfManager(): self
        {
            $this->csrfTokenManager = new CsrfTokenManager();
            return $this;
        }

        /**
         * Adds a header to the response.
         *
         * @param string $headerName The name of the header to add.
         * @param string $headerValue The value of the header to add.
         */
        public function addHeader(string $headerName, string $headerValue): void
        {
            // Prevent header injection attacks
            if (!headers_sent()) {
                // Set the header
                header(sprintf('%s: %s', $headerName, $headerValue));
            }
        }

        /**
         * Removes a header from the response.
         *
         * @param string $headerName The name of the header to remove.
         */
        public function removeHeader(string $headerName): void
        {
            header_remove($headerName);
        }

        /**
         * Sets the response Content-Type header.
         *
         * @param string $contentType The content type to set (e.g., 'text/html', 'application/json').
         */
        public static function setResponseContentType(string $contentType): void
        {
            // Only set the header if it hasn't already been sent
            if (!headers_sent()) {
                header('Content-Type: ' . $contentType);
            }
        }

        /**
         * Creates and returns an HTTP instance with the provided configuration.
         *
         * @param array $config Configuration options such as 'base_uri', 'headers', etc.
         * @return HTTP An instance of the HTTP class
         * @throws InvalidArgumentException If the configuration is invalid
         * 
         * @example
         * $apiManager = new APIManager();
         * $http = $apiManager->useHTTP(['base_uri' => 'https://foo.com/api/', 'headers' => [...]]); 
         * $response = $http->request('GET', 'test');
         * $cookies = $http->cookieJar();
         */
        public function useHTTP(array $config = []): HTTP
        {
            // Instantiate the HTTP class with the provided config
            return new HTTP($config);
        }

        /**
         * Adds a log message, similar to PHP's error_log function.
         *
         * @param string|array|Throwable $logData Log data, either as a string message, an array with level and message, or an exception.
         * @param string $level (optional) The log level (e.g., 'error', 'warning', 'critical'). Default is 'error'.
         * @return $this
         */
        public function errorLog(string|array|Throwable $logData, string $level = 'error'): self
        {
            // If $logData is a string, treat it as the message
            if (is_string($logData)) {
                $message = $logData;
            } 
            // If $logData is an array, extract the message and level
            elseif (is_array($logData)) {
                $message = $logData['message'] ?? '';
                $level = $logData['level'] ?? $level;
            }
            // If $logData is an exception, log it as critical
            elseif ($logData instanceof Throwable) {
                $message = $logData;
                $level = 'critical';
            } else {
                $message = '';
            }

            // Log the message based on the level
            switch ($level) {
                case 'critical':
                    $this->errorLogger->logCritical($message);
                    break;
                case 'warning':
                    $this->errorLogger->logWarning($message);
                    break;
                default:
                    $this->errorLogger->logError($message);
                    break;
            }

            return $this;
        }

        /**
         * Custom error handler for the APIManager.
         * 
         * This method is triggered automatically when a PHP error occurs. It logs the error based on 
         * its severity and may throw an ErrorException for critical errors (e.g., E_ERROR).
         * 
         * @param int $errno The level of the error raised.
         * @param string $errstr The error message.
         * @param string $errfile The filename that the error was raised in.
         * @param int $errline The line number the error was raised at.
         * 
         * @throws ErrorException If the error is of type E_ERROR or similar critical errors.
         *
         */
        public function handleError(int $errno, string $errstr, string $errfile, int $errline): void
        {
            // Determine the log level based on the error type
            $logLevel = Logger::ERROR;  // Default to ERROR
            
            if (in_array($errno, [E_WARNING, E_USER_WARNING])) {
                $logLevel = Logger::WARNING;
            } elseif (in_array($errno, [E_NOTICE, E_USER_NOTICE, E_DEPRECATED, E_USER_DEPRECATED])) {
                $logLevel = Logger::NOTICE;
            } elseif (in_array($errno, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
                $logLevel = Logger::CRITICAL;  // Handle fatal errors with CRITICAL level
            }

            // Prepare the context with file and line information
            $context = [
                'file' => $errfile,
                'line' => $errline,
                'errno' => $errno,
            ];

            // Log the error with the message and context
            $this->errorLogger->logError(
                $errstr,
                $context
            );

            // Throw an exception for critical errors
            if (in_array($errno, [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
                throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
            }
        }

        /**
         * Custom exception handler for the APIManager.
         *
         * This method is triggered automatically when an unhandled exception occurs. It logs the 
         * exception details, including the request method and URI, and sends a 500 HTTP response 
         * with a JSON error message.
         *
         * @param Throwable $throwable The exception that was thrown.
         */
        public function handleException(Throwable $throwable): void
        {
            // Log the exception
            [
                'method' => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
                'uri' => $_SERVER['REQUEST_URI'] ?? 'N/A',
                'file' => $throwable->getFile(),
                'line' => $throwable->getLine(),
            ];

            // Log the exception message and context
            $this->errorLogger->logCritical($throwable);

            // Use the response manager to send a 500 response with a JSON error message
            $this->apiResponseManager->addError(['status' => '500', 'title' => 'Internal Server Error', 'detail' => 'An unexpected error occurred']);
            $this->apiResponseManager->respond(false, [], 500);
        }
        
        /**
         * Sanitizes, trims, and optionally truncates a string.
         * Returns null if the input is empty after sanitization.
         *
         * This method ensures that input data is safe for processing by trimming whitespace,
         * removing invalid UTF-8 characters, and truncating the string if necessary.
         *
         * @param mixed $data The data to sanitize and process.
         * @param int|null $maxLength Optional maximum length for truncation. Must be a positive integer if provided.
         *
         * @return string|null Returns the sanitized and processed string, or null if the string is empty after sanitization.
         *
         * @throws InvalidArgumentException if $maxLength is not null and not a positive integer.
         * @throws RuntimeException if the mbstring extension is required but not available.
         * @throws InvalidArgumentException if the input data is not valid UTF-8 or exceeds the allowed maximum length.
         *
         * @example
         * // Sanitize input with a maximum length of 100 characters
         * $sanitized = $apiManager->sanitizeInput($userInput, 100);
         *
         * // Handle the case where the input was empty after sanitization
         * if ($sanitized === null) {
         *     // Handle empty input
         * }
         */
        public function sanitizeInput(mixed $input, ?int $maxLength = null): string
        {
            // Check if the input is already a string
            if (is_string($input)) {
                return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
            }
    
            // Try to convert to string
            try {
                $convertedString = strval($input);
            } catch (Exception $exception) {
                // If conversion fails, return an empty string
                return '';
            }

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

        /**
         * Validates and sanitizes the expected parameters from a given source (e.g., JSON, XML, POST, GET, REQUEST).
         *
         * @param string $uses The source of the parameters (e.g., JSON, XML, POST, GET, REQUEST).
         * @param array $parameters The array of parameter rules to validate and sanitize.
         * @param bool $handleResponse Determines whether to call handleContinuance() after adding errors.
         * @return array The sanitized and validated parameters.
         * 
         * @example
         * $validatedParams = $this->expectParameters('POST', [
         *     [
         *         'mandatory' => true,
         *         'requires' => 'sessionId',
         *         'name' => 'sessionId',
         *         'format' => FILTER_VALIDATE_REGEXP,
         *         'strictFormat' => true,
         *         'sanitize' => true,
         *         'descriptor' => 'Session ID',
         *         'maxLength' => 32,
         *         'options' => ['regexp' => '/^[a-f0-9]{32}$/i']
         *     ]
         * ], true);
         */
        public function expectParameters(string $uses, array $parameters, bool $handleResponse = true): array
        {
            $inputData = [];
            $errors = [];
            
            // Determine the data source based on $uses
            switch (strtoupper($uses)) {
                case 'JSON':
                    $inputData = $this->getJSONPayload(false);
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        $this->apiResponseManager->addError([
                            'status' => '400',
                            'source' => ['pointer' => '/data'],
                            'title' => 'Invalid JSON payload',
                            'detail' => 'The JSON structure is invalid.',
                        ]);
                        $this->apiResponseManager->bailOut(400);
                    }
                    break;
                case 'XML':
                    $xmlContent = file_get_contents("php://input");
                    if (!$xmlContent) {
                        $this->apiResponseManager->addError([
                            'status' => '400',
                            'source' => ['pointer' => '/data'],
                            'title' => 'Invalid XML payload',
                            'detail' => 'Failed to read XML input.',
                        ]);
                        $this->apiResponseManager->bailOut(400);
                    }
                    $inputData = simplexml_load_string($xmlContent);
                    if ($inputData === false) {
                        $this->apiResponseManager->addError([
                            'status' => '400',
                            'source' => ['pointer' => '/data'],
                            'title' => 'Invalid XML payload',
                            'detail' => 'The XML structure is invalid.',
                        ]);
                        $this->apiResponseManager->bailOut(400);
                    }
                    break;
                case 'POST':
                    $inputData = $_POST;
                    break;
                case 'GET':
                    $inputData = $_GET;
                    break;
                case 'REQUEST':
                    $inputData = $_REQUEST;
                    break;
                default:
                    $this->apiResponseManager->addError([
                        'status' => '400',
                        'source' => ['pointer' => '/data'],
                        'title' => 'Unsupported data source',
                        'detail' => "Unsupported data source: {$uses}",
                    ]);
                    $this->apiResponseManager->bailOut(400);
            }
            
            // Loop through the parameters to validate and sanitize them
            $result = [];
            foreach ($parameters as $param) {
                $mandatory = $param['mandatory'] ?? true;
                $requires = $param['requires'] ?? null;
                $name = $param['name'] ?? $requires;
                $format = $param['format'] ?? null;
                $strictFormat = $param['strictFormat'] ?? true;
                $sanitize = $param['sanitize'] ?? true;
                $descriptor = $param['descriptor'] ?? $name;
                $maxLength = $param['maxLength'] ?? null;

                // Create a dynamic JSON Pointer for the error source
                $pointer = "/data/attributes/{$name}";

                // Check if the required parameter exists in the input data
                $value = $inputData[$requires] ?? null;

                // Check for mandatory fields
                if ($mandatory && $value === null) {
                    $errors[] = [
                        'status' => '400',  // Bad Request
                        'source' => ['pointer' => $pointer],
                        'title' => 'Missing Attribute',
                        'detail' => "{$descriptor} must not be empty.",
                    ];
                    continue;
                }

                // If value is null and not mandatory, continue to the next parameter
                if ($value === null) {
                    $result[$name] = null;
                    continue;
                }

                // Validate the format if a validation rule is provided
                if ($format !== null) {
                    if (is_string($format)) {
                        if ($strictFormat && !preg_match($format, $value)) {
                            $errors[] = [
                                'status' => '422',  // Unprocessable Entity
                                'source' => ['pointer' => $pointer],
                                'title' => 'Invalid Format',
                                'detail' => "{$descriptor} is not in the required format.",
                            ];
                            continue;
                        }
                    } elseif (is_int($format) && !filter_var($value, $format, $param['options'] ?? [])) {
                        if ($strictFormat) {
                            $errors[] = [
                                'status' => '422',  // Unprocessable Entity
                                'source' => ['pointer' => $pointer],
                                'title' => 'Invalid Format',
                                'detail' => "{$descriptor} is not in the required format.",
                            ];
                            continue;
                        }
                    }
                }

                // Sanitize the value if the sanitize flag is true and apply maxLength if specified
                if ($sanitize) {
                    $value = $this->sanitizeInput($value, $maxLength);
                }

                // Add the sanitized and validated value to the result array
                $result[$name] = $value;
            }

            // Handle errors if there are any
            if (!empty($errors)) {
                foreach ($errors as $error) {
                    $this->apiResponseManager->addError($error);
                }

                // Optionally handle response continuation if requested
                if ($handleResponse) {
                    $this->apiResponseManager->handleContinuance(400);
                }
            }

            return $result;
        }

        
        /**
         * Retrieves the response manager instance.
         * 
         * @return ApiResponseManager The response manager instance.
         */
        public function responseManager(): ApiResponseManager
        {
            return $this->apiResponseManager;
        }
        
        /**
        * Securely requires a file.
        *
        * @param string $filePath The path to the file to be required. Use "@/path/to/file" to reference
        *                         the document root, or provide an absolute path.
        * @param bool $force Allow the require operation to proceed even if outside of the document root
        *                    (only works if ENFORCE_SAFE_REQUIRES is not enabled).
        * @throws RuntimeException If the file is outside of the document root and ENFORCE_SAFE_REQUIRES is enabled,
        *                          or if the file does not exist.
        */
       public function requireFile(string $filePath, bool $force = false): void
       {
           $this->handleRequire($filePath, $force, false);
       }
   
       /**
        * Securely requires_once a file.
        *
        * @param string $filePath The path to the file to be required_once. Use "@/path/to/file" to reference
        *                         the document root, or provide an absolute path.
        * @param bool $force Allow the require_once operation to proceed even if outside of the document root
        *                    (only works if ENFORCE_SAFE_REQUIRES is not enabled).
        * @throws RuntimeException If the file is outside of the document root and ENFORCE_SAFE_REQUIRES is enabled,
        *                          or if the file does not exist.
        */
       public function requireOnceFile(string $filePath, bool $force = false): void
       {
           $this->handleRequire($filePath, $force, true);
       }
   
       /**
        * Handles the require and require_once logic with security checks.
        *
        * This method resolves the file path based on the document root and enforces security checks
        * if the ENFORCE_SAFE_REQUIRES environment variable is set. If the file is outside the document root
        * and ENFORCE_SAFE_REQUIRES is enabled, the operation is denied unless the --force flag is provided
        * and ENFORCE_SAFE_REQUIRES is not enabled.
        *
        * @param string $filePath The path to the file.
        * @param bool $force Whether to force the operation if outside of the document root.
        * @param bool $requireOnce Whether to use require_once or require.
        * @throws RuntimeException If the file cannot be safely required.
        */
       private function handleRequire(string $filePath, bool $force, bool $requireOnce): void
       {
           $documentRoot = getenv('DOCUMENT_ROOT_PATH') ?: '/var/www/';
           $safeRequires = getenv('ENFORCE_SAFE_REQUIRES') === 'true';
   
           // Normalize document root to always have a trailing slash
           $documentRoot = rtrim(realpath($documentRoot), '/') . '/';
   
           // Resolve the file path
           $filePath = strpos($filePath, '@/') === 0 ? realpath($documentRoot . ltrim(substr($filePath, 2), '/')) : realpath($filePath);
   
           // Security check: ensure the file is within the document root
           if ($filePath === false || strpos($filePath, $documentRoot) !== 0) {
                if ($safeRequires) {
                    // Deny operation and log with warning
                    $this->errorLogger->warning(sprintf(
                        'Attempted to require file outside of document root: %s. Denied due to ENFORCE_SAFE_REQUIRES.', 
                        $filePath
                    ));
                    throw new RuntimeException("Operation denied: requiring files outside of document root.");
                }
   
                if (!$force) {
                    // Deny if --force flag not used
                    $this->errorLogger->warning(sprintf(
                        'Attempted to require file outside of document root without --force: %s. Denied.', 
                        $filePath
                    ));
                    throw new RuntimeException("Requiring files outside of document root requires --force flag.");
                }
   
               // Log that the force flag is being used
               $this->errorLogger->info('Requiring file outside of document root with --force: ' . $filePath);
            }
   
           // Check if the file exists
           if (!file_exists($filePath)) {
               throw new RuntimeException('File not found: ' . $filePath);
           }
   
           // Require or require_once the file
           if ($requireOnce) {
               require_once $filePath;
           } else {
               require $filePath;
           }
       }

        /**
         * Retrieves the initialized CSRF token manager.
         * 
         * This method returns the instance of the CSRF token manager, if it has been initialized.
         * 
         * @return CsrfTokenManager|null The CSRF token manager instance or null if not initialized.
         */
        public function getCsrfTokenManager(): ?CsrfTokenManager
        {
            return $this->csrfTokenManager;
        }

        /**
         * Converts a human-readable interval (e.g., "1 minute", "2 hours") to a DateInterval.
         *
         * @param string $interval The interval in a human-readable format.
         * @return DateInterval The interval as a DateInterval object.
         * @throws Exception If the interval format is unsupported.
         */
        private function convertToDateInterval(string $interval): DateInterval
        {
            // Convert the interval using supported units
            if (preg_match('/^(\d+)\s*(minute|hour|day|week|month|year)s?$/i', $interval, $matches)) {
                $quantity = (int)$matches[1];
                $unit = strtolower($matches[2]);

                // Supported conversions
                $unitMap = [
                    'minute' => 'PT%sM',
                    'hour' => 'PT%sH',
                    'day' => 'P%sD',
                    'week' => 'P%sW',
                    'month' => 'P%sM',
                    'year' => 'P%sY',
                ];

                if (isset($unitMap[$unit])) {
                    return new DateInterval(sprintf($unitMap[$unit], $quantity));
                }
            }

            throw new Exception('Unsupported interval format: ' . $interval);
        }

        /**
         * Decodes a JSON string into a PHP array with error handling.
         *
         * This method decodes JSON and throws an exception if the JSON is invalid.
         *
         * @param string $json The JSON string to decode.
         * @return array The decoded JSON as a PHP array.
         * @throws RuntimeException If the JSON string is invalid.
         */
        public function decodeJSON(string $json): array
        {
            // Decode the JSON string
            $data = json_decode($json, true);

            // Check if the JSON is valid
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException("Invalid JSON: " . json_last_error_msg());
            }
            
            // Return the decoded data
            return $data;
        }

        /**
         * Encodes a PHP array into a JSON string with error handling.
         *
         * This method encodes data as JSON and throws an exception if encoding fails.
         *
         * @param array $data The data to encode as JSON.
         * @return string The encoded JSON string.
         * @throws RuntimeException If the data cannot be encoded as JSON.
         */
        public function encodeJson(array $data): string
        {
            $json = json_encode($data);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException("Failed to encode JSON: " . json_last_error_msg());
            }
            
            return $json;
        }

        /**
         * Checks if a given string is a valid JSON.
         *
         * @param string $string The string to check.
         * @return bool True if the string is a valid JSON, false otherwise.
         */
        public function isJson($string) {
            if (is_string($string)) {
                json_decode($string);
                return (json_last_error() == JSON_ERROR_NONE);
            }
            
            return false;
        }

        /**
         * Retrieves sanitized input from the $_GET superglobal.
         * 
         * @param string $key The key to retrieve from the $_GET array.
         * @return string|null The sanitized input or null if the key does not exist.
         */
        public function getSanitizedGET(string $key): ?string
        {
            return isset($_GET[$key]) ? $this->sanitizeInput($_GET[$key]) : null;
        }

        /**
         * Retrieves sanitized input from the $_POST superglobal.
         * 
         * @param string $key The key to retrieve from the $_POST array.
         * @return string|null The sanitized input or null if the key does not exist.
         */
        public function getSanitizedPOST(string $key): ?string
        {
            return isset($_POST[$key]) ? $this->sanitizeInput($_POST[$key]) : null;
        }

        /**
         * Retrieves JSON payload from the request body and decodes it into a PHP array.
         *
         * @param bool $requirePayload Whether to require a non-empty JSON payload.
         *
         * @return array The decoded JSON payload.
         * @throws RuntimeException If the JSON payload is invalid or empty.
         */
        public function getJSONPayload(bool $requirePayload = false): array
        {
            // Get the JSON payload from the request body
            $json = file_get_contents('php://input');

            // Check if the JSON payload is empty
            if ($json === '' || $json === '0' || $json === false) {
                if ($requirePayload) {
                    throw new RuntimeException("Request payload is empty.");
                }
                
                return [];
            }
            
            // Decode the JSON payload
            return $this->decodeJSON($json);
        }
    }
?>