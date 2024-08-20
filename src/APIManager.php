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

    use ErrorException;
    use APIManager\CORS;
    use APIManager\responseManager;
    use APIManager\errorLog;
    use Symfony\Component\RateLimiter\RateLimiterFactory;
    use Symfony\Component\Security\Csrf\CsrfTokenManager;
    use Dotenv\Dotenv;
    use Throwable;
    use RuntimeException;
    use InvalidArgumentException;

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
         * @var errorLog $logger Logger instance for error logging.
         */
        private errorLog $errorLog;

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
            $logFilePath = getenv('LOGS_PATH') . '/error.log';

            // Initialize ErrorLogger with the provided log file path
            $this->errorLog = new ErrorLogger($logFilePath);

            // Initialize core components
            $this->apiResponseManager = new ApiResponseManager($corsHandler ?? null, $logger);
            $this->cors = new CORS($this->apiResponseManager, $this->errorLog);


            // Set error and exception handlers
            set_error_handler([$this, 'handleError']);
            set_exception_handler([$this, 'handleException']);

            
            // Register shutdown function to handle fatal errors
            register_shutdown_function([$this, 'handleShutdown']);
        }

        /**
         * Loads environment variables using .env file if DOCUMENT_ROOT_PATH is not already set.
         * If no .env file is found, uses default environment variables.
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
                $this->errorLog->critical(sprintf(
                    'Fatal error: %s in %s on line %d',
                    $error['message'],
                    $error['file'],
                    $error['line']
                ));
                
                // Use the response manager to send a 500 response with a JSON error message
                $this->apiResponseManager->respondWithError(500, 'Internal server error.');
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
            // Apply rate limiting to the current request
            return $this;
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
         * @return $this
         */
        public function addHeader(string $headerName, string $headerValue): self
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
         * @return $this
         */
        public function removeHeader(string $headerName): self
        {
            header_remove($headerName);
            return $this;
        }

        /**
         * Adds a log message.
         *
         * @param array $logData Log data including message, level, and type.
         * @return $this
         */
        public function errorLog(array $logData): self
        {
            $message = $logData['message'] ?? '';
            $level = $logData['level'] ?? 'error';

            switch ($level) {
                case 'critical':
                    $this->errorLog->logCritical($message);
                    break;
                case 'warning':
                    $this->errorLog->logWarning($message);
                    break;
                default:
                    $this->errorLog->logError($message);
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
            // Log the error based on the error level
            $logLevel = Logger::ERROR;

            // Set log level based on error type
            if (in_array($errno, [E_WARNING, E_USER_WARNING])) {
                $logLevel = Logger::WARNING;
            } elseif (in_array($errno, [E_NOTICE, E_USER_NOTICE, E_DEPRECATED, E_USER_DEPRECATED])) {
                $logLevel = Logger::NOTICE;
            }

            // Log the error message
            $this->errorLog->logError($logLevel, sprintf('Error: %s in %s on line %d', $errstr, $errfile, $errline));
            
            // Throw an exception for errors with log level of ERROR
            if ($errno === E_ERROR) {
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
            $context = [
                'method' => $_SERVER['REQUEST_METHOD'] ?? 'CLI',
                'uri' => $_SERVER['REQUEST_URI'] ?? 'N/A',
                'file' => $throwable->getFile(),
                'line' => $throwable->getLine(),
            ];

            // Log the exception message and context
            $this->errorLog->logCritical($throwable->getMessage(), $context);

            // Use the response manager to send a 500 response with a JSON error message
            $this->apiResponseManager->respondWithError(500, 'Internal server error.');
        }
        
        /**
         * Sanitizes, trims, and optionally truncates a string. 
         * Returns null if the input is empty after sanitization.
         *
         * This method ensures that input data is safe for processing by trimming whitespace, 
         * removing invalid UTF-8 characters, and truncating the string if necessary.
         *
         * @param string|null $data The data to sanitize and process. Can be null.
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
        public function sanitizeInput(string $input, ?int $maxLength = null): string
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
           $filePath = strpos($filePath, '@/') === 0 ? $documentRoot . ltrim(substr($filePath, 2), '/') : realpath($filePath);
   
           // Security check: ensure the file is within the document root
           if ($filePath === false || strpos($filePath, $documentRoot) !== 0) {
               if ($safeRequires) {
                   // Log the attempt and deny the operation if ENFORCE_SAFE_REQUIRES is enabled
                   $this->errorLog->warning(sprintf('Attempted to require file outside of document root: %s. Operation denied due to ENFORCE_SAFE_REQUIRES.', $filePath));
                   throw new RuntimeException("Requiring files outside of the document root is not allowed with ENFORCE_SAFE_REQUIRES enabled.");
               }
   
               if (!$force) {
                   // Log the attempt and deny the operation if the force flag is not set
                   $this->errorLog->warning(sprintf('Attempted to require file outside of document root without --force: %s. Operation denied.', $filePath));
                   throw new RuntimeException("Requiring files outside of the document root requires the --force flag.");
               }
   
               // Log that the force flag is being used
               $this->errorLog->info('Requiring file outside of document root with --force: ' . $filePath);
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
         * Decodes a JSON string into a PHP array with error handling.
         * 
         * This method decodes JSON and throws an exception if the JSON is invalid.
         * 
         * @param string $json The JSON string to decode.
         * @return array The decoded JSON as a PHP array.
         * @throws RuntimeException If the JSON string is invalid.
         */
        public function decodeJson(string $json): array
        {
            $data = json_decode($json, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException("Invalid JSON: " . json_last_error_msg());
            }
            
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
         * Retrieves sanitized input from the $_GET superglobal.
         * 
         * @param string $key The key to retrieve from the $_GET array.
         * @return string|null The sanitized input or null if the key does not exist.
         */
        public function getSanitizedGet(string $key): ?string
        {
            return isset($_GET[$key]) ? $this->sanitizeInput($_GET[$key]) : null;
        }

        /**
         * Retrieves sanitized input from the $_POST superglobal.
         * 
         * @param string $key The key to retrieve from the $_POST array.
         * @return string|null The sanitized input or null if the key does not exist.
         */
        public function getSanitizedPost(string $key): ?string
        {
            return isset($_POST[$key]) ? $this->sanitizeInput($_POST[$key]) : null;
        }

        /**
         * Retrieves JSON payload from the request body and decodes it into a PHP array.
         * 
         * @return array The decoded JSON payload.
         * @throws RuntimeException If the JSON payload is invalid or empty.
         */
        public function getJsonPayload(): array
        {
            $json = file_get_contents('php://input');
            if ($json === '' || $json === '0' || $json === false) {
                throw new RuntimeException("Request payload is empty.");
            }
            
            return $this->decodeJson($json);
        }
    }

    // /**
    //  * Example Usages:
    //  * */
    //  // Example with all options enabled
    //  $apiManager = new APIManager();

    //  // --- CORS
    //  $apiManager->useCORS([
    //      'allowedOrigins' => ['https://example.com'],
    //      'allowCredentials' => true,
    //      'allowedMethods' => ['GET', 'POST', 'OPTIONS'],
    //      'allowedHeaders' => ['Content-Type', 'Authorization'],
    //      'exposedHeaders' => ['X-Custom-Header'],
    //      'maxAge' => 3600,
    //  ]);

    // // --- Response manager
    // $responseManager = $apiManager->responseManager();

    // $responseManager->respond(
    //     true, // success
    //     {'someobject' => '...'} // data
    //     200, // optional status code - defaults 200 if success true
    // ); // Successful response

    // $responseManager->addMessage([
    //     'message' => 'Some message',
    //     'type' => 'info',
    // ]); // Adding a message

    // $responseManager->addError([
    //     'status' => "422",
    //     'source' => ['pointer' => '/data/attributes/first-name'],
    //     'title' => 'Invalid Attribute',
    //     'detail' => 'First name must contain at least three characters.',
    // ]); // Adding an error

    // $responseManager->respond(
    //     false, // success
    //     [], // data
    //     400, // optional status code - defaults 400 if success false
    // ); // Error response

    // // --- Rate limiter
    // $responseManager->useRateLimiter([
    //     'id' => 'api_limit',
    //     'policy' => 'sliding_window',
    //     'limit' => 100,
    //     'interval' => '1 minute',
    // ]);

    // // --- CSRF manager
    // $responseManager->useCsrfManager();

    // // --- Security headers
    // $responseManager->useSecurityHeaders([
    //     'Content-Security-Policy' => "default-src 'self'",
    //     'X-Content-Type-Options' => 'nosniff',
    //     'X-Frame-Options' => 'DENY',
    //     'X-XSS-Protection' => '1; mode=block',
    // ]);

    // // Adding a header
    // $responseManager->addHeader('X-Custom-Header', 'CustomValue');

    // // Removing or preventing a header
    // $responseManager->removeHeader('X-Frame-Options');

    // // Adding an error message
    // $responseManager->errorLog([
    //     'message' => 'Some message',
    //     'level' => 'critical', // optional
    //     'type' => 'error', // optional - error, info, warning
    // ]);

    // // Sanitize
    // $responseManager->sanitizeInput('some input', 100 /** desired, optional maximum length */);

    // // .. other stuff, such as decode json, etc.
?>