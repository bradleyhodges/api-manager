<?php
    /**
     * APIManager.php
     * 
     * A robust and secure class for automatically handling Composer autoload, dynamic dependency loading,
     * CORS headers, response management, error logging, security headers, input sanitization, JSON handling, 
     * and exposing custom utilities as defined in `loader.json`.
     * 
     * The APIManager class can be configured with various options to control behavior such as rate limiting, 
     * CSRF protection, and custom headers. It integrates with several key packages to enhance security 
     * and performance for API-driven applications.
     * 
     */
    declare(strict_types=1);

    use Monolog\Logger;
    use Monolog\Handler\StreamHandler;
    use Dotenv\Dotenv;
    use Symfony\Component\RateLimiter\RateLimiterFactory;
    use Symfony\Component\Security\Csrf\CsrfTokenManager;

    class APIManager
    {
        /**
         * @var Logger $logger Monolog logger instance for error logging.
         */
        private Logger $logger;

        /**
         * @var ApiResponseManager|null $responseManager Instance of the response manager, if initialized.
         */
        private ?ApiResponseManager $responseManager = null;

        /**
         * @var RateLimiterFactory|null $limiterFactory Instance of the rate limiter factory, if initialized.
         */
        private ?RateLimiterFactory $limiterFactory = null;

        /**
         * @var CsrfTokenManager|null $csrfTokenManager Instance of the CSRF token manager, if initialized.
         */
        private ?CsrfTokenManager $csrfTokenManager = null;

        /**
         * @var array $securityHeaders Default security headers that can be applied to responses.
         */
        private array $securityHeaders = [
            "Content-Security-Policy" => "default-src 'self'",
            "X-Content-Type-Options" => "nosniff",
            "X-Frame-Options" => "DENY",
            "X-XSS-Protection" => "1; mode=block",
        ];

        /**
         * APIManager constructor.
         * 
         * Initializes the APIManager class, loads environment variables, sets up logging, and configures various options.
         * 
         * @param array $options Configuration options to control the behavior of the manager:
         * - 'dependencies' => array of Composer package names to be loaded.
         * - 'disableCORS' => bool to disable CORS headers.
         * - 'disableResponseManager' => bool to disable response management.
         * - 'disableRateLimiter' => bool to disable rate limiting.
         * - 'disableCsrfManager' => bool to disable CSRF protection.
         * - 'customHeaders' => array of custom security headers to apply.
         * - 'corsOptions' => array of configuration options for CORS handling.
         * - 'rateLimiterConfig' => array of custom configuration options for the rate limiter.
         * - 'csrfConfig' => array of custom configuration options for CSRF management.
         * - 'useUtilities' => array of utility names defined in `loader.json`.
         */
        public function __construct(array $options = [])
        {
            // Load environment variables
            $dotenv = Dotenv::createImmutable(__DIR__);
            $dotenv->load();

            // Initialize logger
            $logPath = getenv('LOGS_PATH') ?: '/var/log/';
            $logFilePath = rtrim($logPath, '/') . '/php_api_errors.log';
            $this->logger = new Logger('api_logger');
            $this->logger->pushHandler(new StreamHandler($logFilePath, Logger::ERROR));

            // Error handling with logging
            set_error_handler([$this, 'handleError']);
            set_exception_handler([$this, 'handleException']);
            
            // Load Composer autoload
            $composerAutoloadPath = getenv('COMPOSER_AUTOLOAD_PATH') ?: '/var/www/vendor/autoload.php';
            if (!file_exists($composerAutoloadPath)) {
                throw new RuntimeException("Composer autoload file not found at: {$composerAutoloadPath}");
            }
            require_once $composerAutoloadPath;

            // Apply configuration options
            $this->applyOptions($options);
        }

        /**
         * Applies the configuration options passed to the API manager.
         * 
         * This method handles setting security headers, initializing CORS, response management,
         * rate limiting, CSRF protection, and loading utilities and dependencies.
         * 
         * @param array $options Configuration options for the API manager.
         */
        private function applyOptions(array $options): void
        {
            // Apply security headers unless disabled
            if (empty($options['disableSecurityHeaders'])) {
                $this->applySecurityHeaders($options['customHeaders'] ?? []);
            }

            // Handle CORS if not disabled
            if (empty($options['disableCORS'])) {
                $this->handleCORS($options['corsOptions'] ?? []);
            }

            // Initialize response manager if not disabled
            if (empty($options['disableResponseManager'])) {
                $this->initializeResponseManager();
            }

            // Initialize rate limiter if not disabled
            if (empty($options['disableRateLimiter'])) {
                $this->initializeRateLimiter($options['rateLimiterConfig'] ?? []);
            }

            // Initialize CSRF token manager if not disabled
            if (empty($options['disableCsrfManager'])) {
                $this->initializeCsrfManager($options['csrfConfig'] ?? []);
            }

            // Load specified utilities
            $this->loadUtilities($options['useUtilities'] ?? []);
        }

        /**
         * Applies security headers to the response.
         * 
         * If a header is already set, it will not be overwritten. Custom headers can also be passed in.
         * 
         * @param array $customHeaders Array of custom headers to be applied.
         */
        private function applySecurityHeaders(array $customHeaders): void
        {
            $headers = array_merge($this->securityHeaders, $customHeaders);
            foreach ($headers as $header => $value) {
                // Only set header if it hasn't been set already
                if (!headers_sent() && !isset($_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))])) {
                    header("{$header}: {$value}");
                }
            }
        }

        /**
         * Handles CORS (Cross-Origin Resource Sharing).
         * 
         * This method loads the CORS utility and applies the provided configuration options.
         * 
         * @param array $corsOptions Configuration options for CORS handling.
         */
        private function handleCORS(array $corsOptions): void
        {
            $corsPath = $this->getUtilityPath('CORS');
            if ($corsPath) {
                require_once $corsPath;
                CORS($corsOptions);  // Pass options to the CORS handler
            }
        }

        /**
         * Initializes the response manager.
         * 
         * This method loads the response manager utility and sets it up for handling API responses.
         */
        private function initializeResponseManager(): void
        {
            $responseManagerPath = $this->getUtilityPath('responseManager');
            if ($responseManagerPath) {
                require_once $responseManagerPath;
                $this->responseManager = new ApiResponseManager();
            }
        }

        /**
         * Initializes the rate limiter.
         * 
         * If custom configuration options are passed, they will override the default settings.
         * 
         * @param array $config Configuration options for rate limiting.
         */
        private function initializeRateLimiter(array $config): void
        {
            $defaultConfig = [
                'id' => 'api_limit',
                'policy' => 'sliding_window',
                'limit' => 100,
                'interval' => '1 minute',
            ];
            $rateLimiterConfig = array_merge($defaultConfig, $config);
            $this->limiterFactory = new RateLimiterFactory($rateLimiterConfig);
        }

        /**
         * Initializes the CSRF (Cross-Site Request Forgery) token manager.
         * 
         * This method sets up CSRF protection for the application.
         * 
         * @param array $config Configuration options for CSRF management.
         */
        private function initializeCsrfManager(array $config): void
        {
            $this->csrfTokenManager = new CsrfTokenManager();
            // Apply additional config if needed
        }

        /**
         * Loads utilities specified in the loader.json configuration file.
         * 
         * @param array $utilities Array of utility names to be loaded.
         */
        private function loadUtilities(array $utilities): void
        {
            $loaderConfig = $this->getLoaderConfig();
            foreach ($utilities as $utilityName) {
                $utilityPath = $this->getUtilityPath($utilityName, $loaderConfig);
                if ($utilityPath) {
                    require_once $utilityPath;
                }
            }
        }

        /**
         * Sets a new header in the response.
         * 
         * This method allows for dynamically setting headers during script execution.
         * 
         * @param string $headerName The name of the header to be set.
         * @param string $headerValue The value of the header to be set.
         */
        public function setNewHeader(string $headerName, string $headerValue): void
        {
            if (!headers_sent()) {
                header("{$headerName}: {$headerValue}");
            }
        }

        /**
         * Retrieves the loader configuration from the loader.json file.
         * 
         * This method loads and parses the loader.json file to get the utility configuration.
         * 
         * @return array The parsed configuration from loader.json.
         */
        private function getLoaderConfig(): array
        {
            $loaderConfigPath = __DIR__ . '/loader.json';
            if (!file_exists($loaderConfigPath)) {
                $this->logger->error("Loader configuration file not found: loader.json");
                throw new RuntimeException("Loader configuration file not found: loader.json");
            }
            
            $loaderConfig = json_decode(file_get_contents($loaderConfigPath), true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $this->logger->error("Error parsing loader.json: " . json_last_error_msg());
                throw new RuntimeException("Error parsing loader.json: " . json_last_error_msg());
            }

            return $loaderConfig;
        }

        /**
         * Retrieves the path of a utility from the loader.json configuration.
         * 
         * This method finds the path of a utility based on its useName in the configuration.
         * 
         * @param string $useName The name of the utility to look up.
         * @param array $config The parsed loader.json configuration.
         * @return string|null The path to the utility, or null if not found.
         */
        private function getUtilityPath(string $useName, array $config = []): ?string
        {
            $config = $config ?: $this->getLoaderConfig();
            foreach ($config as $utility) {
                if ($utility['useName'] === $useName) {
                    return __DIR__ . '/' . $utility['path'];
                }
            }
            return null;
        }

        /**
         * Error handler for the API manager.
         * 
         * Logs the error and throws an ErrorException.
         * 
         * @param int $errno The level of the error raised.
         * @param string $errstr The error message.
         * @param string $errfile The filename that the error was raised in.
         * @param int $errline The line number the error was raised at.
         * @throws ErrorException
         */
        public function handleError(int $errno, string $errstr, string $errfile, int $errline): void
        {
            $this->logger->error("Error: {$errstr} in {$errfile} on line {$errline}");
            throw new ErrorException($errstr, $errno, 0, $errfile, $errline);
        }

        /**
         * Exception handler for the API manager.
         * 
         * Logs the exception and sends a 500 HTTP response with a JSON error message.
         * 
         * @param Throwable $exception The exception that was thrown.
         */
        public function handleException(Throwable $exception): void
        {
            $this->logger->error("Exception: {$exception->getMessage()} in {$exception->getFile()} on line {$exception->getLine()}");
            http_response_code(500);
            echo json_encode(['error' => 'Internal server error.']);
            exit;
        }

        /**
         * Retrieves the initialized response manager.
         * 
         * This method returns the instance of the response manager, if it has been initialized.
         * 
         * @return ApiResponseManager|null The response manager instance or null if not initialized.
         */
        public function getResponseManager(): ?ApiResponseManager
        {
            return $this->responseManager;
        }    /**
        * Securely requires a file.
        * 
        * @param string $filePath The path to the file to be required. Use "@/path/to/file" to reference 
        *                         the document root, or provide an absolute path.
        * @param bool $force Allow the require operation to proceed even if outside of the document root 
        *                    (only works if SAFE_REQUIRES is not enabled).
        * @throws RuntimeException If the file is outside of the document root and SAFE_REQUIRES is enabled, 
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
        *                    (only works if SAFE_REQUIRES is not enabled).
        * @throws RuntimeException If the file is outside of the document root and SAFE_REQUIRES is enabled, 
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
        * if the SAFE_REQUIRES environment variable is set. If the file is outside the document root 
        * and SAFE_REQUIRES is enabled, the operation is denied unless the --force flag is provided 
        * and SAFE_REQUIRES is not enabled.
        * 
        * @param string $filePath The path to the file.
        * @param bool $force Whether to force the operation if outside of the document root.
        * @param bool $requireOnce Whether to use require_once or require.
        * @throws RuntimeException If the file cannot be safely required.
        */
       private function handleRequire(string $filePath, bool $force, bool $requireOnce): void
       {
           $documentRoot = getenv('DOCUMENT_ROOT_PATH') ?: '/var/www/';
           $safeRequires = getenv('SAFE_REQUIRES') === 'true';
   
           // Normalize document root to always have a trailing slash
           $documentRoot = rtrim(realpath($documentRoot), '/') . '/';
   
           // Resolve the file path
           if (strpos($filePath, '@/') === 0) {
               // Replace "@/..." with the document root path
               $filePath = $documentRoot . ltrim(substr($filePath, 2), '/');
           } else {
               // Otherwise, treat as a direct path
               $filePath = realpath($filePath);
           }
   
           // Security check: ensure the file is within the document root
           if ($filePath === false || strpos($filePath, $documentRoot) !== 0) {
               if ($safeRequires) {
                   // Log the attempt and deny the operation if SAFE_REQUIRES is enabled
                   $this->logger->warning("Attempted to require file outside of document root: {$filePath}. Operation denied due to SAFE_REQUIRES.");
                   throw new RuntimeException("Requiring files outside of the document root is not allowed with SAFE_REQUIRES enabled.");
               }
   
               if (!$force) {
                   // Log the attempt and deny the operation if the force flag is not set
                   $this->logger->warning("Attempted to require file outside of document root without --force: {$filePath}. Operation denied.");
                   throw new RuntimeException("Requiring files outside of the document root requires the --force flag.");
               }
   
               // Log that the force flag is being used
               $this->logger->info("Requiring file outside of document root with --force: {$filePath}");
           }
   
           // Check if the file exists
           if (!file_exists($filePath)) {
               throw new RuntimeException("File not found: {$filePath}");
           }
   
           // Require or require_once the file
           if ($requireOnce) {
               require_once $filePath;
           } else {
               require $filePath;
           }
       }

        /**
         * Retrieves the initialized rate limiter factory.
         * 
         * This method returns the instance of the rate limiter factory, if it has been initialized.
         * 
         * @return RateLimiterFactory|null The rate limiter factory instance or null if not initialized.
         */
        public function getRateLimiterFactory(): ?RateLimiterFactory
        {
            return $this->limiterFactory;
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
         * Sanitizes input data.
         * 
         * This method trims whitespace from input and optionally performs other sanitization tasks.
         * 
         * @param string $input The input string to be sanitized.
         * @return string The sanitized string.
         */
        public function sanitizeInput(string $input): string
        {
            return trim(htmlspecialchars($input, ENT_QUOTES, 'UTF-8'));
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
            if (empty($json)) {
                throw new RuntimeException("Request payload is empty.");
            }
            return $this->decodeJson($json);
        }
    }

    /**
     * Example Usages:
     * 
     * These examples demonstrate how to use the `APIManager` class to handle Composer autoload,
     * CORS, response management, and security headers in a dynamic and secure way.
     * 
     * @example
     * // Basic Usage:
     * // Initialize the API manager with default settings and load the MeekroDB dependency.
     * $apiManager = new APIManager([
     *     'dependencies' => ['SergeyTsalkov/meekrodb'],
     *     'useUtilities' => ['CORS'],
     * ]);
     *
     * // Get the response manager and send a successful response.
     * $responseManager = $apiManager->getResponseManager();
     * $responseManager->respondToClient(true, ['data' => 'success']);
     * 
     * 
     * @example
     * // Custom Headers and CORS Configuration:
     * // Initialize the API manager with custom security headers and CORS options.
     * $apiManager = new APIManager([
     *     'customHeaders' => ['X-Custom-Header' => 'CustomValue'],
     *     'corsOptions' => ['allowedOrigins' => ['https://example.com']],
     * ]);
     *
     * // Set an additional custom security header.
     * $apiManager->setNewHeader("X-Additional-Security", "Enabled");
     * 
     * 
     * @example
     * // Disabling Features:
     * // Initialize the API manager with rate limiting and CSRF management disabled.
     * $apiManager = new APIManager([
     *     'disableRateLimiter' => true,
     *     'disableCsrfManager' => true,
     * ]);
     *
     * // The response manager can still be used even with other features disabled.
     * $responseManager = $apiManager->getResponseManager();
     * $responseManager->addGlobalMessage("Some feature is disabled.");
     * $responseManager->respondToClient(true, ['feature_status' => 'disabled']);
     */
?>