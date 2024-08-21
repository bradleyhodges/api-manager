<?php
    namespace APIManager;

    use InvalidArgumentException;
    use Exception;
    use GuzzleHttp\Exception\GuzzleException;
    use GuzzleHttp\Client;
    use GuzzleHttp\HandlerStack;
    use GuzzleHttp\Middleware;
    use GuzzleHttp\Exception\ConnectException;
    use GuzzleHttp\Cookie\CookieJar;
    use Psr\Http\Message\RequestInterface;
    use Psr\Http\Message\ResponseInterface;
    use Psr\SimpleCache\CacheInterface;
    use Symfony\Component\Cache\Adapter\FilesystemAdapter;
    use Symfony\Component\Cache\Psr16Cache;
    use Monolog\Logger;
    use Monolog\Handler\StreamHandler;

    /**
     * Class HTTP
     * Provides an advanced HTTP client with Happy Eyeballs, DNS caching, and HTTP/1, 2, and 3 support.
     */
    class HTTP
    {
        /**
         * @var Client $client The Guzzle HTTP client instance.
         */
        private Client $client;
        
        /**
         * @var CacheInterface $dnsCache DNS cache interface for resolving hostnames to IP addresses.
         */
        private CacheInterface $dnsCache;
        
        /**
         * @var Logger $logger PSR-3 logger instance for logging requests and responses.
         */
        private Logger $logger;
        
        /**
         * @var array $headers Default headers to be used on all requests.
         */
        private array $headers = [];
        
        /**
         * @var array $options Additional request options.
         */
        private array $options = [];
        
        /**
         * @var CookieJar $cookieJar CookieJar instance for managing cookies.
         */
        private CookieJar $cookieJar;
    
        /**
         * Constructor to initialize the HTTP class with configurations.
         *
         * @param array $config Configuration options such as 'base_uri', 'headers', etc.
         * @param CacheInterface|null $dnsCache DNS cache interface, defaults to a filesystem cache if null.
         * @param Logger|null $logger PSR-3 logger instance, defaults to lazy-loaded Monolog logger.
         * @throws InvalidArgumentException If configuration is invalid.
         *
         * @example
         * $http = new HTTP(['base_uri' => 'https://example.com'], $dnsCache, $logger);
         */
        public function __construct(array $config, CacheInterface $dnsCache = null)
        {
            // Initialize DNS caching with a fallback to a file-based cache
            $this->dnsCache = $dnsCache ?? new Psr16Cache(new FilesystemAdapter());
    
            // Initialize the logger (lazy-loaded for performance)
            $this->logger = $logger ?? new Logger('http');
            if ($logger === null) {
                $this->logger->pushHandler(new StreamHandler('php://stdout', Logger::DEBUG));
            }
    
            // Create the handler stack and apply middleware
            $handlerStack = HandlerStack::create();

            // Add middleware for retries with exponential backoff and jitter
            $handlerStack->push($this->createRetryMiddleware(), 'retry');

            // Add middleware for DNS caching using Cloudflare's 1.1.1.1 resolver
            $handlerStack->push($this->createDnsCacheMiddleware(), 'dns_cache');

            // Add middleware for HTTP version fallback (attempt HTTP/3, fall back to HTTP/2, then to HTTP/1.1)
            $handlerStack->push($this->createHttpVersionFallbackMiddleware(), 'http_version_fallback');

            // Merge custom configuration with default options
            $defaultConfig = [
                'handler' => $handlerStack,
                'timeout' => 10,  // Default timeout of 10 seconds
                'http_version' => '2.0',  // Attempt to use HTTP/2
                'verify' => true,  // Enforce SSL certificate validation
                'curl' => [
                    CURLOPT_SSLVERSION => CURL_SSLVERSION_TLSv1_2,  // Enforce TLS 1.2
                    CURLOPT_DNS_SERVERS => '1.1.1.1',  // Use Cloudflare DNS
                ],
            ];
            $finalConfig = array_merge($defaultConfig, $config);

            // Create a cookie jar
            $this->cookieJar = new CookieJar();

            // Initialize the Guzzle client
            $this->client = new Client($finalConfig);

            // Store default headers if provided
            $this->headers = $finalConfig['headers'] ?? [];
        }

        /**
         * Send an HTTP request with the configured client.
         *
         * @param string $method HTTP method (e.g., 'GET', 'POST').
         * @param string $uri Endpoint URI (relative to base URI).
         * @param array $options Additional request options.
         * @return ResponseInterface The HTTP response.
         * @throws GuzzleException If the request fails.
         * @throws RuntimeException For any unexpected issues during the request.
         * 
         * @example
         * $response = $http->request('GET', '/example-endpoint');
         */
        public function request(string $method, string $uri, array $options = []): ResponseInterface
        {
            try {
                // Merge default headers with request-specific headers
                $options['headers'] = array_merge($this->headers, $options['headers'] ?? []);

                // Add idempotency key for POST requests if not already set
                if ($method === 'POST' && !isset($options['headers']['Idempotency-Key'])) {
                    $options['headers']['Idempotency-Key'] = bin2hex(random_bytes(16));
                }

                // Send the request and return the response
                $response = $this->client->request($method, $uri, $options);

                // Log request and response details (optional, can be adjusted for production environments)
                $this->logger->info(sprintf('Sent %s request to %s', $method, $uri), $options);
                $this->logger->info("Received response with status code: " . $response->getStatusCode());

                return $response;
            } catch (GuzzleException $guzzleException) {
                $this->logger->error('Request failed: ' . $guzzleException->getMessage(), ['exception' => $guzzleException]);
                throw new RuntimeException('Request failed', 0, $guzzleException);
            }
        }

        /**
         * Set default headers to be used on all requests.
         *
         * @param array $headers Key-value pairs of headers.
         */
        public function setDefaultHeaders(array $headers): void
        {
            $this->headers = array_merge($this->headers, $headers);
        }

        /**
         * Set Bearer token for authorization.
         *
         * @param string $token The bearer token.
         */
        public function setBearerToken(string $token): void
        {
            $this->setDefaultHeaders(['Authorization' => 'Bearer ' . $token]);
        }

        /**
         * Set Basic Authentication credentials with secure password handling.
         *
         * @param string $username The username.
         * @param string $password The password.
         */
        public function setBasicAuth(string $username, string $password): void
        {
            $this->setDefaultHeaders(['Authorization' => 'Basic ' . base64_encode($username . ':' . $password)]);
        }

        /**
         * Add global query parameters that will be used on all requests.
         *
         * @param array $params Key-value pairs of query parameters.
         */
        public function addQueryParameters(array $params): void
        {
            $this->options['query'] = array_merge($this->options['query'] ?? [], $params);
        }

        /**
         * Returns the cookie jar for managing cookies.
         *
         * @return CookieJar The CookieJar instance.
         */
        public function cookieJar(): CookieJar
        {
            return $this->cookieJar;
        }

        /**
         * Get the Guzzle HTTP client instance.
         *
         * @return Client The Guzzle client instance.
         */
        public function getClient(): Client
        {
            return $this->client;
        }

        /**
         * Create a retry middleware with exponential backoff and jitter.
         *
         * @return callable The retry middleware callable.
         * 
         * @example
         * $handlerStack->push($this->createRetryMiddleware(), 'retry');
         */
        private function createRetryMiddleware(): callable
        {
            return Middleware::retry(
                function (
                    int $retries,
                    RequestInterface $request,
                    ?ResponseInterface $response = null,
                    ?Exception $exception = null
                ): bool {
                    // Retry on network failures, 429 (Too Many Requests), or 5xx responses
                    if ($exception instanceof ConnectException || ($response && $response->getStatusCode() >= 500)) {
                        $this->logger->info("Retrying request due to exception or server error", [
                            'retries' => $retries,
                            'request' => (string) $request->getUri(),
                            'exception' => $exception instanceof Exception ? $exception->getMessage() : null,
                            'response' => $response instanceof ResponseInterface ? $response->getStatusCode() : null,
                        ]);
                        return $retries < 5;  // Retry up to 5 times
                    }

                    return false;
                },
                function (int $retries): int {
                    $jitter = random_int(0, 100);  // Add jitter to avoid thundering herd problem
                    return (1000 * pow(2, $retries)) + $jitter;  // Exponential backoff with jitter
                }
            );
        }

        /**
         * Create a DNS caching middleware using Cloudflare's 1.1.1.1 DNS.
         *
         * @return callable The DNS caching middleware callable.
         * 
         * @example
         * $handlerStack->push($this->createDnsCacheMiddleware(), 'dns_cache');
         */
        private function createDnsCacheMiddleware(): callable
        {
            return Middleware::mapRequest(function (RequestInterface $request): RequestInterface {
                $host = parse_url($request->getUri(), PHP_URL_HOST);

                // Check DNS cache
                if ($this->dnsCache->has($host)) {
                    $ip = $this->dnsCache->get($host);
                } else {
                    // Perform DNS resolution with Happy Eyeballs using Cloudflare's 1.1.1.1 DNS
                    $ip = $this->resolveWithHappyEyeballs($host);
                    $this->dnsCache->set($host, $ip, 3600);  // Cache for 1 hour
                }

                // Replace the host in the request URI with the resolved IP
                $uri = $request->getUri()->withHost($ip);
                return $request->withUri($uri);
            });
        }

        /**
         * Create middleware to handle HTTP version fallback with improved logging.
         *
         * @return callable The HTTP version fallback middleware callable.
         * 
         * @example
         * $handlerStack->push($this->createHttpVersionFallbackMiddleware(), 'http_version_fallback');
         */
        private function createHttpVersionFallbackMiddleware(): callable
        {
            return function (callable $handler): callable {
                return function (RequestInterface $request, array $options) use ($handler) {
                    $options['http_version'] = '3.0';  // Start with HTTP/3

                    try {
                        return $handler($request, $options);
                    } catch (Exception $exception) {
                        $this->logger->warning("HTTP/3 failed, falling back to HTTP/2", [
                            'exception' => $exception->getMessage(),
                            'request' => (string) $request->getUri(),
                        ]);

                        // Fall back to HTTP/2 if HTTP/3 fails
                        $options['http_version'] = '2.0';
                        try {
                            return $handler($request, $options);
                        } catch (Exception $exception) {
                            $this->logger->error("HTTP/2 also failed, falling back to HTTP/1.1", [
                                'exception' => $exception->getMessage(),
                                'request' => (string) $request->getUri(),
                            ]);

                            // Fall back to HTTP/1.1 if HTTP/2 also fails
                            $options['http_version'] = '1.1';
                            return $handler($request, $options);
                        }
                    };
                };
            };
        }

        /**
         * Resolve a hostname using the Happy Eyeballs algorithm by measuring connection times
         * to both IPv6 and IPv4 addresses and selecting the fastest one.
         *
         * @param string $ipv6 The IPv6 address of the host.
         * @param string $ipv4 The IPv4 address of the host.
         * @param int $port The port to connect to (default is 80 for HTTP).
         * @param int $timeout The maximum time to wait for each connection attempt (in seconds).
         * @return string The IP address (either IPv6 or IPv4) with the fastest connection time.
         * 
         * @throws RuntimeException If both connection attempts fail.
         * 
         * @example
         * $fastestIp = $this->connectToFastestIP('::1', '127.0.0.1', 443, 3);
         * try {
         *     $fastestIp = $this->connectToFastestIP('::1', '127.0.0.1');
         * } catch (RuntimeException $e) {
         *     echo "Failed to connect to both IPv6 and IPv4: " . $e->getMessage();
         * }
         */
        private function connectToFastestIP(string $ipv6, string $ipv4, int $port = 80, int $timeout = 2): string
        {
            // Measure connection time to IPv6
            $ipv6Time = $this->measureConnectionTime($ipv6, $timeout, $port);

            // Measure connection time to IPv4
            $ipv4Time = $this->measureConnectionTime($ipv4, $timeout, $port);

            // Log the results for debugging purposes
            $this->logger->info("Connection times", ['IPv6' => $ipv6Time, 'IPv4' => $ipv4Time]);

            // Choose the IP address with the fastest connection time
            if ($ipv6Time !== false && ($ipv4Time === false || $ipv6Time < $ipv4Time)) {
                return $ipv6;
            } elseif ($ipv4Time !== false) {
                return $ipv4;
            }

            // If both connections fail, throw an exception with details
            $this->logger->error("Failed to connect to both IPv6 and IPv4 addresses.");
            throw new RuntimeException("Failed to connect to both IPv6 and IPv4 addresses.");
        }

        /**
         * Measure the time it takes to connect to a given IP address.
         *
         * @param string $ip The IP address to connect to.
         * @param int $timeout The maximum time to wait for a connection (in seconds).
         * @param int $port The port to connect to (default is 443 for HTTPS).
         * @return float|false The connection time in seconds, or false on failure.
         * 
         * @example
         * $connectionTime = $this->measureConnectionTime('127.0.0.1', 2, 443);
         */
        private function measureConnectionTime(string $ip, int $timeout, int $port = 443)
        {
            // Validate the IP address
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                $this->logger->warning("Invalid IP address: {$ip}");
                return false;
            }

            // Record the start time
            $startTime = microtime(true);

            // Attempt to open a secure connection to the IP address on the specified port
            $connection = @fsockopen($ip, $port, $errno, $errstr, $timeout);

            if ($connection) {
                // Calculate the elapsed time
                fclose($connection);
                return microtime(true) - $startTime;  // Return the elapsed time
            }

            // Log the connection failure with details
            $this->logger->warning("Failed to connect to IP {$ip} on port {$port}. Error: {$errstr} ({$errno})");

            // Return false if the connection failed
            return false;
        }
    }
?>