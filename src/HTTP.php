<?php
    namespace APIManager;

    use APIManager\ErrorLogger;
    use InvalidArgumentException;
    use Exception;
    use GuzzleHttp\Exception\GuzzleException;
    use GuzzleHttp\Client;
    use GuzzleHttp\HandlerStack;
    use GuzzleHttp\Middleware;
    use GuzzleHttp\Exception\ConnectException;
    use GuzzleHttp\Exception\RequestException;
    use GuzzleHttp\Cookie\CookieJar;
    use Psr\Http\Message\RequestInterface;
    use Psr\Http\Message\ResponseInterface;
    use Psr\SimpleCache\CacheInterface;
    use Symfony\Component\Cache\Adapter\FilesystemAdapter;
    use Symfony\Component\Cache\Psr16Cache;
    use Monolog\Logger;
    use Monolog\Handler\StreamHandler;
    use RuntimeException;
    use React\EventLoop\Factory;
    use React\Socket\Connector;
    use React\Dns\Resolver\Factory as DnsFactory;
    use React\EventLoop\Factory as LoopFactory;
    use React\Promise\PromiseInterface;
    use function React\Promise\race;
    use React\EventLoop\LoopInterface;
    use React\Promise\Deferred;
    use function React\Promise\resolve;
    use GuzzleHttp\Promise\Promise as GuzzlePromise;
    use React\Promise\allSettled;
    use GuzzleHttp\Promise\Utils;

    /**
     * Class HTTP
     * Provides an advanced HTTP client with Happy Eyeballs, DNS caching, and HTTP/1, 2, and 3 support.
     */
    class HTTP
    {
        /**
         * @var Client|null $client The Guzzle HTTP client instance.
         */
        private ?Client $client = null;
        
        /**
         * @var CacheInterface $dnsCache DNS cache interface for resolving hostnames to IP addresses.
         */
        private CacheInterface $dnsCache;
        
        /**
         * @var ErrorLogger $errorLog Logger instance for error logging.
         */
        private ErrorLogger $errorLogger;  // Correct the type to ErrorLogger
        
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
         * @var bool $happyEyeballsEnabled Whether to use the Happy Eyeballs algorithm for DNS resolution.
         */
        private bool $happyEyeballsEnabled = false;

        /**
         * @var bool $retryEnabled Whether to enable retries with exponential backoff and jitter.
         */
        private bool $retryEnabled = false; // Disabled by default

        /**
         * @var bool $dnsCacheEnabled Whether to enable DNS result caching
         */
        private bool $dnsCacheEnabled = false; // Disabled by default

        /**
         * @var bool $httpVersionFallbackEnabled Whether to enable HTTP version fallback (HTTP/3 -> HTTP/2 -> HTTP/1.1).
         */
        private bool $httpVersionFallbackEnabled = false; // Disabled by default

        /**
         * @var bool $minTlsVersionEnabled Whether to enforce a minimum TLS version of 1.2.
         */
        private bool $minTlsVersionEnabled = true;

        /**
         * @var bool $cloudflareDnsEnabled Whether to use Cloudflare's DNS resolver instead of the system resolver.
         */
        private bool $cloudflareDnsEnabled = true;

        /**
         * @var bool $cookieJarEnabled Whether to use a cookie jar for managing cookies.
         */
        private bool $cookieJarEnabled = true;

        /**
         * @var array $userSuppliedConfig User-supplied configuration options.
         */
        private array $userSuppliedConfig = [];

        /**
         * @var bool $useDefaultConfig Whether to use the default configuration options.
         */
        private bool $useDefaultConfig = true;

        /**
         * @var array $happyEyeballsCache Cache for storing IP race data for Happy Eyeballs.
         */
        private array $happyEyeballsCache = [];

        /**
         * @var int $cacheExpiration Cache expiration in seconds (e.g., 5 minutes).
         */
        private int $cacheExpiration = 300; // Cache expiration in seconds (e.g., 5 minutes)

        /**
         * @var array|null $stashedConfig The cached configuration used to create the client.
         */
        private ?array $stashedConfig = null;
    
        /**
         * Constructor to initialize the HTTP class with configurations.
         *
         * @param array $config Configuration options such as 'base_uri', 'headers', etc.
         * @param CacheInterface|null $dnsCache DNS cache interface, defaults to a filesystem cache if null.
         * @param Logger|null $errorLogger PSR-3 logger instance, defaults to lazy-loaded Monolog logger.
         * @throws InvalidArgumentException If configuration is invalid.
         *
         * @example
         * $http = new HTTP(['base_uri' => 'https://example.com'], $dnsCache, $errorLogger);
         */
        public function __construct(array $config = [], CacheInterface $dnsCache = null, Logger $errorLogger = null)
        {
            // Initialize DNS caching with a fallback to a file-based cache
            $this->dnsCache = $dnsCache ?? new Psr16Cache(new FilesystemAdapter());
            
            // Initialize the logger (lazy-loaded for performance)
            $this->errorLogger = new ErrorLogger();

            // Set the user-supplied configuration options
            $this->userSuppliedConfig = $config;

            // Prepare the request with middleware and configuration
            $this->prepareRequest();
        }

        /**
         * Prepare the request with middleware and configuration.
         * 
         * This method creates a Guzzle client with the configured middleware and options.
         * 
         * @throws RuntimeException If the request preparation fails.
         */
        private function prepareRequest() : void
         {
            // Create the handler stack
            $handlerStack = HandlerStack::create();

            // Add middleware conditionally based on flags
            if ($this->retryEnabled) {
                $handlerStack->push($this->createRetryMiddleware(), 'retry');
            }

            if ($this->dnsCacheEnabled) {
                $handlerStack->push($this->createDnsCacheMiddleware(), 'dns_cache');
            }

            if ($this->httpVersionFallbackEnabled) {
                $handlerStack->push($this->createHttpVersionFallbackMiddleware(), 'http_version_fallback');
            }

            // Merge custom configuration with default options
            if ($this->useDefaultConfig) {
                $defaultConfig = [
                    'handler' => $handlerStack,
                    'timeout' => 10,  // Default timeout of 10 seconds
                    'http_version' => $this->httpVersionFallbackEnabled ? '3.0' : '2.0',  // Attempt HTTP/3 if fallback is enabled, otherwise HTTP/2
                    'verify' => true,  // Enforce SSL certificate validation
                    'curl' => [
                        CURLOPT_SSLVERSION => $this->minTlsVersionEnabled ? CURL_SSLVERSION_TLSv1_2 : CURL_SSLVERSION_DEFAULT,
                        CURLOPT_TCP_KEEPALIVE => 1, // Enable TCP keep-alive
                        CURLOPT_FORBID_REUSE => 0,  // Allow connection reuse
                        CURLOPT_ENCODING => 'gzip, deflate, br',  // Enable Brotli compression
                    ],
                ];
            } else {
                $defaultConfig = [];
            }

            // Merge the default and custom configurations
            $finalConfig = array_merge($defaultConfig, $this->userSuppliedConfig);

            // If the client has not been created or if the configuration has changed, recreate the client
            if ($this->client === null || $this->stashedConfig !== $finalConfig) {
                // Create a cookie jar if enabled
                if ($this->cookieJarEnabled) {
                    $this->cookieJar = new CookieJar();
                    $finalConfig['cookies'] = $this->cookieJar;
                }

                // Initialize the Guzzle client with the final configuration
                $this->client = new Client($finalConfig);

                // Cache the configuration
                $this->stashedConfig = $finalConfig;
            }

            // Store default headers if provided
            $this->headers = $finalConfig['headers'] ?? [];
        }

        /**
         * Send an HTTP request with the configured client.
         *
         * This method supports the Happy Eyeballs algorithm for resolving hostnames
         * if enabled. It merges the default headers with any request-specific headers,
         * adds an idempotency key for POST requests, and logs the request and response details.
         *
         * The method blocks until the asynchronous operation completes, making it 
         * appear synchronous to the caller.
         *
         * @param string $method HTTP method (e.g., 'GET', 'POST'). Must be uppercase and conform to RFC 7231.
         * @param string $uri Endpoint URI, which can be relative to the base URI. Must be validated to avoid SSRF attacks.
         * @param array $options Request options compatible with Guzzle, such as 'headers', 'query', etc.
         * @return ResponseInterface The HTTP response.
         * 
         * @throws GuzzleException If the request fails.
         * @throws \RuntimeException If both IPv6 and IPv4 connection attempts fail, or other unexpected issues occur.
         * @throws \InvalidArgumentException If input parameters are invalid.
         */
        public function request(string $method, string $uri, array $options = []): ResponseInterface
        {
            // Validate HTTP method
            $validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
            if (!in_array(strtoupper($method), $validMethods, true)) {
                throw new \InvalidArgumentException("Invalid HTTP method: $method");
            }
    
            // Validate the URI to mitigate SSRF (Server-Side Request Forgery) risks
            if (!filter_var($uri, FILTER_VALIDATE_URL) && !preg_match('/^\/[\w\-\/]+$/', $uri)) {
                throw new \InvalidArgumentException("Invalid URI: $uri");
            }

            // Prepare the request with middleware and configuration
            $this->prepareRequest();

            // If Happy Eyeballs is not enabled, handle the request synchronously without async logic
            if (!$this->happyEyeballsEnabled) {
                return $this->requestBoring($method, $uri, $options);
            }

            // Happy Eyeballs is enabled, proceed with async logic
            $loop = Factory::create();

            // Define a variable to hold the response or error
            $response = null;
            $error = null;

            // Initiate the async request and handle the response or error
            $this->requestAsync($method, $uri, $options, $loop)
                ->then(
                    function ($res) use (&$response) {
                        // Store the response for later retrieval
                        $response = $res;
                    },
                    function ($err) use (&$error) {
                        // Store the error for later retrieval
                        $error = $err;
                    }
                )
                ->always(function () use ($loop) {
                    // Stop the event loop after the request completes
                    $loop->stop();
                });

            // Run the event loop to process the async request
            $loop->run();

            // Check for an error after the loop has stopped
            if ($error !== null) {
                // Log the error message
                $this->logError("Error in request: " . $error->getMessage());

                // Throw the caught error
                throw $error;
            }

            // Ensure the response is set
            if ($response === null) {
                throw new \RuntimeException("Unexpected error: No response or error received during the request.");
            }

            return $response;
        }

        /**
         * The asynchronous version of the requestBoring method. This returns a promise and 
         * is intended to be run in an event loop. If no loop is provided, a new one is created.
         *
         * @param string $method HTTP method (e.g., 'GET', 'POST').
         * @param string $uri Endpoint URI, can be relative to the base URI.
         * @param array $options Request options compatible with Guzzle, such as 'headers', 'query', etc.
         * @param LoopInterface|null $loop The ReactPHP event loop. If null, a new loop will be created.
         * 
         * @return PromiseInterface A promise that resolves to the HTTP response.
         */
        public function requestAsync(string $method, string $uri, array $options = [], ?LoopInterface $loop = null): PromiseInterface
        {
            // Create a loop if none is provided
            // if ($loop === null) {
            //     $loop = \React\EventLoop\Factory::create();
            // }
            $loop = $loop ?? $this->loop ?? ($this->loop = \React\EventLoop\Factory::create());

            // Merge default headers with request-specific headers
            $options['headers'] = array_merge($this->headers, $options['headers'] ?? []);

            // Add idempotency key for POST requests if not already set
            if ($method === 'POST' && !isset($options['headers']['Idempotency-Key'])) {
                $options['headers']['Idempotency-Key'] = bin2hex(random_bytes(16));
            }

            // Add an explicit timeout to the Guzzle request to avoid hanging indefinitely
            $options['timeout'] = $options['timeout'] ?? 10;  // Set a default timeout if not provided

            // If Happy Eyeballs is enabled, resolve the fastest IP for the URI
            if ($this->happyEyeballsEnabled && filter_var($uri, FILTER_VALIDATE_URL)) {
                // Extract the hostname from the URI
                $host = parse_url($uri, PHP_URL_HOST);

                // Proceed if the URI contains a valid hostname
                if ($host) {
                    // Resolve the hostname to IPv6 and IPv4 addresses
                    $resolvedIps = $this->resolveHost($host);

                    if ($resolvedIps['ipv4'] || $resolvedIps['ipv6']) {
                        return $this->makeEyeballsHappy($host, $resolvedIps['ipv6'], $resolvedIps['ipv4'])
                            ->then(function ($fastestIp) use ($host, $uri, $method, $options, $loop) {
                                // Set the CURLOPT_RESOLVE option to use the resolved IP for the given hostname
                                $options['curl'] = [
                                    CURLOPT_RESOLVE => [
                                        "$host:80:$fastestIp",
                                        "$host:443:$fastestIp"
                                    ]
                                ];
                                
                                // Initiate the async Guzzle request with the resolved IP
                                $guzzlePromise = $this->client->requestAsync($method, $uri, $options);

                                // Convert the Guzzle promise to a ReactPHP promise, managing the loop
                                return $this->convertGuzzlePromiseToReactPromise($guzzlePromise, $loop);
                            })
                            ->otherwise(function (\Throwable $e) use ($host) {
                                $this->logError("Failed to resolve Happy Eyeballs for host: $host. Error: " . $e->getMessage());
                                return \React\Promise\reject($e);
                            });
                    } else {
                        $this->logError("Failed to resolve any IPs for host: $host");
                        return \React\Promise\reject(new \RuntimeException("Failed to resolve the host: $host"));
                    }
                }
            }
            
            // If Happy Eyeballs is not enabled, initiate the Guzzle async request
            $guzzlePromise = $this->client->requestAsync($method, $uri, $options);

            // Convert the Guzzle promise to a ReactPHP promise, managing the loop
            return $this->convertGuzzlePromiseToReactPromise($guzzlePromise, $loop);
        }

        /**
         * Send a synchronous HTTP request with the configured client.
         *
         * This method supports using resolved IP addresses directly to bypass the system DNS resolver
         * by utilizing Cloudflare DNS-over-HTTPS if enabled.
         *
         * @param string $method HTTP method (e.g., 'GET', 'POST').
         * @param string $uri Endpoint URI, can be relative to the base URI.
         * @param array $options Request options compatible with Guzzle, such as 'headers', 'query', etc.
         * @return ResponseInterface The HTTP response.
         *
         * @throws GuzzleException If the request fails.
         * @throws RuntimeException If DNS resolution or the HTTP request fails.
         */
        private function requestBoring(string $method, string $uri, array $options = []): ResponseInterface
        {
            try {
                // Parse the host from the URI
                $host = parse_url($uri, PHP_URL_HOST);

                // Resolve the host to get its IPv4 and/or IPv6 addresses
                $resolvedAddresses = $this->resolveHost($host);

                // Check if we have resolved addresses and set CURLOPT_RESOLVE accordingly
                if ($resolvedAddresses['ipv4'] !== null || $resolvedAddresses['ipv6'] !== null) {
                    $curlOptions = [];

                    if ($resolvedAddresses['ipv4'] !== null) {
                        $curlOptions[] = "{$host}:80:{$resolvedAddresses['ipv4']}";
                        $curlOptions[] = "{$host}:443:{$resolvedAddresses['ipv4']}"; // Include HTTPS port 443
                    }

                    if ($resolvedAddresses['ipv6'] !== null) {
                        $curlOptions[] = "{$host}:80:[{$resolvedAddresses['ipv6']}]";
                        $curlOptions[] = "{$host}:443:[{$resolvedAddresses['ipv6']}]"; // Include HTTPS port 443
                    }

                    // Add the resolved addresses to Guzzle's cURL options
                    $options['curl'][CURLOPT_RESOLVE] = $curlOptions;
                }

                // Merge default headers with request-specific headers
                $options['headers'] = array_merge($this->headers, $options['headers'] ?? []);

                // Add idempotency key for POST requests if not already set
                if ($method === 'POST' && !isset($options['headers']['Idempotency-Key'])) {
                    $options['headers']['Idempotency-Key'] = bin2hex(random_bytes(16));
                }

                // Send the request and return the response
                $response = $this->client->request($method, $uri, $options);

                return $response;
            } catch (RequestException $guzzleException) {
                $this->logError('Request failed: ' . $guzzleException->getMessage(), ['exception' => $guzzleException]);
                throw new RuntimeException('Request failed', 0, $guzzleException);
            }
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
                        $this->logError("Retrying request due to exception or server error", [
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
         * Convert a Guzzle promise to a ReactPHP promise using native ReactPHP utilities.
         *
         * @param GuzzlePromise $guzzlePromise The Guzzle promise to convert.
         * @param LoopInterface $loop The ReactPHP event loop to run.
         * @return PromiseInterface The converted ReactPHP promise.
         */
        private function convertGuzzlePromiseToReactPromise(GuzzlePromise $guzzlePromise, LoopInterface $loop): PromiseInterface
        {
            // Create a deferred promise to handle the Guzzle promise resolution
            $deferred = new Deferred();

            // Handle fulfillment and rejection after the promise is waited on
            $guzzlePromise->then(
                function ($value) use ($deferred) {
                    // Resolve the deferred promise with the Guzzle promise value
                    $deferred->resolve($value);
                },
                function ($reason) use ($deferred) {
                    // Reject the deferred promise with the Guzzle promise reason
                    $deferred->reject($reason);
                }
            )->wait();  // Wait for the Guzzle promise to resolve or reject

            // Run the loop until the deferred promise is settled
            $loop->run();  // Run the event loop until the promise resolves

            // The loop will stop in the deferred promise resolution function
            return $deferred->promise();
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
                        $this->errorLogger->warning("HTTP/3 failed, falling back to HTTP/2", [
                            'exception' => $exception->getMessage(),
                            'request' => (string) $request->getUri(),
                        ]);

                        // Fall back to HTTP/2 if HTTP/3 fails
                        $options['http_version'] = '2.0';
                        try {
                            return $handler($request, $options);
                        } catch (Exception $exception) {
                            $this->logError("HTTP/2 also failed, falling back to HTTP/1.1", [
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
         * Resolves both IPv4 and IPv6 addresses for the given host using either the system DNS resolver 
         * or Cloudflare's DNS-over-HTTPS service, depending on configuration.
         *
         * @param string $host The hostname to resolve.
         * @return array An array with 'ipv4' and 'ipv6' keys containing the resolved addresses, or null if resolution fails.
         * @throws InvalidArgumentException If the host is invalid.
         */
        public function resolveHost(string $host): array
        {
            // Validate and sanitize the host
            if (!filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                throw new InvalidArgumentException("Invalid host: $host");
            }

            // Check DNS cache before resolving
            if ($this->dnsCacheEnabled && $this->dnsCache->has($host)) {

                $result = $this->dnsCache->get($host);

                echo "DNS cache hit for $host\n";
                echo "IPv4: {$result['ipv4']}\n";
                echo "IPv6: {$result['ipv6']}\n";

                var_dump($result);

                return $this->dnsCache->get($host);
            }

            // Initialize the result array with null values
            $result = [
                'ipv4' => null,
                'ipv6' => null,
            ];

            try {
                if ($this->cloudflareDnsEnabled) {
                    // Use Cloudflare DNS-over-HTTPS resolver
                    $result = $this->resolveUsingCloudflare($host);
                } else {
                    // Use system DNS resolver
                    $result = $this->resolveUsingSystemDns($host);
                }
            } catch (\Throwable $e) {
                // Log any unexpected errors during resolution
                $this->logError("DNS resolution failed for host: $host. Error: " . $e->getMessage());
            }

            // Cache the result if DNS caching is enabled
            if ($this->dnsCacheEnabled && $result) {
                echo "Caching DNS result for $host\n";
                echo "IPv4: {$result['ipv4']}\n";
                echo "IPv6: {$result['ipv6']}\n";
                
                $this->dnsCache->set($host, $result, $this->cacheExpiration);
            }

            // Return the resolved IP addresses
            return $result;
        }

        /**
         * Resolves a hostname using Cloudflare's DNS-over-HTTPS resolver.
         *
         * @param string $host The hostname to resolve.
         * @return array An array with 'ipv4' and 'ipv6' keys containing the resolved addresses, or null if resolution fails.
         * @throws RuntimeException if the DNS resolution via Cloudflare fails.
         */
        private function resolveUsingCloudflare(string $host): array
        {
            // Configure Guzzle client with connection pooling and persistent connections enabled
            $client = new Client([
                'base_uri' => 'https://cloudflare-dns.com',
                'timeout'  => 5.0,
                'verify'   => true, // Enforce SSL verification
                'headers'  => [
                    'Accept' => 'application/dns-json',
                ],
                'curl' => [
                    CURLOPT_TCP_KEEPALIVE => 1,  // Enable keep-alive
                    CURLOPT_SSLVERSION    => CURL_SSLVERSION_TLSv1_2, // Enforce strong TLS
                    CURLOPT_ENCODING => 'gzip, deflate, br',  // Enable Brotli compression
                ],
            ]);

            // Initialize the result array with null values
            $result = [
                'ipv4' => null,
                'ipv6' => null,
            ];

            try {
                // Send both A and AAAA queries asynchronously
                $promises = [
                    'ipv4' => $client->getAsync('/dns-query', [
                        'query' => [
                            'name' => $host,
                            'type' => 'A',
                        ],
                    ]),
                    'ipv6' => $client->getAsync('/dns-query', [
                        'query' => [
                            'name' => $host,
                            'type' => 'AAAA',
                        ],
                    ]),
                ];

                // Wait for both promises to be fulfilled
                $responses = Utils::settle($promises)->wait();

                // Handle IPv4 (A) response
                if ($responses['ipv4']['state'] === 'fulfilled') {
                    // Decode the JSON response
                    $data = json_decode($responses['ipv4']['value']->getBody()->getContents(), true);

                    // Extract the A record from the response
                    if (isset($data['Answer'])) {
                        // Find the first A record in the response
                        foreach ($data['Answer'] as $answer) {
                            // Check if the record is an A record
                            if ($answer['type'] == 1) { // A record
                                $result['ipv4'] = $answer['data'];
                                break;
                            }
                        }
                    }
                }

                // Handle IPv6 (AAAA) response
                if ($responses['ipv6']['state'] === 'fulfilled') {
                    // Decode the JSON response
                    $data = json_decode($responses['ipv6']['value']->getBody()->getContents(), true);

                    // Extract the AAAA record from the response
                    if (isset($data['Answer'])) {
                        // Find the first AAAA record in the response
                        foreach ($data['Answer'] as $answer) {
                            // Check if the record is an AAAA record
                            if ($answer['type'] == 28) { // AAAA record
                                $result['ipv6'] = $answer['data'];
                                break;
                            }
                        }
                    }
                }
            } catch (RequestException $e) {
                // Log the error and rethrow it
                $this->logError("Failed to resolve DNS using Cloudflare for host: $host. Error: " . $e->getMessage());

                // Rethrow the error with a more descriptive message
                throw new RuntimeException("Cloudflare DNS resolution failed for host: $host", 0, $e);
            } catch (\Throwable $e) {
                // Log any other unexpected errors
                $this->logError("An unexpected error occurred during DNS resolution for host: $host. Error: " . $e->getMessage());
                
                // Rethrow the error with a more descriptive message
                throw new RuntimeException("Unexpected error during DNS resolution for host: $host", 0, $e);
            }
            
            // Return the resolved IP addresses
            return $result;
        }

        /**
         * Resolves a hostname using the system's default DNS resolver.
         *
         * @param string $host The hostname to resolve.
         * @return array An array with 'ipv4' and 'ipv6' keys containing the resolved addresses, or null if resolution fails.
         */
        private function resolveUsingSystemDns(string $host): array
        {
            // Initialize the result array with null values
            $result = [
                'ipv4' => null,
                'ipv6' => null,
            ];

            // Resolve IPv6 (AAAA) records
            $ipv6Records = dns_get_record($host, DNS_AAAA);

            // Extract the first IPv6 record if available
            if ($ipv6Records !== false && count($ipv6Records) > 0) {
                // Store the first IPv6 record in the result array
                $result['ipv6'] = $ipv6Records[0]['ipv6'];
            }

            // Resolve IPv4 (A) records
            $ipv4Records = dns_get_record($host, DNS_A);

            // Extract the first IPv4 record if available
            if ($ipv4Records !== false && count($ipv4Records) > 0) {
                // Store the first IPv4 record in the result array
                $result['ipv4'] = $ipv4Records[0]['ip'];
            }

            // Log the resolved IP addresses
            return $result;
        }

        /**
         * Resolve a hostname using the Happy Eyeballs algorithm by measuring connection times
         * to both IPv6 and IPv4 addresses and selecting the fastest one.
         *
         * @param string $host The hostname to resolve.
         * @param string|null $ipv6 The IPv6 address of the host, or null if unavailable.
         * @param string|null $ipv4 The IPv4 address of the host, or null if unavailable.
         * @param int $port The port to connect to (default is 443 for HTTPS).
         * @param int $timeout The maximum time to wait for each connection attempt (in seconds).
         * @return PromiseInterface A promise that resolves to the IP address (either IPv6 or IPv4) with the fastest connection time.
         *
         * @throws InvalidArgumentException if neither IPv6 nor IPv4 addresses are provided.
         * @throws RuntimeException if the connection to both addresses fails.
         */
        private function makeEyeballsHappy(string $host, ?string $ipv6, ?string $ipv4, int $port = 443, int $timeout = 1): PromiseInterface {
            // Ensure at least one IP address is provided
            if ($ipv6 === null && $ipv4 === null) {
                // Log the error
                $this->logError("No valid IP addresses (IPv6 or IPv4) provided for host: $host.");

                // Reject the promise with an error
                return \React\Promise\reject(new \InvalidArgumentException("No valid IP addresses provided for host: $host."));
            }

            // Deferred promise to resolve when the first connection is established
            $deferred = new Deferred();

            // Track if a connection has been established
            $connectionEstablished = false;

            // Create a new event loop or retrieve the current one
            $loop = \React\EventLoop\Loop::get();

            // Success handler for the connection attempt
            $onConnectionSuccess = function (string $ip) use (&$connectionEstablished, $deferred, $loop) {
                if (!$connectionEstablished) {
                    $connectionEstablished = true;
                    $deferred->resolve($ip);

                    // Stop the loop after the first successful connection
                    $loop->stop();
                }
            };

            // Failure handler for the connection attempt
            $onConnectionFailure = function (\Throwable $e) use (&$connectionEstablished, $deferred, $loop) {
                if (!$connectionEstablished) {
                    $connectionEstablished = true;
                    $deferred->reject($e);

                    // Stop the loop after failure if no connections succeeded
                    $loop->stop();
                }
            };

            // Attempt to connect to IPv6 and IPv4 addresses concurrently
            if ($ipv6 !== null) {
                $this->measureConnectionTime($ipv6, $port, $timeout + 1, $loop)
                    ->then($onConnectionSuccess, $onConnectionFailure);
            }

            if ($ipv4 !== null) {
                // Delay the IPv4 attempt slightly if IPv6 is being attempted
                $delay = $ipv6 !== null ? 0.025 : 0;

                // Schedule the IPv4 connection attempt with a slight delay
                $loop->addTimer($delay, function () use ($ipv4, $port, $timeout, $onConnectionSuccess, $onConnectionFailure) {
                    $this->measureConnectionTime($ipv4, $port, $timeout)
                        ->then($onConnectionSuccess, $onConnectionFailure);
                });
            }

            // Start the event loop
            $loop->run();

            // Return the promise that will resolve with the fastest IP address
            return $deferred->promise();
        }

        /**
         * Measure the time it takes to connect to a given IP address via a socket connection.
         *
         * @param string $ip The IP address to connect to.
         * @param int $port The port to connect to (default is 443 for HTTPS).
         * @param int $timeout The maximum time to wait for a connection (in seconds).
         * @param LoopInterface|null $loop The shared event loop, or null to create a new one.
         * @return PromiseInterface The promise that resolves with the IP address on success, or rejects on failure.
         *
         * @throws InvalidArgumentException if the IP address is invalid.
         */
        private function measureConnectionTime(string $ip, int $port = 443, int $timeout = 1, ?LoopInterface $loop = null): PromiseInterface {
            // Validate the IP address
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                // Reject the promise with an error
                return \React\Promise\reject(new \InvalidArgumentException("Invalid IP address: $ip"));
            }

            // Create a new event loop if none is provided
            $connector = new Connector($loop, [
                'timeout' => $timeout,
            ]);

            // Record the start time for measuring the connection duration
            $startTime = microtime(true);

            // Create a promise to handle the connection attempt
            return $connector->connect("$ip:$port")->then(
                function ($connection) use ($ip, $startTime) {
                    // Calculate the connection duration
                    $elapsedTime = microtime(true) - $startTime;

                    // Close the connection after measuring
                    $connection->close();

                    // Return the IP address
                    return $ip;
                },
                function (\Throwable $error) use ($ip) {
                    // Reject the promise with the error
                    return \React\Promise\reject($error);
                }
            );
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
         * Enable or disable the Happy Eyeballs functionality.
         *
         * @param bool $enabled Whether to enable Happy Eyeballs.
         * @return $this
         */
        public function useHappyEyeballs(bool $enabled): self
        {
            $this->happyEyeballsEnabled = $enabled;
            return $this;
        }

        /**
         * Enable or disable the retry middleware.
         *
         * @param bool $enabled Whether to enable retry middleware.
         * @return $this
         */
        public function useRetry(bool $enabled): self
        {
            $this->retryEnabled = $enabled;
            return $this;
        }

        /**
         * Enable or disable DNS caching middleware.
         *
         * @param bool $enabled Whether to enable DNS caching middleware.
         * @return $this
         */
        public function useDnsCache(bool $enabled): self
        {
            $this->dnsCacheEnabled = $enabled;
            return $this;
        }

        /**
         * Enable or disable HTTP version fallback middleware.
         *
         * @param bool $enabled Whether to enable HTTP version fallback middleware.
         * @return $this
         */
        public function useHttpVersionFallback(bool $enabled): self
        {
            $this->httpVersionFallbackEnabled = $enabled;
            return $this;
        }

        /**
         * Enable or disable the minimum TLS version enforcement.
         *
         * @param bool $enabled Whether to enforce minimum TLS version.
         * @return $this
         */
        public function useMinTlsVersion(bool $enabled): self
        {
            $this->minTlsVersionEnabled = $enabled;
            return $this;
        }

        /**
         * Enable or disable the use of Cloudflare DNS.
         *
         * @param bool $enabled Whether to use Cloudflare DNS.
         * @return $this
         */
        public function useCloudflareDns(bool $enabled): self
        {
            $this->cloudflareDnsEnabled = $enabled;
            return $this;
        }

        /**
         * Enable or disable the use of the cookie jar for managing cookies.
         *
         * @param bool $enabled Whether to use the cookie jar.
         * @return $this
         */
        public function useCookieJar(bool $enabled): self
        {
            $this->cookieJarEnabled = $enabled;
            return $this;
        }

        /**
         * Enable or disable the use of the default configuration.
         *
         * @param bool $enabled Whether to use the default configuration.
         * @return $this
         */
        public function useDefaultConfig(bool $enabled): self
        {
            $this->useDefaultConfig = $enabled;
            return $this;
        }

        /**
         * Send an HTTP GET request.
         *
         * @param string $uri The endpoint URI.
         * @param array $options Additional request options.
         * @return ResponseInterface The HTTP response.
         * @throws GuzzleException If the request fails.
         */
        public function get(string $uri, array $options = []): ResponseInterface
        {
            return $this->request('GET', $uri, $options);
        }

        /**
         * Send an HTTP POST request.
         *
         * @param string $uri The endpoint URI.
         * @param array $options Additional request options.
         * @return ResponseInterface The HTTP response.
         * @throws GuzzleException If the request fails.
         */
        public function post(string $uri, array $options = []): ResponseInterface
        {
            return $this->request('POST', $uri, $options);
        }

        /**
         * Send an HTTP PUT request.
         *
         * @param string $uri The endpoint URI.
         * @param array $options Additional request options.
         * @return ResponseInterface The HTTP response.
         * @throws GuzzleException If the request fails.
         */
        public function put(string $uri, array $options = []): ResponseInterface
        {
            return $this->request('PUT', $uri, $options);
        }

        /**
         * Send an HTTP DELETE request.
         *
         * @param string $uri The endpoint URI.
         * @param array $options Additional request options.
         * @return ResponseInterface The HTTP response.
         * @throws GuzzleException If the request fails.
         */
        public function delete(string $uri, array $options = []): ResponseInterface
        {
            return $this->request('DELETE', $uri, $options);
        }

        /**
         * Send an HTTP PATCH request.
         *
         * @param string $uri The endpoint URI.
         * @param array $options Additional request options.
         * @return ResponseInterface The HTTP response.
         * @throws GuzzleException If the request fails.
         */
        public function patch(string $uri, array $options = []): ResponseInterface
        {
            return $this->request('PATCH', $uri, $options);
        }
        
        /**
         * Logs an error message using the provided logger or error_log as fallback.
         *
         * @param string $message The error message to log.
         */
        private function logInfo(string $message): void
        {
            if ($this->errorLogger instanceof errorLog) {
                $this->errorLogger->logError("[Information only]: " . $message);
            } else {
                error_log("[Information only]: " . $message);
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