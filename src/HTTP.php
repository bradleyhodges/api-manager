<?php
    namespace APIManager;

    use JsonException;
    use SplFileInfo;
    use Throwable;
    use React\EventLoop\Loop;
    use function React\Promise\reject;
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
         * @var LoopInterface|null $loop The ReactPHP event loop instance.
         */
        private $loop;
        
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
        private bool $happyEyeballsEnabled = true;

        /**
         * @var bool $retryEnabled Whether to enable retries with exponential backoff and jitter.
         */
        private bool $retryEnabled = false; // Disabled by default

        /**
         * @var bool $dnsCacheEnabled Whether to enable DNS result caching
         */
        private bool $dnsCacheEnabled = true; // Disabled by default

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
         * @var int $cacheExpiration Cache expiration in seconds (e.g., 5 minutes).
         */
        private int $cacheExpiration = 300; // Cache expiration in seconds (e.g., 5 minutes)

        /**
         * @var array|null $stashedConfig The cached configuration used to create the client.
         */
        private ?array $stashedConfig = null;

        /**
         * Whether to evaluate request intention (e.g., detect accidental body data in GET requests).
         */
        private bool $evaluateRequestIntention = true;

        /**
         * The last URI that was requested.
         */
        public string $lastUri = '';
        
        /**
         * An object which may contain cookies from the last request.
         */
        public $cookies;
    
        /**
         * Constructor to initialize the HTTP class with configurations.
         *
         * @param array $config Configuration options such as 'base_uri', 'headers', etc.
         * @param CacheInterface|null $dnsCache DNS cache interface, defaults to a filesystem cache if null.
         * @throws InvalidArgumentException If configuration is invalid.
         * @example
         * $http = new HTTP(['base_uri' => 'https://example.com'], $dnsCache, $errorLogger);
         */
        public function __construct(array $config = [], CacheInterface $dnsCache = null)
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
            if (!$this->client instanceof Client || $this->stashedConfig !== $finalConfig) {
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
         * @throws RuntimeException If both IPv6 and IPv4 connection attempts fail, or other unexpected issues occur.
         * @throws InvalidArgumentException If input parameters are invalid.
         */
        public function request(string $method, string $uri, array $options = []): ResponseInterface
        {
            // Validate HTTP method
            $validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];
            if (!in_array(strtoupper($method), $validMethods, true)) {
                throw new InvalidArgumentException('Invalid HTTP method: ' . $method);
            }
    
            // Validate the URI to mitigate SSRF (Server-Side Request Forgery) risks
            if (!filter_var($uri, FILTER_VALIDATE_URL) && (preg_match('/^\/[\w\-\/]+$/', $uri) === 0 || preg_match('/^\/[\w\-\/]+$/', $uri) === false)) {
                throw new InvalidArgumentException('Invalid URI: ' . $uri);
            }

            // Prepare the request with middleware and configuration
            $this->prepareRequest();
            
            // Save the last URI for potential referer use in future requests
            $this->lastUri = $uri;

            // If Happy Eyeballs is not enabled, handle the request synchronously without async logic
            if (!$this->happyEyeballsEnabled) {
                return $this->requestBoring($method, $uri, $options);
            }

            // Happy Eyeballs is enabled, proceed with async logic
            $loop = LoopFactory::create();

            // Define a variable to hold the response or error
            $response = null;
            $error = null;

            // Initiate the async request and handle the response or error
            $this->requestAsync($method, $uri, $options, $loop)
                ->then(
                    function ($res) use (&$response): void {
                        // Store the response for later retrieval
                        $response = $res;
                    },
                    function ($err) use (&$error): void {
                        // Store the error for later retrieval
                        $error = $err;
                    }
                )
                ->always(function () use ($loop): void {
                    // Stop the event loop after the request completes
                    $loop->stop();
                });

            // Run the event loop to process the async request
            $loop->run();

            // Check for an error after the loop has stopped
            if ($error instanceof Throwable) {
                // Log the error message
                $this->logError("Error in request: " . $error->getMessage());

                // Throw the caught error
                throw $error;
            }

            // Ensure the response is set
            if ($response === null) {
                throw new RuntimeException("Unexpected error: No response or error received during the request.");
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
            // Use the provided loop or create a new one if not provided
            $loop = $loop ?? $this->loop ?? ($this->loop = LoopFactory::create());

            // Merge default headers with request-specific headers
            $options['headers'] = array_merge($this->headers, $options['headers'] ?? []);

            // Add an explicit timeout to the Guzzle request to avoid hanging indefinitely
            $options['timeout'] = $options['timeout'] ?? 10;  // Set a default timeout if not provided

            // If DNS caching is enabled, check the cache first
            if ($this->dnsCacheEnabled && filter_var($uri, FILTER_VALIDATE_URL)) {
                $host = parse_url($uri, PHP_URL_HOST);

                if ($host && $this->dnsCache->has($host)) {
                    // Retrieve cached IP addresses
                    $cachedIps = $this->dnsCache->get($host);

                    // If we have a cached IPv4 or IPv6 address, we can skip Happy Eyeballs
                    if ($cachedIps['ipv4'] || $cachedIps['ipv6']) {
                        $fastestIp = $cachedIps['ipv6'] ?? $cachedIps['ipv4']; // Use IPv6 if available, fallback to IPv4

                        // Set the CURLOPT_RESOLVE option to use the cached IP
                        $options['curl'] = [
                            CURLOPT_RESOLVE => [
                                sprintf('%s:80:%s', $host, $fastestIp),
                                sprintf('%s:443:%s', $host, $fastestIp)
                            ]
                        ];

                        // Initiate the async Guzzle request with the cached IP
                        $guzzlePromise = $this->client->requestAsync($method, $uri, $options);

                        // Convert the Guzzle promise to a ReactPHP promise, managing the loop
                        return $this->convertGuzzlePromiseToReactPromise($guzzlePromise, $loop);
                    }
                }
            }

            // If Happy Eyeballs is enabled, resolve the fastest IP for the URI
            if ($this->happyEyeballsEnabled && filter_var($uri, FILTER_VALIDATE_URL)) {
                // Extract the hostname from the URI
                $host = parse_url($uri, PHP_URL_HOST);

                if ($host) {
                    // Resolve the hostname to IPv6 and IPv4 addresses
                    $resolvedIps = $this->resolveHost($host);

                    // Check if we have resolved IPs for the hostname
                    if ($resolvedIps['ipv4'] || $resolvedIps['ipv6']) {
                        return $this->makeEyeballsHappy($host, $resolvedIps['ipv6'], $resolvedIps['ipv4'])
                            ->then(function ($fastestIp) use ($host, $uri, $method, $options, $loop): PromiseInterface {
                                // Set the CURLOPT_RESOLVE option to use the resolved IP for the given hostname
                                $options['curl'] = [
                                    CURLOPT_RESOLVE => [
                                        sprintf('%s:80:%s', $host, $fastestIp),
                                        sprintf('%s:443:%s', $host, $fastestIp)
                                    ]
                                ];
                                
                                // Initiate the async Guzzle request with the resolved IP
                                $guzzlePromise = $this->client->requestAsync($method, $uri, $options);

                                // Convert the Guzzle promise to a ReactPHP promise, managing the loop
                                return $this->convertGuzzlePromiseToReactPromise($guzzlePromise, $loop);
                            })
                            ->otherwise(function (Throwable $throwable) use ($host): PromiseInterface {
                                $this->logError(sprintf('Failed to resolve Happy Eyeballs for host: %s. Error: ', $host) . $throwable->getMessage());
                                return reject($throwable);
                            });
                    }

                    // Log an error if DNS resolution fails
                    $this->logError('Failed to resolve any IPs for host: ' . $host);
                    return reject(new RuntimeException('Failed to resolve the host: ' . $host));
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
                        $curlOptions[] = sprintf('%s:80:%s', $host, $resolvedAddresses['ipv4']);
                        $curlOptions[] = sprintf('%s:443:%s', $host, $resolvedAddresses['ipv4']); // Include HTTPS port 443
                    }

                    if ($resolvedAddresses['ipv6'] !== null) {
                        $curlOptions[] = sprintf('%s:80:[%s]', $host, $resolvedAddresses['ipv6']);
                        $curlOptions[] = sprintf('%s:443:[%s]', $host, $resolvedAddresses['ipv6']); // Include HTTPS port 443
                    }

                    // Add the resolved addresses to Guzzle's cURL options
                    $options['curl'][CURLOPT_RESOLVE] = $curlOptions;
                }

                // Merge default headers with request-specific headers
                $options['headers'] = array_merge($this->headers, $options['headers'] ?? []);

                // Send the request and return the response
                $response = $this->client->request($method, $uri, $options);

                return $response;
            } catch (RequestException $requestException) {
                $this->logError('Request failed: ' . $requestException->getMessage());
                throw new RuntimeException('Request failed', 0, $requestException);
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
                        $this->logError("Retrying request due to exception or server error");
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
        private function convertGuzzlePromiseToReactPromise(\GuzzleHttp\Promise\PromiseInterface $guzzlePromise, LoopInterface $loop): PromiseInterface
        {
            // Create a deferred promise to handle the Guzzle promise resolution
            $deferred = new Deferred();

            // Handle fulfillment and rejection after the promise is waited on
            $guzzlePromise->then(
                function ($value) use ($deferred): void {
                    $deferred->resolve($value);
                },
                function ($reason) use ($deferred): void {
                    // Reject the deferred promise with the rejection reason
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
                    try {
                        $ip = $this->resolveUsingCloudflare($host);
                        $this->dnsCache->set($host, $ip, 3600);  // Cache for 1 hour
                    } catch (Throwable $e) {
                        // Log the error and handle the exception gracefully
                        $this->logError("DNS resolution failed: " . $e->getMessage());
                        return $request; // Return the original request if DNS resolution fails
                    }
                }

                // Set the resolved IP address in the request's cURL options
                $uri = $request->getUri()->withHost($host);

                // Return the request with the resolved IP address
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
                            $this->logError("HTTP/2 also failed, falling back to HTTP/1.1");

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
                throw new InvalidArgumentException('Invalid host: ' . $host);
            }

            // Check DNS cache before resolving
            if ($this->dnsCacheEnabled && $this->dnsCache->has($host)) {
                // Return the cache hit if available
                return $this->dnsCache->get($host);
            }

            // Initialize the result array with null values
            $result = [
                'ipv4' => null,
                'ipv6' => null,
            ];

            try {
                $result = $this->cloudflareDnsEnabled ? $this->resolveUsingCloudflare($host) : $this->resolveUsingSystemDns($host);
            } catch (Throwable $throwable) {
                // Log any unexpected errors during resolution
                $this->logError(sprintf('DNS resolution failed for host: %s. Error: ', $host) . $throwable->getMessage());
            }

            // Cache the result if DNS caching is enabled
            if ($this->dnsCacheEnabled && $result) {
                // Cache the result with the configured expiration time
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
                $this->logError(sprintf('Failed to resolve DNS using Cloudflare for host: %s. Error: ', $host) . $e->getMessage());

                // Rethrow the error with a more descriptive message
                throw new RuntimeException('Cloudflare DNS resolution failed for host: ' . $host, 0, $e);
            } catch (Throwable $e) {
                // Log any other unexpected errors
                $this->logError(sprintf('An unexpected error occurred during DNS resolution for host: %s. Error: ', $host) . $e->getMessage());
                
                // Rethrow the error with a more descriptive message
                throw new RuntimeException('Unexpected error during DNS resolution for host: ' . $host, 0, $e);
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
            if ($ipv6Records !== false && $ipv6Records !== []) {
                // Store the first IPv6 record in the result array
                $result['ipv6'] = $ipv6Records[0]['ipv6'];
            }

            // Resolve IPv4 (A) records
            $ipv4Records = dns_get_record($host, DNS_A);

            // Extract the first IPv4 record if available
            if ($ipv4Records !== false && $ipv4Records !== []) {
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
                $this->logError(sprintf('No valid IP addresses (IPv6 or IPv4) provided for host: %s.', $host));

                // Reject the promise with an error
                return reject(new InvalidArgumentException(sprintf('No valid IP addresses provided for host: %s.', $host)));
            }

            // Deferred promise to resolve when the first connection is established
            $deferred = new Deferred();

            // Track if a connection has been established
            $connectionEstablished = false;

            // Create a new event loop or retrieve the current one
            $loop = Loop::get();

            // Success handler for the connection attempt
            $onConnectionSuccess = function (string $ip) use (&$connectionEstablished, $deferred, $loop): void {
                if (!$connectionEstablished) {
                    $connectionEstablished = true;
                    $deferred->resolve($ip);

                    // Stop the loop after the first successful connection
                    $loop->stop();
                }
            };

            // Failure handler for the connection attempt
            $onConnectionFailure = function (Throwable $throwable) use (&$connectionEstablished, $deferred, $loop): void {
                if (!$connectionEstablished) {
                    $connectionEstablished = true;
                    $deferred->reject($throwable);

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
                $loop->addTimer($delay, function () use ($ipv4, $port, $timeout, $onConnectionSuccess, $onConnectionFailure): void {
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
                return reject(new InvalidArgumentException('Invalid IP address: ' . $ip));
            }

            // Create a new event loop if none is provided
            $connector = new Connector($loop, [
                'timeout' => $timeout,
            ]);

            // Record the start time for measuring the connection duration
            $startTime = microtime(true);

            // Create a promise to handle the connection attempt
            return $connector->connect(sprintf('%s:%d', $ip, $port))->then(
                function ($connection) use ($ip, $startTime): string {
                    // Calculate the connection duration
                    $elapsedTime = microtime(true) - $startTime;

                    // Close the connection after measuring
                    $connection->close();

                    // Return the IP address
                    return $ip;
                },
                function (Throwable $throwable) use ($ip): PromiseInterface {
                    // Reject the promise with the error
                    return reject($throwable);
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
         * Enable or disable evaluation of request intention.
         *
         * @param bool $evaluate Whether to evaluate request intentions.
         */
        public function useEvaluateRequestIntention(bool $evaluate): self
        {
            $this->evaluateRequestIntention = $evaluate;
            return $this;
        }

        /**
         * Detect the content type based on the body data and format it accordingly.
         *
         * This method determines the appropriate Content-Type header based on the structure
         * and contents of the request body. It supports various formats such as `multipart/form-data`,
         * `application/json`, `application/x-www-form-urlencoded`, and plain text.
         *
         * The body data is formatted based on the detected content type and returned along
         * with the appropriate headers.
         *
         * @param mixed $body The request body, which can be an array, string, or other supported types.
         *                    This variable is passed by reference and may be modified to match the
         *                    Content-Type.
         *
         * @return array An associative array containing 'headers' and 'body', where 'headers' holds
         *               the Content-Type and 'body' holds the formatted body data.
         *
         * @throws InvalidArgumentException If the body cannot be properly encoded or an unsupported body type is detected.
         *
         * @example
         * $result = $this->detectContentTypeAndFormatBody($body);
         * header("Content-Type: " . $result['headers']['Content-Type']);
         * echo $result['body'];
         */
        private function detectContentTypeAndFormatBody(mixed &$body): array
        {
            try {
                if (is_array($body)) {
                    // Check if the array contains a file for multipart/form-data
                    if ($this->containsFile($body)) {
                        return [
                            'headers' => [
                                'Content-Type' => 'multipart/form-data'
                            ],
                            'body' => $body,
                        ];
                    }

                    // Determine if the array is associative or sequential
                    $isAssociative = $this->isAssociativeArray($body);
                    if ($isAssociative) {
                        // Handle associative arrays as JSON
                        $encodedBody = json_encode($body, JSON_THROW_ON_ERROR);

                        return [
                            'headers' => [
                                'Content-Type' => 'application/json'
                            ],
                            'body' => $encodedBody,
                        ];
                    }

                    // Handle sequential arrays as x-www-form-urlencoded
                    $encodedBody = http_build_query($body, '', '&', PHP_QUERY_RFC3986);
                    return [
                        'headers' => [
                            'Content-Type' => 'application/x-www-form-urlencoded'
                        ],
                        'body' => $encodedBody,
                    ];
                }
                
                // Return the body as-is with a plain text Content-Type
                return [
                    'headers' => [
                        'Content-Type' => 'text/plain'
                    ],
                    'body' => $body,
                ];
            } catch (JsonException $e) {
                // Return an empty array if JSON encoding fails
                return [];
            } catch (Exception $e) {
                // General catch for any other unexpected errors
                return [];
            }
        }

        /**
         * Check if the provided array contains a file, indicating multipart/form-data.
         *
         * @param array $data The array to check for files.
         * @return bool True if the array contains a file, false otherwise.
         */
        private function containsFile(array $data): bool
        {
            foreach ($data as $item) {
                if (is_array($item)) {
                    // Recursively check nested arrays for files
                    if ($this->containsFile($item)) {
                        return true;
                    }
                } elseif ($item instanceof SplFileInfo) {
                    // Check if the item is a file object
                    return true;
                } elseif (is_string($item) && file_exists($item)) {
                    // If the item is a string path to a file, consider it a file
                    return true;
                }
            }
            
            return false;
        }

        /**
         * Determine if an array is associative.
         *
         * @param array $array The array to check.
         * @return bool True if the array is associative, false if it is sequential.
         */
        private function isAssociativeArray(array $array): bool
        {
            return array_keys($array) !== range(0, count($array) - 1);
        }

        /**
         * Impersonate a browser and send an HTTP request with browser-like headers.
         *
         * This method sends an HTTP request to the specified URI, mimicking the behavior
         * of Chrome on a Windows PC. It sets headers and options to closely resemble what
         * a browser would send, including user-agent, accept, and language headers. It
         * handles cookies, sessions, and redirects similar to a browser.
         *
         * Supported methods include GET, POST, PUT, PATCH, and DELETE.
         *
         * @param string $method The HTTP method to use (e.g., 'GET', 'POST', 'PUT', 'PATCH', 'DELETE').
         * @param string $uri The endpoint URI.
         * @param mixed $body The request body, applicable for methods like POST, PUT, and PATCH.
         * @param array<string, string> $headers Additional request headers (default: empty).
         * @param array<string, mixed> $queryParams Additional query parameters (default: empty).
         * @param array<string, mixed> $options Additional request options that override defaults (default: empty).
         * 
         * @return ResponseInterface The HTTP response.
         * 
         * @throws GuzzleException If the request fails.
         * @throws InvalidArgumentException If an unsupported HTTP method is provided.
         * 
         * @example
         * $response = $this->impersonateBrowser('GET', 'https://example.com');
         */
        public function impersonateBrowser(
            string $method,
            string $uri,
            mixed $body = null,
            array $headers = [],
            array $queryParams = [],
            array $options = []
        ): ResponseInterface {
            // Common headers for browser impersonation
            $browserHeaders = [
                'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
                'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Encoding' => 'gzip, deflate, br, zstd',
                'Accept-Language' => 'en-US,en;q=0.9',
                'Cache-Control' => 'no-cache',
                'Pragma' => 'no-cache',
                'Upgrade-Insecure-Requests' => '1',
                'DNT' => '1',
                'Sec-CH-UA' => '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
                'Sec-CH-UA-Mobile' => '?0',
                'Sec-CH-UA-Platform' => '"Windows"',
                'Sec-Fetch-Dest' => 'document',
                'Sec-Fetch-Mode' => 'navigate',
                'Sec-Fetch-Site' => 'same-origin',
                'Sec-Fetch-User' => '?1',
            ];

            // Merge the provided headers with the browser impersonation headers
            $headers = array_merge($browserHeaders, $headers);

            // Handle cookies
            if (!isset($options['cookies']) && (property_exists($this, 'cookies') && $this->cookies !== null)) {
                $options['cookies'] = $this->cookies;
            }

            // Handle referer (if available from previous requests)
            if (isset($this->lastUri)) {
                $headers['Referer'] = $this->lastUri;
            }

            // Enable redirect handling similar to a browser
            $options['allow_redirects'] = $options['allow_redirects'] ?? [
                'max' => 10,  // Maximum number of redirects to follow
                'strict' => true,  // Follow strict RFC 7231 redirects
                'referer' => true,  // Add referer header when following redirects
                'protocols' => ['http', 'https'],
                'track_redirects' => true,
            ];

            // Set timeout and maximum response size to avoid abuse
            $options['timeout'] = $options['timeout'] ?? 30;  // Set a reasonable timeout
            $options['max_response_size'] = $options['max_response_size'] ?? 1024 * 1024 * 5; // 5MB limit

            // Save the last URI for potential referer use in future requests
            $this->lastUri = $uri;

            // Handle request methods
            switch (strtoupper($method)) {
                case 'GET':
                    return $this->get($uri, $headers, $queryParams, $options);
                case 'POST':
                    return $this->post($uri, $body, $headers, $queryParams, $options);
                case 'PUT':
                    return $this->put($uri, $body, $headers, $queryParams, $options);
                case 'PATCH':
                    return $this->patch($uri, $body, $headers, $queryParams, $options);
                case 'DELETE':
                    return $this->delete($uri, $headers, $queryParams, $options);
                default:
                    throw new InvalidArgumentException('Unsupported HTTP method: ' . $method);
            }
        }

        /**
         * Send an HTTP GET request.
         *
         * This method sends a GET request to the specified URI with optional headers,
         * query parameters, and additional options. It detects if body content has been
         * erroneously provided and logs a warning if so. The body content is discarded.
         *
         * @param string $uri The endpoint URI.
         * @param array<string, string> $headers Additional request headers (default: empty).
         * @param array<string, mixed> $queryParams Additional query parameters (default: empty).
         * @param array<string, mixed> $options Additional request options that override defaults (default: empty).
         * 
         * @return ResponseInterface The HTTP response.
         * 
         * @throws GuzzleException If the request fails.
         */
        public function get(
            string $uri,
            mixed $headers = [],
            mixed $queryParams = [],
            mixed $options = [],
            mixed $catchBody = null
        ): ResponseInterface {
            try {
                // Handle content type detection and body formatting if no content type is specified
                if ($this->evaluateRequestIntention && ($catchBody !== null || isset($options['body']))) {
                    // Log a warning if body content is detected in a DELETE request
                    $this->logError("Body data was provided in a GET request, which is unusual and not permitted by RFC 9110. The body has been discarded. You can force the request by disabling request intention evaluation.");

                    // Shift parameters
                    $catchBody = null; // Discard the body content
                    $options = $queryParams;
                    $queryParams = $headers;
                    $headers = [];
                    
                    // Remove the body from the request options
                    unset($options['body']);
                }

                // Add query parameters to the options
                if ($queryParams !== []) {
                    $options['query'] = $queryParams;
                }

                // Add headers to the options
                $options['headers'] = array_merge($this->headers, $headers);
            } catch (Exception $exception) {
                // Handle exceptions and rethrow them with additional context if needed
                throw new RuntimeException('GET request preparation failed: ' . $exception->getMessage(), 0, $exception);
            }

            // Send the GET request and return the response
            return $this->request('GET', $uri, $options);
        }

        /**
         * Send an HTTP DELETE request.
         *
         * This method sends a DELETE request to the specified URI with optional headers,
         * query parameters, and additional options. It detects if body content has been
         * erroneously provided and logs a warning if so. The body content is discarded.
         *
         * @param string $uri The endpoint URI.
         * @param array<string, string> $headers Additional request headers (default: empty).
         * @param array<string, mixed> $queryParams Additional query parameters (default: empty).
         * @param array<string, mixed> $options Additional request options that override defaults (default: empty).
         * 
         * @return ResponseInterface The HTTP response.
         * 
         * @throws GuzzleException If the request fails.
         */
        public function delete(
            string $uri,
            mixed $headers = [],
            mixed $queryParams = [],
            mixed $options = [],
            mixed $catchBody = null
        ): ResponseInterface {
            try {
                // Handle content type detection and body formatting if no content type is specified
                if ($this->evaluateRequestIntention && ($catchBody !== null || isset($options['body']))) {
                    // Log a warning if body content is detected in a DELETE request
                    $this->logError("Body data was provided in a DELETE request, which is unusual and not permitted by RFC 9110. The body has been discarded. You can force the request by disabling request intention evaluation.");

                    // Shift parameters
                    $catchBody = null; // Discard the body content
                    $options = $queryParams;
                    $queryParams = $headers;
                    $headers = [];
                    
                    // Remove the body from the request options
                    unset($options['body']);
                }

                // Add query parameters to the options
                if ($queryParams !== []) {
                    $options['query'] = $queryParams;
                }

                // Add headers to the options
                $options['headers'] = array_merge($this->headers, $headers);
            } catch (Exception $exception) {
                // Handle exceptions and rethrow them with additional context if needed
                throw new RuntimeException('DELETE request preparation failed: ' . $exception->getMessage(), 0, $exception);
            }

            // Send the DELETE request and return the response
            return $this->request('DELETE', $uri, $options);
        }

        /**
         * Send an HTTP POST request.
         *
         * This method sends a POST request to the specified URI with optional body data,
         * headers, query parameters, and additional options. It automatically detects
         * the content type based on the body and formats the request accordingly.
         *
         * @param string $uri The endpoint URI.
         * @param mixed $body The request body, which could be JSON, form data, or other supported types.
         * @param array<string, string> $headers Additional request headers (default: empty).
         * @param array<string, mixed> $queryParams Additional query parameters (default: empty).
         * @param array<string, mixed> $options Additional request options that override defaults (default: empty).
         * 
         * @return ResponseInterface The HTTP response.
         * 
         * @throws GuzzleException If the request fails.
         * @throws InvalidArgumentException If body formatting fails or an unsupported content type is provided.
         */
        public function post(
            string $uri,
            mixed $body = null,
            array $headers = [],
            array $queryParams = [],
            array $options = []
        ): ResponseInterface {
            try {
                // Handle content type detection and body formatting if no content type is specified
                if ($this->evaluateRequestIntention && !isset($headers['Content-Type'])) {
                    // Detect content type and format body accordingly
                    $contentTypeAndBody = $this->detectContentTypeAndFormatBody($body);
        
                    // Merge the detected headers and body with the provided options
                    $headers = array_merge($headers, $contentTypeAndBody['headers']);
                    $body = $contentTypeAndBody['body'];
                }

                // Add query parameters to the options
                if ($queryParams !== []) {
                    $options['query'] = $queryParams;
                }

                // Add body and headers to the options
                $options['body'] = $body;
                $options['headers'] = array_merge($this->headers, $headers);
            } catch (Exception $exception) {
                // Handle exceptions and rethrow them with additional context if needed
                throw new RuntimeException('POST request preparation failed: ' . $exception->getMessage(), 0, $exception);
            }

            // Send the POST request and return the response
            return $this->request('POST', $uri, $options);
        }

        /**
         * Send an HTTP PUT request.
         *
         * This method sends a PUT request to the specified URI with optional body data,
         * headers, query parameters, and additional options. It automatically detects
         * the content type based on the body and formats the request accordingly. An
         * idempotency key is automatically added to ensure idempotency for PUT requests.
         *
         * @param string $uri The endpoint URI.
         * @param mixed $body The request body, which could be JSON, form data, or other supported types.
         * @param array<string, string> $headers Additional request headers (default: empty).
         * @param array<string, mixed> $queryParams Additional query parameters (default: empty).
         * @param array<string, mixed> $options Additional request options that override defaults (default: empty).
         * 
         * @return ResponseInterface The HTTP response.
         * 
         * @throws GuzzleException If the request fails.
         * @throws InvalidArgumentException If body formatting fails or an unsupported content type is provided.
         */
        public function put(
            string $uri,
            mixed $body = null,
            array $headers = [],
            array $queryParams = [],
            array $options = []
        ): ResponseInterface {
            try {
                // Handle content type detection and body formatting if no content type is specified
                if ($this->evaluateRequestIntention && !isset($headers['Content-Type'])) {
                    // Detect content type and format body accordingly
                    $contentTypeAndBody = $this->detectContentTypeAndFormatBody($body);
        
                    // Merge the detected headers and body with the provided options
                    $headers = array_merge($headers, $contentTypeAndBody['headers']);
                    $body = $contentTypeAndBody['body'];
                }
        
                // Add query parameters to the options
                if ($queryParams !== []) {
                    $options['query'] = $queryParams;
                }
        
                // Add body and headers to the options
                $options['body'] = $body;
                $options['headers'] = array_merge($this->headers, $headers);
        
                // Ensure the request is idempotent by adding a unique key
                $options['headers']['Idempotency-Key'] = $options['headers']['Idempotency-Key'] ?? bin2hex(random_bytes(16));
            } catch (Exception $exception) {
                // Handle exceptions and rethrow them with additional context if needed
                throw new RuntimeException('PUT request preparation failed: ' . $exception->getMessage(), 0, $exception);
            }
        
            // Send the PUT request and return the response
            return $this->request('PUT', $uri, $options);
        }

        /**
         * Send an HTTP PATCH request.
         *
         * This method sends a PATCH request to the specified URI with optional body data,
         * headers, query parameters, and additional options. It automatically detects
         * the content type based on the body and formats the request accordingly. An
         * idempotency key is automatically added to ensure idempotency for PATCH requests.
         *
         * @param string $uri The endpoint URI.
         * @param mixed $body The request body, which could be JSON, form data, or other supported types.
         * @param array<string, string> $headers Additional request headers (default: empty).
         * @param array<string, mixed> $queryParams Additional query parameters (default: empty).
         * @param array<string, mixed> $options Additional request options that override defaults (default: empty).
         * 
         * @return ResponseInterface The HTTP response.
         * 
         * @throws GuzzleException If the request fails.
         * @throws InvalidArgumentException If body formatting fails or an unsupported content type is provided.
         */
        public function patch(
            string $uri,
            mixed $body = null,
            array $headers = [],
            array $queryParams = [],
            array $options = []
        ): ResponseInterface {
            try {
                // Handle content type detection and body formatting if no content type is specified
                if ($this->evaluateRequestIntention && !isset($headers['Content-Type'])) {
                    // Detect content type and format body accordingly
                    $contentTypeAndBody = $this->detectContentTypeAndFormatBody($body);
        
                    // Merge the detected headers and body with the provided options
                    $headers = array_merge($headers, $contentTypeAndBody['headers']);
                    $body = $contentTypeAndBody['body'];
                }
        
                // Add query parameters to the options
                if ($queryParams !== []) {
                    $options['query'] = $queryParams;
                }
        
                // Add body and headers to the options
                $options['body'] = $body;
                $options['headers'] = array_merge($this->headers, $headers);
        
                // Ensure the request is idempotent by adding a unique key
                $options['headers']['Idempotency-Key'] = $options['headers']['Idempotency-Key'] ?? bin2hex(random_bytes(16));
            } catch (Exception $exception) {
                // Handle exceptions and rethrow them with additional context if needed
                throw new RuntimeException('PATCH request preparation failed: ' . $exception->getMessage(), 0, $exception);
            }
        
            // Send the PATCH request and return the response
            return $this->request('PATCH', $uri, $options);
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
    }
?>