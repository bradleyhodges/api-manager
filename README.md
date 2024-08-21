# APIManager 📦

**APIManager** is a robust PHP package that simplifies API development by providing utilities for handling CORS, managing API responses, implementing rate limiting, securing your API with security headers, sanitizing input, and much more. 🚀

## Features 🎯

- 🌐 **CORS Management**: Easily configure Cross-Origin Resource Sharing (CORS) rules.
- 🌐 **Advanced HTTP Client**: Send HTTP requests with support for Happy Eyeballs, DNS caching, HTTP/1, 2, and 3*, and more.
- 📊 **Rate Limiting**: Implement rate limiting with customizable policies.
- 🗄️ **Response Management**: Structure your API responses and handle errors consistently.
- 🧹 **Input Sanitization**: Clean and sanitize user input.
- 🔄 **Custom Headers**: Add or remove custom headers in your API responses.
- 📋 **CSRF Protection**: Secure your forms with CSRF token management.
- 🛡️ **Security Headers**: Apply essential security headers to safeguard your API.

## Installation 🛠️

Install the package via Composer:

```bash
composer require bradleyhodges/api-manager
```

or you can manually add it to your `composer.json`:

```json
{
    "repositories": [
      {
        "type": "vcs",
        "url": "https://github.com/dfes-ses/api-manager.git"
      }
    ],
    "require": {
        "bradleyhodges/api-manager": "dev-main"
    },
    "minimum-stability": "dev",
    "prefer-stable": true
}
```

## Usage 📝

### Basic Setup

```php
use APIManager\APIManager;

// Initialize the APIManager
$apiManager = new APIManager();
```

### HTTP Client Usage 🌐

The `HTTP` class provides a powerful HTTP client built on top of [Guzzle](https://github.com/guzzle/guzzle), with support for Happy Eyeballs, DNS caching, HTTP/1, 2, and 3, retry logic, and more.

Some really neat features and enhancements are enabled by default, including:

- **Happy Eyeballs Algorithm**: This optimizes connection speed by attempting to connect to both IPv4 and IPv6 addresses simultaneously, selecting the one that responds the quickest. This ensures minimal latency, especially in environments where network configurations might favor one protocol over the other.

- **DNS Caching**: DNS responses are cached for faster subsequent requests, reducing the overhead of repeated DNS lookups. This is especially useful for APIs with high traffic, as it cuts down on repeated DNS resolution time and improves response times.

- **HTTP/3 Fallback**: By default, the client attempts to use HTTP/3 for faster and more reliable connections. If HTTP/3 is unavailable, it automatically falls back to HTTP/2 or HTTP/1.1, ensuring compatibility with a wide range of server configurations.

- **Automatic Retry with Exponential Backoff**: The client can be configured to automatically retry failed requests (such as network timeouts or server errors). The retry logic includes exponential backoff with jitter, minimizing the chances of overloading the server with repeated requests in rapid succession.

- **TLS Enforcement**: For security, the client enforces a minimum TLS version of 1.2, ensuring that all connections are secure and compliant with modern security standards (can be overriden using `$http->useMinTlsVersion(false);`).

- **Customizable DNS Resolver**: By default, the client uses Cloudflare's `1.1.1.1` DNS resolver for faster and more secure DNS lookups. This can be toggled off if the system's default DNS resolver is preferred.

- **Cookie Management**: The client includes a `CookieJar` by default, allowing for stateful HTTP requests with cookie management across multiple requests. This is useful for interacting with APIs that require session management.

These features are highly configurable and can be enabled or disabled based on your specific needs, giving you full control over how your HTTP requests are handled.

Here's a basic usage example:

```php
use APIManager\HTTP;

// Initialize the HTTP client
$http = new HTTP();

// Send a GET request
$response = $http->get('/endpoint');

// Get the response body
$body = $response->getBody()->getContents();

// Get the response code and reason phrase
$responseCode = $response->getStatusCode(); // 200
$responseReason = $response->getReasonPhrase(); // OK

// More methods and examples at https://docs.guzzlephp.org/en/stable/quickstart.html#using-responses
// Just replace `$client` with `$http` to use them
```

You can also configure advanced options such as retries, DNS caching, and HTTP version fallback:

```php
$http->useRetry(true)
     ->useDnsCache(true)
     ->useHttpVersionFallback(true);

// Send a POST request with a Bearer token
$http->setBearerToken('your-token-here');
$response = $http->post('/submit', ['json' => ['key' => 'value']]);
```

Because the HTTP Class is built on top of Guzzle, you can optionally pass your custom Guzzle config:

```php
use APIManager\HTTP;

$http = new HTTP([
    // Base URI is used with relative requests
    'base_uri' => 'http://httpbin.org',
    // You can set any number of default request options.
    'timeout'  => 2.0,
]);
```

If you'd prefer to access [Guzzle's methods](https://docs.guzzlephp.org/en/stable/quickstart.html) directly, you can use the `getClient` method to access the Guzzle client instance and call it's methods as usual:

```php
use APIManager\HTTP;

// Initialize the HTTP client
$http = new HTTP();

// Access the Guzzle client instance
$client = $http->getClient();

// Send an asynchronous request using Guzzle's magic methods:
$promise = $client->getAsync('http://httpbin.org/get');
```

### CORS Configuration 🌐

The CORS implementation is **RFC 6454 compliant** and "just works" with minimal configuration. Simply specify the allowed origins, and the rest is handled for you. If you need more control, you can optionally configure other aspects like allowed methods, headers, and credentials:

```php
$apiManager->useCORS([
  'allowedOrigins' => ['https://example.com'],
  'allowCredentials' => true,
  'allowedMethods' => ['GET', 'POST', 'OPTIONS'],
  'allowedHeaders' => ['Content-Type', 'Authorization'],
  'exposedHeaders' => ['X-Custom-Header'],
  'maxAge' => 3600,
]);
```

```php
$apiManager->useCORS([
  'allowedOrigins' => ['https://example.com'],
]);
```

### API Response Management 📋

**APIManager** implements the **JSON:API (v1.1) specification** for response formats, ensuring that your API responses follow a standardized format. This makes it easier to integrate with other services and clients that expect JSON:API-compliant responses:

```php
$responseManager = $apiManager->responseManager();

// Add a message to the response
$responseManager->addMessage('Hello, world!');

// Add an error to the response
$responseManager->addError([
  'status' => "422",
  'source' => ['pointer' => '/data/attributes/first-name'],
  'title' => 'Invalid Attribute',
  'detail' => 'First name must contain at least three characters.',
]);

// Respond with data
$responseManager->respond(true, ['some key' => 'some value']); // Successful response

// Respond with an error
$responseManager->respond(false, [], 400); // Error response with optional status code
```

### Rate Limiting 📊

Rate limiting works **out of the box** with **no configuration needed**. Simply calling `useRateLimiter()` will automatically protect your pages from excessive requests. You can customize the configuration if needed, but the default settings are designed to work without any additional setup:

```php
$apiManager->useRateLimiter();
```

```php
$apiManager->useRateLimiter([
  'id' => 'api_limit',
  'policy' => 'sliding_window',
  'limit' => 100,
  'interval' => '1 minute',
]);
```

### CSRF Protection 🛡️

```php
$apiManager->useCsrfManager();
```

### Automatic Security Headers and Header Customisation 🛡️

```php
// Adding a custom header
$apiManager->addHeader('X-Custom-Header', 'CustomValue');

// Removing or preventing a header
$apiManager->removeHeader('X-Frame-Options');
```

### Input Sanitization 🧹

```php
echo $apiManager->sanitizeInput('some input');
```

## Public Methods Overview 📖

### `APIManager`

- **`useCORS(array $config)`**: Configure CORS settings for your API.
- **`responseManager()`**: Get the instance of `ApiResponseManager` to manage responses.
- **`useRateLimiter(array $config)`**: Set up rate limiting for your API.
- **`useCsrfManager()`**: Initialize CSRF protection.
- **`useSecurityHeaders(array $headers)`**: Apply security headers to API responses.
- **`addHeader(string $name, string $value)`**: Add a custom header to the response.
- **`removeHeader(string $name)`**: Remove or prevent a header from being sent in the response.
- **`sanitizeInput(string $input, int $maxLength = null)`**: Sanitize and clean input data.

### `ApiResponseManager`

- **`addMessage(string $message)`**: Add a message to the response.
- **`addError(array $error)`**: Add an error to the response.
- **`respond(bool $success, array $data = [], int $statusCode = 200)`**: Send the response to the client with the provided data and status code.

### `ErrorLogger`

- **`logError(string $message, array $context = [])`**: Log an error with detailed information.
- **`logCritical(string|Throwable $error)`**: Log a critical error or exception.
- **`logInfo(string $message)`**: Log an informational message.

### `HTTP`

- **`request(string $method, string $uri, array $options = [])`**: Send a request to the specified URI, using the given method, with optional configuration. See [Guzzle 7 docs](https://docs.guzzlephp.org/en/stable/quickstart.html) for available configuration and other methods.
- **`get(string $uri, array $options = [])`**: Shorthand method for `request('GET', ...);`
- **`post(string $uri, array $options = [])`**: Shorthand method for `request('POST', ...);`
- **`put(string $uri, array $options = [])`**: Shorthand method for `request('PUT', ...);`
- **`delete(string $uri, array $options = [])`**: Shorthand method for `request('DELETE', ...);`
- **`patch(string $uri, array $options = [])`**: Shorthand method for `request('PATCH', ...);`
- **`setDefaultHeaders(array $headers)`**: Set default headers for all requests.
- **`setBearerToken(string $token)`**: Set a Bearer token for authorization.
- **`setBasicAuth(string $username, string $password)`**: Set Basic Authentication credentials.
- **`addQueryParameters(array $params)`**: Add global query parameters for all requests.
- **`cookieJar(): CookieJar`**: Retrieve the CookieJar instance for managing cookies.
- **`useHappyEyeballs(bool $enabled)`**: Enable or disable the Happy Eyeballs algorithm for faster connections.
- **`useRetry(bool $enabled)`**: Enable or disable the retry mechanism with exponential backoff.
- **`useDnsCache(bool $enabled)`**: Enable or disable DNS caching.
- **`useHttpVersionFallback(bool $enabled)`**: Enable or disable HTTP version fallback (HTTP/3 -> HTTP/2 -> HTTP/1.1).
- **`useMinTlsVersion(bool $enabled)`**: Enable or disable the enforcement of minimum TLS version 1.2.
- **`useCloudflareDns(bool $enabled)`**: Enable or disable the use of Cloudflare's DNS resolver.
- **`useCookieJar(bool $enabled)`**: Enable or disable the use of a CookieJar for managing cookies.

## License 📄

This package is open-source and available under the [Apache 2.0 License](LICENSE).

## Contributions 🤝

Contributions are welcome! Feel free to submit issues and pull requests.

## Contact 💬

For any questions or support, please raise an Issue.

Happy Coding! 😄