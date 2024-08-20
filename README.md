# APIManager 📦

**APIManager** is a robust PHP package that simplifies API development by providing utilities for handling CORS, managing API responses, implementing rate limiting, securing your API with security headers, sanitizing input, and much more. 🚀

## Features 🎯

- 🌐 **CORS Management**: Easily configure Cross-Origin Resource Sharing (CORS) rules.
- 🛡️ **Security Headers**: Apply essential security headers to safeguard your API.
- 📊 **Rate Limiting**: Implement rate limiting with customizable policies.
- 📋 **CSRF Protection**: Secure your forms with CSRF token management.
- 🗄️ **Response Management**: Structure your API responses and handle errors consistently.
- 🧹 **Input Sanitization**: Clean and sanitize user input.
- 🔄 **Custom Headers**: Add or remove custom headers in your API responses.

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
);
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

## License 📄

This package is open-source and available under the [Apache 2.0 License](LICENSE).

## Contributions 🤝

Contributions are welcome! Feel free to submit issues and pull requests.

## Contact 💬

For any questions or support, please raise an Issue.

Happy Coding! 😄