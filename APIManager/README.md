# APIManager.php 🚀

A robust and secure PHP class for managing various API-related tasks, including:

- **Composer autoloading**
- **Dynamic dependency loading**
- **CORS headers**
- **Response management**
- **Error logging**
- **Security headers**
- **Input sanitization**
- **JSON handling**
- **CSRF protection**
- **Rate limiting**

This class is designed to be highly configurable, secure, and performant for API-driven applications. It integrates with key packages to enhance security and manage common API tasks.

## 🌟 Features

- **🔒 Security**: Secure file inclusion, CORS handling, and security headers are built-in to protect your application.
- **⚙️ Flexibility**: Configure options for CORS, rate limiting, and CSRF protection, or disable them entirely if needed.
- **🛠 Utility Functions**: Useful functions like JSON handling, input sanitization, and secure file inclusion are ready to use.

## ⚙️ Configuration Options

The `APIManager` constructor accepts an array of configuration options to control its behavior:

- `disableCORS`: Disable CORS headers.
- `disableResponseManager`: Disable response management.
- `disableRateLimiter`: Disable rate limiting.
- `disableCsrfManager`: Disable CSRF protection.
- `customHeaders`: Array of custom security headers to apply.
- `corsOptions`: Array of configuration options for CORS handling.
- `rateLimiterConfig`: Custom configuration options for the rate limiter.
- `csrfConfig`: Custom configuration options for CSRF management.
- `useUtilities`: Array of utility names defined in `loader.json`.

## 🛠 Public Methods

### `requireFile(string $filePath, bool $force = false)`

Securely requires a file. Supports referencing the document root with `"@/"`. Includes security checks to prevent importing files outside the document root unless explicitly forced.

**Example Usage:**

```php
$apiManager->requireFile('@/path/to/file.php');
$apiManager->requireFile('/absolute/path/to/file.php', true);
```

### `requireOnceFile(string $filePath, bool $force = false)`

Same as `requireFile`, but uses `require_once`.

**Example Usage:**

```php
$apiManager->requireOnceFile('@/path/to/file.php');
$apiManager->requireOnceFile('/absolute/path/to/file.php', true);
```

### `getResponseManager(): ?ApiResponseManager`

Retrieves the initialized response manager, if it has been set up.

**Example Usage:**

```php
$responseManager = $apiManager->getResponseManager();
$responseManager->respondToClient(true, ['data' => 'success']);
```

### `getRateLimiterFactory(): ?RateLimiterFactory`

Retrieves the initialized rate limiter factory, if it has been set up.

**Example Usage:**

```php
$rateLimiter = $apiManager->getRateLimiterFactory();
```

### `getCsrfTokenManager(): ?CsrfTokenManager`

Retrieves the initialized CSRF token manager, if it has been set up.

**Example Usage:**

```php
$csrfManager = $apiManager->getCsrfTokenManager();
```

### `sanitizeInput(string $input): string`

Sanitizes input by trimming whitespace and encoding special characters. Helps prevent XSS attacks.

**Example Usage:**

```php
$sanitized = $apiManager->sanitizeInput('<script>alert("XSS")</script>');
```

### `decodeJson(string $json): array`

Decodes a JSON string into a PHP array with error handling. Throws an exception if the JSON is invalid.

**Example Usage:**

```php
$data = $apiManager->decodeJson('{"key": "value"}');
```

### `encodeJson(array $data): string`

Encodes a PHP array into a JSON string with error handling. Throws an exception if encoding fails.

**Example Usage:**

```php
$json = $apiManager->encodeJson(['key' => 'value']);
```

### `getSanitizedGet(string $key): ?string`

Retrieves sanitized input from the `$_GET` superglobal.

**Example Usage:**

```php
$sanitizedValue = $apiManager->getSanitizedGet('param');
```

### `getSanitizedPost(string $key): ?string`

Retrieves sanitized input from the `$_POST` superglobal.

**Example Usage:**

```php
$sanitizedValue = $apiManager->getSanitizedPost('param');
```

### `getJsonPayload(): array`

Retrieves the JSON payload from the request body and decodes it into a PHP array.

**Example Usage:**

```php
$payload = $apiManager->getJsonPayload();
```

### `setNewHeader(string $headerName, string $headerValue): void`

Sets a new HTTP header for the response.

**Example Usage:**

```php
$apiManager->setNewHeader('X-Custom-Header', 'MyValue');
```

## 🔧 Example Usage

### Basic Initialization

```php
$apiManager = new APIManager([
    'useUtilities' => ['CORS'],
]);

$responseManager = $apiManager->getResponseManager();
$responseManager->respondToClient(true, ['data' => 'success']);
```

### Custom Headers and CORS Configuration

```php
$apiManager = new APIManager([
    'customHeaders' => ['X-Custom-Header' => 'CustomValue'],
    'corsOptions' => ['allowedOrigins' => ['https://example.com']],
]);

$apiManager->setNewHeader('X-Additional-Security', 'Enabled');
```

### Disabling Features

```php
$apiManager = new APIManager([
    'disableRateLimiter' => true,
    'disableCsrfManager' => true,
]);

$responseManager = $apiManager->getResponseManager();
$responseManager->addGlobalMessage("Some feature is disabled.");
$responseManager->respondToClient(true, ['feature_status' => 'disabled']);
```

## 🚨 Environment Variables

- **`DOCUMENT_ROOT_PATH`**: The document root directory (default: `/var/www/`).
- **`COMPOSER_AUTOLOAD_PATH`**: The environment variable that defines the path to the Composer autoload file (default: `/var/www/vendor/autoload.php`).
- **`LOGS_PATH`**: Directory for storing logs (default: `/var/log/`).
- **`ENFORCE_SAFE_REQUIRES`**: If `true`, file inclusion outside of the document root is forbidden.

## ✨ Conclusion

The `APIManager` class provides a powerful and flexible foundation for building secure and performant APIs in PHP. By combining Composer dependency management, CORS handling, response management, and security features, this class helps streamline development while ensuring best practices are followed.

Feel free to contribute or raise issues in the repository. Happy coding! 🎉