# 🚒 Common API Utilities

Welcome to the **Common API Utilities** repository! This repository contains a set of utility scripts used by publically-facing State Emergency Service (SES) APIs. These utilities provide common functions like CORS handling, response management, and sanitization - all crucial for robust and secure API services.

We've also created the [`APIManager` class](./APIManager/), which is a powerful, robust, and secure PHP class for managing various API-related tasks, including:

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

## 📂 Repository Structure

Here's a brief overview of the repository files:

- dfes-ses/common-api-utilities
  - **`APIManager/`**
    - **[`class.php`](./APIManager/class.php)**: APIManager class for managing utilities in a single interface
    - **[`loader.json`](./APIManager/loader.json)**: Configuration file for loading utilities in APIManager
  - **[`README.md`](./README.md)**: This documentation
  - **[`composer.json`](./composer.json)**: Dependencies for the utilities, managed via Composer
  - **[`.deployignore`](./deployignore)**: A `.gitignore`-style file for specifying files which should be ignored in production repo clones
  - **`linting/`**
    - *Various linting resources for development - not required in production*
  - **`src/`**
    - **[`CORS.php`](./src/CORS.php)**: Handles Cross-Origin Resource Sharing (CORS) to ensure secure API interactions
    - **[`responseManager.php`](./src/responseManager.php)**: Manages API responses in a standardized and consistent manner
    - **[`sanitize.php`](./src/sanitize.php)**: Sanitizes input to prevent security vulnerabilities such as SQL injection and XSS

## ⚙️ Dependencies

We utilize several key packages to enhance the functionality, security, and performance of our utilities:

- **[MeekroDB](https://github.com/SergeyTsalkov/meekrodb)**: A lightweight, easy-to-use MySQL database library. (v3.0+)
- **[Guzzle](https://github.com/guzzle/guzzle)**: A PHP HTTP client for sending HTTP requests. (v7.9+)
- **[Monolog](https://github.com/Seldaek/monolog)**: A logging library that sends your logs to files, sockets, inboxes, databases, etc. (v3.7+)
- **[libphonenumber-for-php](https://github.com/giggsey/libphonenumber-for-php)**: A library for parsing, formatting, and validating international phone numbers. (v8.13+)
- **[ULID](https://github.com/robinvdvleuten/ulid)**: A library for generating ULIDs (Universally Unique Lexicographically Sortable Identifiers). (v5.0+)
- **[phpdotenv](https://github.com/vlucas/phpdotenv)**: A library for loading environment variables from a `.env` file into `$_ENV` and `$_SERVER`. (v5.6+)
- **[Carbon](https://github.com/briannesbitt/Carbon)**: An extension for PHP DateTime to handle dates and times effectively. (v3.8+)
- **[Symfony Validator](https://github.com/symfony/validator)**: A powerful library for validating data. (v7.1+)
- **[Flysystem](https://github.com/thephpleague/flysystem)**: A filesystem abstraction layer that allows you to work with local filesystems, SFTP, Amazon S3, and more. (v3.0+)
- **[lcobucci/jwt](https://github.com/lcobucci/jwt)**: A PHP library to generate, parse, and validate JSON Web Tokens (JWT). (v4.0+)
- **[Symfony Rate Limiter](https://github.com/symfony/rate-limiter)**: A rate-limiting component for preventing excessive API usage. (v7.1+)
- **[Symfony Security CSRF](https://github.com/symfony/security-csrf)**: Provides CSRF protection to prevent cross-site request forgery attacks. (v7.1+)
- **[phpseclib](https://github.com/phpseclib/phpseclib)**: A pure PHP library for encryption, decryption, and other security operations. (v3.0+)

**Note:** `thephpleague/flysystem` requires the `fileinfo` extension to be enabled in PHP to function properly. More info: [php.net/manual/en/fileinfo.inst...](https://www.php.net/manual/en/fileinfo.installation.php)

To install all dependencies, run:

```bash
composer install
```

## 🛠️ Usage

You can either use the individual functions and classes provided in the `src/` directory or opt for the [`APIManager` class](./APIManager/), which integrates all utilities into a single class. The choice is yours!

### 1. CORS Handling ([`cors.php`](./cors.php))

To handle CORS in your API, use the `CORS()` function to allow requests from specific origins.

```php
require_once 'cors.php';

// Example: Allow requests from specific origins
CORS(['https://example.com', 'https://another-allowed-origin.com']);

// Example: No origins allowed (default behavior)
CORS();
```

The function handles Cross-Origin Resource Sharing (CORS) securely by sending appropriate headers. It checks the origin of the request and only allows approved origins. Preflight OPTIONS requests are handled, and security errors are logged for disallowed origins.

### 2. Response Management ([`responseManager.php`](./responseManager.php))

Use the `ApiResponseManager` class to manage API responses with consistent JSON formatting and security headers.

```php
require_once 'responseManager.php';

// Example: Sending a successful response with data and messages
$responseManager = new ApiResponseManager();
$responseManager->addGlobalMessage("Operation successful.");
$responseManager->respondToClient(true, ["result" => "success"]);

// Example: Handling an error and bailing out
$responseManager = new ApiResponseManager();
$responseManager->addGlobalError("Invalid data provided.");
$responseManager->bailOut(422); // Unprocessable Entity
```

This class helps manage global messages and errors, ensuring that your API responses are consistent, secure, and structured as JSON.

### 3. Sanitization ([`sanitize.php`](./sanitize.php))

Use the `sanitize()` function to clean and process user input, ensuring it is safe for use in your application.

```php
require_once 'sanitize.php';

// Example: Sanitize and trim a string
$cleanInput = sanitize($userInput);

// Example: Sanitize and truncate input to a maximum length
$cleanInput = sanitize($userInput, 100);
```

This function sanitizes input strings, trims whitespace, and optionally truncates to a specified length. It also validates that the input is UTF-8 encoded and within a safe length limit.

## 🧰 APIManager Class (Optional)

For those looking for a more integrated approach, we offer the `APIManager` class, which consolidates the utilities into a single, configurable class. You can still use the standalone functions directly from the `src/` directory if you prefer.

### How to Use the APIManager

The `APIManager` class handles Composer autoloading, CORS, response management, logging, and more. It's designed to make your API management easier and more secure.

To use the `APIManager` in your files:

```php
require_once 'path/to/APIManager.php';

$apiManager = new APIManager([
    // Example: Enable CORS and response management
    'useUtilities' => ['CORS', 'responseManager'],
]);

// Example: Use the response manager
$responseManager = $apiManager->getResponseManager();
$responseManager->respondToClient(true, ['data' => 'success']);


## 🛡️ Security Considerations

Security is our top priority. The utilities in this repository have been developed with secure coding practices, and we follow relevant NIST and industry standards. For example:

- **Input sanitization** helps protect against SQL injection and cross-site scripting (XSS).
- **CORS handling** ensures that only trusted domains can interact with our APIs.

We encourage developers to regularly review and update their security practices. Check out the [PHP Security Best Practices](https://phptherightway.com/#security), [PHP Security Docs](https://www.php.net/manual/en/security.php), and [PHP Type Safety Topic](https://thephp.cc/topics/type-safety) resources for more information.

## 🤝 Contributing

We welcome contributions to improve the utilities in this repository. Please submit your pull requests, ensuring that your code adheres to best practices for security and performance.

## 🔍 License

This repository is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

| Permissions                        | Limitations                      | Conditions                         |
| ---------------------------------- | --------------------------------- | ---------------------------------- |
| ✔️ Commercial use                  | ❌ Trademark use                  | ℹ️ License and copyright notice    |
| ✔️ Modification                    | ❌ Liability                      | ℹ️ State changes                   |
| ✔️ Distribution                    | ❌ Warranty                       |                                    |
| ✔️ Patent use                      |                                   |                                    |
| ✔️ Private use                     |                                   |                                    |

For more details, please refer to the [Apache License 2.0](LICENSE).

## 🎉 Acknowledgments

- Maintained by the dedicated Strategic Application Services Team (SAST) at the [**State Emergency Service**](https://wases.com.au).
- Special thanks to the contributors and dependency managers who help make this project better every day, indirectly supporting and securing our frontline personnel.

Feel free to check out the [documentation](https://github.com/dfes-ses/common-api-utilities/wiki) for more details on each utility.
