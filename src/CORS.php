<?php
    /**
     * Handles Cross-Origin Resource Sharing (CORS) requests in a secure and flexible manner.
     * This function sends the necessary headers to allow cross-origin requests from approved origins.
     *
     * @param array|null $allowedOrigins An array of allowed origins. If null or empty, no origins are allowed.
     *                                   The origins must be fully qualified domain names (e.g., https://example.com).
     * @throws Exception If an unsupported HTTP method is requested during preflight OPTIONS checks.
     */
    function CORS(?array $allowedOrigins = null): void
    {
        // Ensure that headers have not been sent already
        if (headers_sent()) {
            error_log("Headers already sent, cannot set CORS headers.");
            return;
        }

        // If allowedOrigins is not provided or is empty, default to an empty array (no allowed origins).
        $allowedOrigins = $allowedOrigins ?? [];

        // Ensure the $_SERVER superglobal contains the required keys
        if (!isset($_SERVER['HTTP_ORIGIN']) || !isset($_SERVER['REQUEST_METHOD'])) {
            error_log("Missing HTTP_ORIGIN or REQUEST_METHOD in the request.");
            http_response_code(400);  // Bad Request
            exit('Bad Request');
        }

        // Sanitize the Origin header
        $origin = filter_var($_SERVER['HTTP_ORIGIN'], FILTER_SANITIZE_URL);

        // Check if the origin is in the allowed list
        if (in_array($origin, $allowedOrigins, true)) {
            // Allow requests from this origin
            header("Access-Control-Allow-Origin: $origin");
            header('Access-Control-Allow-Credentials: true');
            header('Access-Control-Max-Age: 86400');  // Cache for 1 day
        } else {
            // Log disallowed origin attempt
            error_log("Disallowed CORS origin: $origin");

            // If the origin is not allowed, send a 403 Forbidden response
            http_response_code(403);
            exit('Origin not allowed');
        }

        // Handle preflight requests (OPTIONS method)
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            // Check if the request method is allowed
            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])) {
                $allowedMethods = ['GET', 'POST', 'OPTIONS'];  // Add more allowed methods as needed

                // Validate the requested method
                $requestMethod = strtoupper($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']);
                if (in_array($requestMethod, $allowedMethods, true)) {
                    header("Access-Control-Allow-Methods: " . implode(', ', $allowedMethods));
                } else {
                    error_log("Unsupported HTTP method requested in preflight: $requestMethod");
                    throw new Exception('Unsupported HTTP method requested in preflight.');
                }
            }

            // Check if custom headers are being requested
            if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])) {
                $allowedHeaders = filter_var($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'], FILTER_SANITIZE_STRING);
                header("Access-Control-Allow-Headers: $allowedHeaders");
            }

            // End the preflight OPTIONS request
            exit(0);
        }
    }

    /**
     * Example usage:
     * 
     * // Allow requests from specific origins
     * CORS(['https://example.com', 'https://another-allowed-origin.com']);
     * 
     * // No origins allowed (default behavior)
     * CORS();
     */
?>
