<?php
    namespace APIManager;

    use Exception;
    use Monolog\Logger;
    use Monolog\Handler\StreamHandler;
    use Monolog\Formatter\LineFormatter;
    use Throwable;
    use Monolog\Handler\WhatFailureGroupHandler;

    /**
     * ErrorLogger class that standardizes error logging with detailed information.
     * It uses the Monolog library to log errors to a specified file.
     */
    class ErrorLogger
    {
        /**
         * @var Logger $logger Monolog logger instance for error logging.
         */
        private Logger $logger;

        /**
         * ErrorLogger constructor.
         * Initializes the Monolog logger with a file handler and custom formatting.
         *
         * @param string $logFile The file path where logs will be written.
         */
        public function __construct(string $logFile = '/var/log/caddy/phpApiManager.log')
        {
            // Create a new Monolog logger instance
            $this->logger = new Logger('ErrorLogger');
            
            try {
                // Create a StreamHandler to log to a file with a custom formatter
                $streamHandler = new StreamHandler($logFile, Logger::DEBUG);
                
                // Define a custom format: [date] [script_name:line_number] error_message
                $output = "[%datetime%] [%extra.file%:%extra.line%] %message% %context%\n";
                $lineFormatter = new LineFormatter($output, null, true, true);
                $streamHandler->setFormatter($lineFormatter);

                // Push the StreamHandler to the logger
                $this->logger->pushHandler($streamHandler);
            } catch (Exception $exception) {
                // If there's an issue with the log file (e.g., permission issues), fallback to PHP's error_log
                error_log(sprintf('Failed to open log file %s for writing. Falling back to PHP\'s error_log. Exception: ', $logFile) . $exception->getMessage());

                // Use a WhatFailureGroupHandler to fallback to PHP's error_log
                $this->logger->pushHandler(new StreamHandler('php://stderr', Logger::ERROR));
            }
        }

        /**
         * Logs an error with detailed information including file, line, message, and optional trace.
         *
         * @param string $message The error message to log.
         * @param array $context Optional additional context (e.g., exception trace).
         */
        public function logError(string $message, array $context = []): void
        {
            // Get the calling file and line number
            $debugBacktrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 1)[0];

            // Add file and line information to the log context
            $context['file'] = $debugBacktrace['file'] ?? 'Unknown file';
            $context['line'] = $debugBacktrace['line'] ?? 'Unknown line';

            // Log the error with context information
            $this->logger->error($message, $context);

            // Output the error to the page if display_errors is enabled
            $this->outputErrorToPage($message, $context);
        }

        /**
         * Logs a critical error. Can accept either a string message or a Throwable.
         *
         * @param string|Throwable $error The error to log, either as a message or an exception.
         */
        public function logCritical(string|Throwable $error): void
        {
            // Check if the error is a Throwable object or a string
            if ($error instanceof Throwable) {
                // Extract the message and context from the Throwable object
                $message = $error->getMessage();
                $context = [
                    'file' => $error->getFile(),
                    'line' => $error->getLine(),
                    'trace' => $error->getTraceAsString(),
                ];
            } else {
                // If the error is a string, log it as is with no context
                $message = $error;
                $context = [];  // No context available for string messages
            }

            // Log the critical error with message and context
            $this->logger->critical($message, $context);

            // Output the error to the page if display_errors is enabled
            $this->outputErrorToPage($message, $context);
        }

        /**
         * Logs an info-level message for general application info.
         *
         * @param string $message The informational message to log.
         */
        public function logInfo(string $message): void
        {
            // Get the calling file and line number
            $debugBacktrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 1)[0];

            // Add file and line information to the log context
            $context['file'] = $debugBacktrace['file'] ?? 'Unknown file';
            $context['line'] = $debugBacktrace['line'] ?? 'Unknown line';

            // Log the info message with context information
            $this->logger->info($message, $context);
        }
        
        /**
         * Outputs the error to the page if display_errors is enabled.
         *
         * @param string $message The error message.
         * @param array $context Additional context such as file and line.
         */
        private function outputErrorToPage(string $message, array $context): void
        {
            if (ini_get('display_errors')) {
                // If html_errors is enabled, format output as HTML
                if (ini_get('html_errors')) {
                    echo "<div style='color: red;'><strong>Error:</strong> " . htmlentities($message) . "<br>";
                    if (!empty($context['file']) && !empty($context['line'])) {
                        echo "<strong>File:</strong> " . htmlentities($context['file']) . "<br>";
                        echo "<strong>Line:</strong> " . htmlentities($context['line']) . "<br>";
                    }
                    
                    echo "</div>";

                    // Set the content type to HTML
                    APIManager::setResponseContentType('text/html');
                } else {
                    // Plain text output
                    echo "Error: " . $message . "\n";
                    if (!empty($context['file']) && !empty($context['line'])) {
                        echo "File: " . $context['file'] . " Line: " . $context['line'] . "\n";
                    }
                }
            }
        }
    }
?>