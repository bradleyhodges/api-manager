<?php
    namespace APIManager\Classes;

    use Monolog\Logger;
    use Monolog\Handler\StreamHandler;
    use Monolog\Formatter\LineFormatter;
    use Throwable;

    /**
     * ErrorLogger class that standardizes error logging with detailed information.
     * It uses the Monolog library to log errors to a specified file.
     */
    class ErrorLogger
    {
        private Logger $logger;

        /**
         * ErrorLogger constructor.
         * Initializes the Monolog logger with a file handler and custom formatting.
         *
         * @param string $logFile The file path where logs will be written.
         */
        public function __construct(string $logFile = __DIR__ . '/logs/error.log')
        {
            // Create a new Logger instance
            $this->logger = new Logger('ErrorLogger');

            // Create a StreamHandler to log to a file with a custom formatter
            $streamHandler = new StreamHandler($logFile, Logger::DEBUG);
            
            // Define a custom format: [date] [script_name:line_number] error_message
            $output = "[%datetime%] [%extra.file%:%extra.line%] %message% %context%\n";
            $lineFormatter = new LineFormatter($output, null, true, true);
            $streamHandler->setFormatter($lineFormatter);

            // Push the handler to the logger
            $this->logger->pushHandler($streamHandler);
        }

        /**
         * Logs an error with detailed information including file, line, message, and optional trace.
         *
         * @param string $message The error message to log.
         * @param array $context Optional additional context (e.g., exception trace).
         */
        public function logError(string $message, array $context = []): void
        {
            $debugBacktrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 1)[0];
            
            // Add file and line information to the log context
            $context['file'] = $debugBacktrace['file'] ?? 'Unknown file';
            $context['line'] = $debugBacktrace['line'] ?? 'Unknown line';

            // Log the error with context information
            $this->logger->error($message, $context);
        }

        /**
         * Logs a critical error and can include the exception trace.
         *
         * @param Throwable $throwable The exception to log.
         */
        public function logCritical(Throwable $throwable): void
        {
            $message = $throwable->getMessage();
            $context = [
                'file' => $throwable->getFile(),
                'line' => $throwable->getLine(),
                'trace' => $throwable->getTraceAsString(),
            ];

            $this->logger->critical($message, $context);
        }

        /**
         * Logs an info-level message for general application info.
         *
         * @param string $message The informational message to log.
         */
        public function logInfo(string $message): void
        {
            $debugBacktrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 1)[0];

            // Add file and line information to the log context
            $context['file'] = $debugBacktrace['file'] ?? 'Unknown file';
            $context['line'] = $debugBacktrace['line'] ?? 'Unknown line';

            $this->logger->info($message, $context);
        }
    }
?>