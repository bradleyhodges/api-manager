# Linting Setup Guide 🚀

Welcome to the development environment linting setup for this project! This guide will walk you through installing PHP, Composer, PHPStan, and nodemon. We use PHPStan for automatic linting to ensure code quality, and nodemon to automatically run PHPStan whenever files are changed.

All linting-related configuration and utilities are contained in the `linting/` (this) directory, which is responsible for handling the project's code quality checks.

You may want to add the `linting/` directory to your `.gitignore` when deploying to production, as it is only necessary for development and linting purposes.

## Prerequisites 📦

1. **Download and Install PHP**:
   - Visit the [PHP Windows Downloads page](https://windows.php.net/download).
   - Download the latest, stable, **Thread Safe** version for your system architecture (x86 or x64).
   - Extract the `.zip` file to your Program Files: `C:\Program Files\PHP\<phpversion>`, e.g., `C:\Program Files\PHP\8.3`.
   - Add the PHP directory to your system's `Path`:
     - Right-click `This PC` or `Computer`, select `Properties`.
     - Click `Advanced system settings`, then `Environment Variables`.
     - Find the `Path` variable in `System variables`, click `Edit`, and add your PHP path (e.g., `C:\Program Files\PHP\8.3`).
   - Verify installation by running `php --version` in Command Prompt.

2. **Install Composer**:
   - Download Composer from the [Composer website](https://getcomposer.org/).
   - Run the Composer-Setup.exe file and follow the installation steps.
   - Verify installation by running `composer --version` in Command Prompt.

3. **Install nodemon** (for watching file changes):
   - Nodemon is a utility that will monitor for any changes in your source files and automatically restart your application. We use it here to monitor PHP files and trigger PHPStan.
   - Open Command Prompt and run:

     ```bash
     npm install -g nodemon
     ```

   **It is important that `nodemon` is installed globally. Make sure to use the `-g` flag.**
   - Learn more about nodemon [here](https://github.com/remy/nodemon).

## Tools Used 🔧

- **[PHPStan](https://github.com/phpstan/phpstan)**: A static analysis tool for PHP that focuses on finding errors in your code without running it.
- **[Rector](https://github.com/rectorphp/rector)**: A tool for automated code refactoring and upgrades to improve code quality, type safety, and security.
- **[Composer](https://github.com/composer/composer)**: A dependency manager for PHP, used to manage project dependencies.
- **[Nodemon](https://github.com/remy/nodemon)**: A tool that monitors changes in your source files and automatically restarts applications. In this project, it's used to watch for PHP file changes and run PHPStan.

## Setting Up the Project ⚙️

The linting functions of this project are intended to be run on a Windows machine. To get started with linting, follow these steps to set up your environment:

1. **Clone the Repository**:
   - Clone the repository to your local machine. 
   
      You can either download the repository from Github as a zip:

      > https://github.com/dfes-ses/common-api-utilities/archive/refs/heads/main.zip

      or, if you have `git` installed, you can clone the repository:

     ```bash
     git clone https://github.com/dfes-ses/common-api-utilities.git
     ```

   - Navigate into the repository directory:

     ```bash
     cd path/to/repo
     ```

2. **Install Project Dependencies**:
   - Navigate to the `linting` directory and install PHP dependencies with Composer:

   ```bash
   cd path/to/repo/linting
   composer install
   ```

3. **Configure PHPStan**:
   - Ensure you have the `phpstan.neon` file in the project root with the correct configuration for PHPStan.

4. **Set Up nodemon**:
   - Ensure you have the `nodemon.json` file in the project root with the configuration for watching PHP files and running PHPStan.

5. **Run PHPStan Automatically**:
   - Navigate to the `linting` directory:

     ```bash
     cd path/to/repo/linting
     ```

   - Start nodemon to watch for file changes and run PHPStan:

     ```bash
     composer run watch
     ```

   - This command will use `nodemon` to watch for changes in PHP files in the root directory and automatically run PHPStan to check for code issues.

6. **Run PHPStan Automatically**:
   - To run Rector and check for potential improvements and refactoring opportunities, run:

     ```bash
     composer rector:dry-run
     ```

   - This will show you what changes Rector would apply without actually modifying the files.

   - To apply the suggested changes, run:

     ```bash
     composer rector
     ```

## Summary 🎯

- **PHPStan** is used for automatic linting to ensure code quality.
- **Rector** is used for automated code refactoring, improving code quality, type safety, and security.
- **nodemon** watches for file changes and triggers PHPStan automatically.
- **linting/** directory contains all the configuration and tools related to linting.
- Follow these steps to set up the environment and start working with the project.
- You can learn more about the tools we use by visiting their respective GitHub repositories:
  - [PHPStan](https://github.com/phpstan/phpstan)
  - [Composer](https://github.com/composer/composer)
  - [Nodemon](https://github.com/remy/nodemon)

Feel free to reach out if you have any questions or need further assistance. Happy coding! 😊