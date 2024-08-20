# Development Setup Guide 🚀

Welcome to the development environment setup for this project! This guide will walk you through installing PHP, Composer, PHPStan, and nodemon. We use PHPStan for automatic linting to ensure code quality.

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
   - Open Command Prompt and run:

     ```bash
     npm install -g nodemon
     ```

## Setting Up the Project ⚙️

1. **Clone the Repository**:
   - Clone the repository to your local machine:

     ```bash
     git clone https://github.com/yourusername/common-api-utilities.git
     ```

   - Navigate into the repository directory:

     ```bash
     cd path/to/repo
     ```

2. **Install Project Dependencies**:
   - Install PHP dependencies with Composer:

     ```bash
     composer install
     ```

3. **Configure PHPStan**:
   - Ensure you have the `phpstan.neon` file in the project root with the correct configuration for PHPStan.

4. **Set Up nodemon**:
   - Ensure you have the `nodemon.json` file in the project root with the configuration for watching PHP files and running PHPStan.

5. **Run PHPStan Automatically**:
   - Navigate to the `tests` directory:

     ```bash
     cd path/to/repo/tests
     ```

   - Start nodemon to watch for file changes and run PHPStan:

     ```bash
     composer run watch
     ```

   - This command will use `nodemon` to watch for changes in PHP files and automatically run PHPStan to check for code issues.

## Summary 🎯

- **PHPStan** is used for automatic linting to ensure code quality.
- **nodemon** watches for file changes and triggers PHPStan automatically.
- Follow these steps to set up the environment and start working with the project.

Feel free to reach out if you have any questions or need further assistance. Happy coding! 😊