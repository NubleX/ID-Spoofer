# Contributing to ID-Spoofer

Thank you for your interest in contributing to ID-Spoofer! This document provides guidelines and information for contributors.

## Project Goals

ID-Spoofer aims to be a comprehensive, secure, and user-friendly toolkit for hardware identity spoofing on Linux systems. Our primary goals are:

- **Security**: Provide robust tools for legitimate security testing
- **Usability**: Make the tools accessible to both technical and non-technical users
- **Reliability**: Ensure stable operation across different OS distributions
- **Safety**: Implement safeguards to prevent accidental system damage

## How to Contribute

### Reporting Issues

Before reporting an issue, please:

1. **Search existing issues** to avoid duplicates
2. **Test on a clean system** if possible
3. **Gather system information** (distribution, kernel version, etc.)

When reporting issues, please include:

- **System information**: OS, kernel version, distribution
- **Steps to reproduce**: Clear, numbered steps
- **Expected behavior**: What should happen
- **Actual behavior**: What actually happens
- **Error messages**: Complete error output
- **Log files**: If available (use `--log` option)

### Suggesting Features

Feature requests are welcome! Please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** clearly
3. **Explain the benefit** to users
4. **Consider security implications**

### Code Contributions

#### Development Setup

```bash
# Fork the repository on GitHub
git clone https://github.com/YOUR_USERNAME/id-spoofer.git
cd id-spoofer

# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes
# Test thoroughly

# Commit and push
git commit -m "Add: your feature description"
git push origin feature/your-feature-name

# Create a pull request
```

#### Code Standards

**Shell Script Guidelines:**

- Use `#!/bin/bash` shebang
- Enable strict mode: `set -e`
- Quote variables: `"$variable"`
- Use meaningful function names
- Add comments for complex logic
- Follow the existing code style

**Formatting:**

- 2-space indentation
- Maximum line length: 100 characters
- Use lowercase for local variables
- Use UPPERCASE for constants

**Error Handling:**

- Check command exit codes
- Provide meaningful error messages
- Use proper logging levels
- Implement cleanup on exit

#### Testing

Before submitting a pull request:

1. **Test on multiple distributions** (if possible)
2. **Test both CLI and GUI modes**
3. **Test error conditions**
4. **Verify cleanup works properly**
5. **Test with and without required dependencies**

**Testing Checklist:**

- [ ] Script runs without errors
- [ ] All command-line options work
- [ ] GUI mode functions properly
- [ ] Cleanup removes temporary files
- [ ] Logging works correctly
- [ ] Error messages are helpful
- [ ] No root privilege escalation issues

#### Documentation

- Update README.md if adding new features
- Add inline comments for complex code
- Update help text for new options
- Include examples in documentation

## Pull Request Process

1. **Create an issue** first (for significant changes)
2. **Fork the repository** and create a feature branch
3. **Make your changes** following the code standards
4. **Test thoroughly** on clean systems
5. **Update documentation** as needed
6. **Submit a pull request** with a clear description

### Pull Request Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring

## Testing
- [ ] Tested on Ubuntu/Debian
- [ ] Tested on RHEL/CentOS
- [ ] Tested on Arch Linux
- [ ] Tested CLI mode
- [ ] Tested GUI mode
- [ ] Tested error conditions

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new security vulnerabilities
```

## Security Considerations

This project involves system-level operations that could affect security. Please:

### Security Review Process

1. **Consider privilege implications** of all changes
2. **Avoid unnecessary file system access**
3. **Validate all user inputs**
4. **Use secure temporary file handling**
5. **Document security-relevant changes**

### Reporting Security Issues

For security vulnerabilities:

1. **Do NOT create public issues**
2. **Email <nublexer@hotmail.com>** (replace with actual contact)
3. **Include detailed reproduction steps**
4. **Allow reasonable time for fixes**

## Development Environment

### Required Tools

- **Bash 4.0+**: For script execution
- **Git**: For version control
- **Text editor**: With shell script support
- **Virtual machines**: For testing (recommended)

### Recommended Setup

```bash
# Install development tools
sudo apt-get install shellcheck bash-completion

# Set up git hooks (optional)
cp .githooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

### Testing Environment

We recommend testing in virtual machines to avoid affecting your main system:

- **VirtualBox/VMware**: For isolated testing
- **Docker containers**: For quick distribution testing
- **Clean installations**: To verify dependency handling

## Code Style Guide

### Variable Naming

```bash
# Local variables: lowercase with underscores
local_variable="value"
user_input=""

# Global variables: UPPERCASE
GLOBAL_CONSTANT="value"
LOG_FILE="/var/log/app.log"

# Function names: lowercase with underscores
function_name() {
    local param="$1"
    # Function body
}
```

### Function Structure

```bash
# Function template
function_name() {
    local param1="$1"
    local param2="$2"
    
    # Validate parameters
    if [ -z "$param1" ]; then
        log_message "ERROR" "Missing required parameter"
        return 1
    fi
    
    # Function logic here
    
    # Return appropriate exit code
    return 0
}
```

### Error Handling

```bash
# Check command success
if ! command_that_might_fail; then
    log_message "ERROR" "Command failed"
    return 1
fi

# Use trap for cleanup
cleanup() {
    rm -rf "$temp_dir"
}
trap cleanup EXIT
```

## Architecture Overview

### Project Structure

```
id-spoofer/
├── src/
│   ├── bin/
│   │   ├── hardware-spoof.sh         # Fixed main script
│   │   ├── idspoof-menu.sh           # Interactive menu
│   │   └── uninstall.sh              # Comprehensive uninstaller
│   └── share/
│       └── applications/
│           └── hardware-spoofer.desktop
├── assets/
│   └── images/
│       └── logo.svg                  # Project logo
├── install.sh                        # Enhanced installer
├── emergency-uninstall.sh            # Standalone cleanup
├── README.md                         # Updated documentation
├── CHANGELOG.md                      # Version history
├── CONTRIBUTING.md                   # Development guidelines
└── LICENSE                           # GPL v3 license
```

### Core Components

1. **Main Script** (`hardware-spoof.sh`)
   - Command-line interface
   - Core spoofing functions
   - Progress tracking
   - Error handling

2. **Menu Interface** (`idspoof-menu.sh`)
   - User-friendly menu system
   - Status display
   - Operation selection

3. **Installer** (`install.sh`)
   - Multi-distribution support
   - Dependency management
   - Desktop integration

## UI/UX Guidelines

### Command-Line Interface

- **Clear output**: Use colors and formatting for readability
- **Progress indication**: Show progress for long operations
- **Helpful errors**: Provide actionable error messages
- **Consistent options**: Follow standard CLI conventions

### GUI Interface

- **Responsive dialogs**: Don't block for too long
- **Clear messages**: Use simple, non-technical language
- **Progress feedback**: Show what's happening
- **Error recovery**: Offer solutions when possible

## Testing Guidelines

### Unit Testing

While formal unit tests aren't currently implemented, please verify:

- **Function isolation**: Each function should work independently
- **Parameter validation**: Test with invalid inputs
- **Error conditions**: Verify proper error handling
- **Cleanup**: Ensure resources are properly released

### Integration Testing

Test complete workflows:

```bash
# Test full spoofing
sudo ./src/bin/hardware-spoof.sh --quiet

# Test individual components
sudo ./src/bin/hardware-spoof.sh --mac-only --quiet
sudo ./src/bin/hardware-spoof.sh --hostname-only --quiet

# Test error conditions
./src/bin/hardware-spoof.sh  # Should fail without root
```

### Distribution Testing

Test on different Linux distributions:

- **Ubuntu/Debian**: Primary development platform
- **RHEL/CentOS**: Enterprise environments
- **Arch Linux**: Rolling release
- **Fedora**: Recent package versions
- **Kali Linux**: Security testing focused

## Documentation Standards

### Code Comments

```bash
# Function description: what it does
# Parameters: describe each parameter
# Returns: describe return values/exit codes
function_name() {
    # Implementation details for complex logic
}
```

### Commit Messages

Follow conventional commit format:

```
type(scope): description

Add: new feature implementation
Fix: bug correction
Update: modification to existing feature
Remove: deletion of feature/file
Docs: documentation changes
Style: formatting changes
Refactor: code restructuring
Test: test-related changes
```

Examples:

```
Add: GUI support for hostname spoofing
Fix: network interface detection on newer kernels
Update: improve error messages for missing dependencies
Docs: add troubleshooting section to README
```

## Contribution Areas

We welcome contributions in these areas:

### High Priority

- **Bug fixes**: Stability and reliability improvements
- **Distribution support**: Support for additional Linux distributions
- **Error handling**: Better error messages and recovery
- **Testing**: Automated testing framework

### Medium Priority

- **Features**: New spoofing capabilities
- **UI improvements**: Better user experience
- **Performance**: Optimization of existing code
- **Documentation**: Tutorials and examples

### Low Priority

- **Code cleanup**: Refactoring and style improvements
- **Internationalization**: Multi-language support
- **Packaging**: Distribution-specific packages

## Recognition

Contributors will be recognized in:

- **README.md**: Contributors section
- **CHANGELOG.md**: Credit for specific contributions
- **GitHub**: Through commit history and contributors page

## Communication

### GitHub

- **Issues**: Bug reports and feature requests
- **Discussions**: General questions and ideas
- **Pull Requests**: Code contributions

### Guidelines for Communication

- **Be respectful**: Treat all contributors with respect
- **Be constructive**: Offer solutions, not just criticism
- **Be patient**: Maintainers are volunteers
- **Be clear**: Explain your ideas thoroughly

## Legal Considerations

### License Agreement

By contributing, you agree that:

- Your contributions will be licensed under GPL v3.0
- You have the right to submit your contributions
- Your contributions are your original work

### Responsible Use

This project is for legitimate security testing only. Contributors should:

- **Consider ethical implications** of changes
- **Document security considerations**
- **Avoid enabling malicious use**
- **Follow responsible disclosure** for vulnerabilities

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] Update version numbers
- [ ] Update CHANGELOG.md
- [ ] Test on multiple distributions
- [ ] Update documentation
- [ ] Create release notes
- [ ] Tag release in Git

## Resources

### Learning Resources

- [Bash Scripting Guide](https://tldp.org/LDP/Bash-Beginners-Guide/html/)
- [ShellCheck](https://www.shellcheck.net/) - Script analysis tool
- [Linux Network Stack](https://www.kernel.org/doc/Documentation/networking/)

### Tools

- **ShellCheck**: Static analysis for shell scripts
- **Bash Language Server**: IDE support for bash
- **Git**: Version control
- **Virtual Machines**: Safe testing environment

---

Thank you for contributing to ID-Spoofer! Your help makes this project better for everyone.

**Happy coding!**
