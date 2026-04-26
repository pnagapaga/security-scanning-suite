# 🚀 Quick Start Guide - Security Scanning Suite

Get started with security scanning in 5 minutes!

A reference DevSecOps project demonstrating how SAST scanning can be embedded into a CI/CD workflow for a Spring Boot application.

This project reflects practical security patterns I have used in real-world environments, including:

    Static Application Security Testing
    CI/CD security checks
    Vulnerability reporting
    Secure development workflow design
    Developer-friendly security feedback loops

The goal is not just to run a tool.

The goal is to show how security controls can become part of the delivery process instead of being treated as a late-stage review.

This approach was influenced by security patterns implemented while working on real-world systems, including startup and federal environments.

## For Local Scanning

### Step 1: Install Prerequisites

```bash
# Check if you have the required tools
java -version    # Need Java 21
mvn -version     # Need Maven
docker --version # Need Docker
python3 --version # Need Python 3.11+

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Install Security Tools (Optional but Recommended)

```bash
# Install Snyk (for dependency scanning)
npm install -g snyk
snyk auth

# Install Trivy (for container scanning)
# Ubuntu/Debian:
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# macOS:
brew install trivy

# Install OWASP Dependency-Check
# Download from: https://owasp.org/www-project-dependency-check/
```

### Step 3: Run the Scans

```bash
# Make script executable (already done if you cloned the repo)
chmod +x run-security-scans.sh

# Run all security scans
./run-security-scans.sh
```

### Step 4: View Results

```bash
# Note: Sample Security Scanning Executive Summary report in the security-reports folder
# View the PDF summary
open security-reports/executive-summary-*.pdf

# Or check the consolidated JSON
cat security-reports/consolidated-report-*.json | jq
```

## Understanding the Results

### Severity Levels

- 🔴 **CRITICAL**: Immediate action required - exploitable vulnerabilities
- 🟠 **HIGH**: Should be fixed soon - significant security risk
- 🟡 **MEDIUM**: Should be reviewed - moderate security concern
- 🟢 **LOW**: Low priority - minor security issue
- ℹ️ **INFO**: Informational - best practice recommendations

### What to Do Next

1. **Review the PDF Summary**: Start with the executive summary
2. **Prioritize Critical/High**: Focus on the most severe issues first
3. **Check Remediation**: Look for upgrade paths in the detailed reports
4. **Update Dependencies**: Run `mvn versions:display-dependency-updates`
5. **Re-scan**: Run the scans again after fixes to verify

## Common Commands

```bash
# Run only specific scans
cd backend/auth-service
mvn spotbugs:spotbugs  # SpotBugs only
mvn pmd:pmd            # PMD only
snyk test              # Snyk only
trivy fs .             # Trivy filesystem only

# Generate reports from existing scan results
python3 generate-executive-summary.py --reports-dir security-reports
python3 create-pdf-report.py --reports-dir security-reports

# Clean up old reports
rm -rf security-reports/*
```

## Troubleshooting

### "Command not found" errors
- Install the missing tool (see Step 2 above)
- Or the script will skip that scan and continue

### Snyk authentication failed
```bash
snyk auth
# Follow the browser prompt to authenticate
```

### Docker build fails
```bash
# Make sure Docker is running
docker ps

# If needed, restart Docker
sudo systemctl restart docker  # Linux
# or restart Docker Desktop on macOS/Windows
```

### Python module not found
```bash
pip install -r requirements.txt
# or
pip install reportlab
```

## Need More Help?

- 📖 Read the full documentation on this Readme file
- 🐛 Report issues: Open a GitHub issue
- 💬 Ask questions: Check the troubleshooting section in the main README

## Next Steps

1. ✅ Run your first scan
2. ✅ Review the PDF report
3. ✅ Fix critical vulnerabilities
4. ✅ Integrate into your CI/CD pipeline
5. ✅ Schedule regular scans(weekly recommended)
6. ✅ Use scanning tools that provides the best coverage for your application

Happy scanning! 🔒
