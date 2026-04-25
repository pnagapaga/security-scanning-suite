#!/bin/bash

################################################################################
# Security Scanning Script for Auth Service
# Runs: SpotBugs, PMD, Snyk, OWASP Dependency-Check, Trivy FS, Trivy Image
# Outputs: JSON reports for all scans
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="backend/auth-service"
REPORTS_DIR="security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create reports directory
mkdir -p "${REPORTS_DIR}"

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Security Scanning Suite${NC}"
echo -e "${BLUE}================================${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check prerequisites
print_status "Checking prerequisites..."

MISSING_TOOLS=()

if ! command_exists mvn; then
    MISSING_TOOLS+=("maven")
fi

if ! command_exists docker; then
    MISSING_TOOLS+=("docker")
fi

if ! command_exists snyk; then
    print_warning "Snyk CLI not found. Install with: npm install -g snyk"
    MISSING_TOOLS+=("snyk")
fi

if ! command_exists dependency-check; then
    print_warning "OWASP Dependency-Check not found. Install from: https://owasp.org/www-project-dependency-check/"
    MISSING_TOOLS+=("dependency-check")
fi

if ! command_exists trivy; then
    print_warning "Trivy not found. Install from: https://aquasecurity.github.io/trivy/"
    MISSING_TOOLS+=("trivy")
fi

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    print_error "Missing tools: ${MISSING_TOOLS[*]}"
    echo ""
    echo "Please install missing tools before running this script."
    exit 1
fi

print_success "All required tools are installed"
echo ""

# Navigate to project directory
cd "${PROJECT_DIR}"

################################################################################
# 1. SpotBugs (SAST)
################################################################################
print_status "Running SpotBugs (SAST)..."
if mvn clean compile spotbugs:spotbugs -Dspotbugs.xmlOutput=false 2>&1 | tee ../../${REPORTS_DIR}/spotbugs.log; then
    # Convert SpotBugs XML to JSON (SpotBugs doesn't natively support JSON, so we'll use XML)
    if [ -f "target/spotbugsXml.xml" ]; then
        cp target/spotbugsXml.xml ../../${REPORTS_DIR}/spotbugs-${TIMESTAMP}.xml
        print_success "SpotBugs scan completed - XML report generated"
    else
        print_warning "SpotBugs XML report not found"
    fi
else
    print_warning "SpotBugs scan completed with warnings"
fi
echo ""

################################################################################
# 2. PMD (SAST)
################################################################################
print_status "Running PMD (SAST)..."
if mvn pmd:pmd -Dpmd.outputFormat=json 2>&1 | tee ../../${REPORTS_DIR}/pmd.log; then
    if [ -f "target/pmd.json" ]; then
        cp target/pmd.json ../../${REPORTS_DIR}/pmd-${TIMESTAMP}.json
        print_success "PMD scan completed - JSON report generated"
    elif [ -f "target/pmd.xml" ]; then
        cp target/pmd.xml ../../${REPORTS_DIR}/pmd-${TIMESTAMP}.xml
        print_success "PMD scan completed - XML report generated"
    else
        print_warning "PMD report not found"
    fi
else
    print_warning "PMD scan completed with warnings"
fi
echo ""

################################################################################
# 3. Snyk (Dependency Scanning)
################################################################################
print_status "Running Snyk dependency scan..."
if command_exists snyk; then
    # Check if authenticated
    if snyk auth status >/dev/null 2>&1; then
        if snyk test --json --severity-threshold=low > ../../${REPORTS_DIR}/snyk-${TIMESTAMP}.json 2>&1; then
            print_success "Snyk scan completed - JSON report generated"
        else
            # Snyk returns non-zero if vulnerabilities found, but still generates report
            if [ -f "../../${REPORTS_DIR}/snyk-${TIMESTAMP}.json" ]; then
                print_warning "Snyk scan found vulnerabilities - JSON report generated"
            else
                print_error "Snyk scan failed"
            fi
        fi
    else
        print_error "Snyk not authenticated. Run: snyk auth"
        echo "Skipping Snyk scan..."
    fi
else
    print_warning "Snyk not installed - skipping"
fi
echo ""

################################################################################
# 4. OWASP Dependency-Check
################################################################################
print_status "Running OWASP Dependency-Check..."
if command_exists dependency-check; then
    dependency-check \
        --project "auth-service" \
        --scan . \
        --format JSON \
        --format HTML \
        --out ../../${REPORTS_DIR} \
        --suppression ../../dependency-check-suppressions.xml 2>&1 | tee ../../${REPORTS_DIR}/dependency-check.log || true
    
    if [ -f "../../${REPORTS_DIR}/dependency-check-report.json" ]; then
        mv ../../${REPORTS_DIR}/dependency-check-report.json ../../${REPORTS_DIR}/dependency-check-${TIMESTAMP}.json
        print_success "OWASP Dependency-Check completed - JSON report generated"
    else
        print_warning "OWASP Dependency-Check report not found"
    fi
else
    print_warning "OWASP Dependency-Check not installed - skipping"
fi
echo ""

################################################################################
# 5. Trivy Filesystem Scan
################################################################################
print_status "Running Trivy filesystem scan..."
if command_exists trivy; then
    trivy fs \
        --format json \
        --output ../../${REPORTS_DIR}/trivy-fs-${TIMESTAMP}.json \
        --severity CRITICAL,HIGH,MEDIUM,LOW \
        . 2>&1 | tee ../../${REPORTS_DIR}/trivy-fs.log || true
    
    if [ -f "../../${REPORTS_DIR}/trivy-fs-${TIMESTAMP}.json" ]; then
        print_success "Trivy filesystem scan completed - JSON report generated"
    else
        print_warning "Trivy filesystem report not found"
    fi
else
    print_warning "Trivy not installed - skipping"
fi
echo ""

################################################################################
# 6. Build Docker Image and Scan
################################################################################
print_status "Building Docker image..."
IMAGE_NAME="auth-service-security-scan:${TIMESTAMP}"
if docker build -t ${IMAGE_NAME} . 2>&1 | tee ../../${REPORTS_DIR}/docker-build.log; then
    print_success "Docker image built successfully"
    
    print_status "Running Trivy image scan..."
    if command_exists trivy; then
        trivy image \
            --format json \
            --output ../../${REPORTS_DIR}/trivy-image-${TIMESTAMP}.json \
            --severity CRITICAL,HIGH,MEDIUM,LOW \
            ${IMAGE_NAME} 2>&1 | tee ../../${REPORTS_DIR}/trivy-image.log || true
        
        if [ -f "../../${REPORTS_DIR}/trivy-image-${TIMESTAMP}.json" ]; then
            print_success "Trivy image scan completed - JSON report generated"
        else
            print_warning "Trivy image report not found"
        fi
    else
        print_warning "Trivy not installed - skipping image scan"
    fi
    
    # Clean up Docker image
    print_status "Cleaning up Docker image..."
    docker rmi ${IMAGE_NAME} >/dev/null 2>&1 || true
else
    print_error "Docker build failed - skipping image scan"
fi
echo ""

# Return to root directory
cd ../..

################################################################################
# 7. Generate Consolidated Report
################################################################################
print_status "Generating consolidated report..."
if command_exists python3; then
    if [ -f "utils/generate-executive-summary.py" ]; then
        python3 utils/generate-executive-summary.py --timestamp ${TIMESTAMP}
        print_success "Consolidated JSON report generated"
        
        if [ -f "utils/create-pdf-report.py" ]; then
            print_status "Generating PDF executive summary..."
            python3 utils/create-pdf-report.py --timestamp ${TIMESTAMP}
            print_success "PDF executive summary generated"
        else
            print_warning "PDF generator script not found - skipping PDF generation"
        fi
    else
        print_warning "Report aggregation script not found - skipping consolidation"
    fi
else
    print_warning "Python3 not found - skipping report consolidation"
fi
echo ""

################################################################################
# Summary
################################################################################
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Scan Summary${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo "Reports generated in: ${REPORTS_DIR}/"
echo ""
echo "Available reports:"
ls -lh ${REPORTS_DIR}/*${TIMESTAMP}* 2>/dev/null || echo "No timestamped reports found"
echo ""
echo -e "${GREEN}Security scanning completed!${NC}"
echo ""
echo "Next steps:"
echo "1. Review the executive summary PDF: ${REPORTS_DIR}/executive-summary-${TIMESTAMP}.pdf"
echo "2. Check individual scan reports for detailed findings"
echo "3. Prioritize remediation based on severity levels"
echo ""
