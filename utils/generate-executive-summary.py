#!/usr/bin/env python3
"""
Security Scan Report Aggregator
Consolidates JSON reports from multiple security scanning tools into a unified format
"""

import json
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

class SecurityReportAggregator:
    def __init__(self, reports_dir="security-reports", timestamp=None):
        self.reports_dir = Path(reports_dir)
        self.timestamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.consolidated_report = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "timestamp": self.timestamp,
                "project": "Authorization Service",
                "tools_used": []
            },
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            },
            "findings_by_tool": {},
            "critical_issues": [],
            "all_findings": []
        }

    def normalize_severity(self, severity):
        """Normalize severity levels across different tools"""
        severity_upper = str(severity).upper()
        
        # Map various severity levels to standard categories
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "MODERATE": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO",
            "INFORMATIONAL": "INFO",
            "WARNING": "MEDIUM",
            "ERROR": "HIGH",
            "1": "HIGH",  # PMD priority
            "2": "MEDIUM",
            "3": "LOW",
            "4": "INFO",
            "5": "INFO"
        }
        
        return severity_map.get(severity_upper, "MEDIUM")

    def parse_spotbugs_xml(self, file_path):
        """Parse SpotBugs XML report"""
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            for bug in root.findall('.//BugInstance'):
                severity = self.normalize_severity(bug.get('priority', '3'))
                finding = {
                    "tool": "SpotBugs",
                    "type": bug.get('type', 'Unknown'),
                    "category": bug.get('category', 'Unknown'),
                    "severity": severity,
                    "message": bug.find('.//LongMessage').text if bug.find('.//LongMessage') is not None else "No description",
                    "file": bug.find('.//SourceLine').get('sourcepath', 'Unknown') if bug.find('.//SourceLine') is not None else "Unknown",
                    "line": bug.find('.//SourceLine').get('start', 'N/A') if bug.find('.//SourceLine') is not None else "N/A"
                }
                findings.append(finding)
                
        except Exception as e:
            print(f"Warning: Error parsing SpotBugs XML: {e}")
        
        return findings

    def parse_pmd_json(self, file_path):
        """Parse PMD JSON report"""
        findings = []
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for file_data in data.get('files', []):
                for violation in file_data.get('violations', []):
                    severity = self.normalize_severity(violation.get('priority', '3'))
                    finding = {
                        "tool": "PMD",
                        "type": violation.get('rule', 'Unknown'),
                        "category": violation.get('ruleset', 'Unknown'),
                        "severity": severity,
                        "message": violation.get('description', 'No description'),
                        "file": file_data.get('filename', 'Unknown'),
                        "line": violation.get('beginline', 'N/A')
                    }
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Warning: Error parsing PMD JSON: {e}")
        
        return findings

    def parse_pmd_xml(self, file_path):
        """Parse PMD XML report"""
        findings = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Handle XML namespace if present
            namespace = ''
            if root.tag.startswith('{'):
                namespace = root.tag[root.tag.find('{')+1:root.tag.find('}')]
                ns = {'pmd': namespace}
                file_elements = root.findall('.//pmd:file', ns)
            else:
                file_elements = root.findall('.//file')
            
            for file_elem in file_elements:
                filename = file_elem.get('name', 'Unknown')
                
                # Find violations with or without namespace
                if namespace:
                    violations = file_elem.findall('.//pmd:violation', ns)
                else:
                    violations = file_elem.findall('.//violation')
                
                for violation in violations:
                    severity = self.normalize_severity(violation.get('priority', '3'))
                    finding = {
                        "tool": "PMD",
                        "type": violation.get('rule', 'Unknown'),
                        "category": violation.get('ruleset', 'Unknown'),
                        "severity": severity,
                        "message": violation.text.strip() if violation.text else 'No description',
                        "file": filename,
                        "line": violation.get('beginline', 'N/A')
                    }
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Warning: Error parsing PMD XML: {e}")
            import traceback
            traceback.print_exc()
        
        return findings

    def parse_snyk_json(self, file_path):
        """Parse Snyk JSON report"""
        findings = []
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for vuln in data.get('vulnerabilities', []):
                severity = self.normalize_severity(vuln.get('severity', 'medium'))
                finding = {
                    "tool": "Snyk",
                    "type": vuln.get('id', 'Unknown'),
                    "category": "Dependency Vulnerability",
                    "severity": severity,
                    "message": vuln.get('title', 'No description'),
                    "package": vuln.get('packageName', 'Unknown'),
                    "version": vuln.get('version', 'Unknown'),
                    "cvss_score": vuln.get('cvssScore', 'N/A'),
                    "cve": vuln.get('identifiers', {}).get('CVE', []),
                    "remediation": vuln.get('upgradePath', [])
                }
                findings.append(finding)
                
        except Exception as e:
            print(f"Warning: Error parsing Snyk JSON: {e}")
        
        return findings

    def parse_dependency_check_json(self, file_path):
        """Parse OWASP Dependency-Check JSON report"""
        findings = []
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for dependency in data.get('dependencies', []):
                for vuln in dependency.get('vulnerabilities', []):
                    severity = self.normalize_severity(vuln.get('severity', 'MEDIUM'))
                    finding = {
                        "tool": "OWASP Dependency-Check",
                        "type": vuln.get('name', 'Unknown'),
                        "category": "Dependency Vulnerability",
                        "severity": severity,
                        "message": vuln.get('description', 'No description'),
                        "package": dependency.get('fileName', 'Unknown'),
                        "cvss_score": vuln.get('cvssv3', {}).get('baseScore', vuln.get('cvssv2', {}).get('score', 'N/A')),
                        "cve": [vuln.get('name', '')],
                        "references": [ref.get('url', '') for ref in vuln.get('references', [])]
                    }
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Warning: Error parsing OWASP Dependency-Check JSON: {e}")
        
        return findings

    def parse_trivy_json(self, file_path, scan_type="filesystem"):
        """Parse Trivy JSON report"""
        findings = []
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for result in data.get('Results', []):
                target = result.get('Target', 'Unknown')
                for vuln in result.get('Vulnerabilities', []):
                    severity = self.normalize_severity(vuln.get('Severity', 'MEDIUM'))
                    finding = {
                        "tool": f"Trivy ({scan_type})",
                        "type": vuln.get('VulnerabilityID', 'Unknown'),
                        "category": "Vulnerability",
                        "severity": severity,
                        "message": vuln.get('Title', vuln.get('Description', 'No description')),
                        "package": vuln.get('PkgName', 'Unknown'),
                        "version": vuln.get('InstalledVersion', 'Unknown'),
                        "fixed_version": vuln.get('FixedVersion', 'Not available'),
                        "target": target,
                        "references": vuln.get('References', [])
                    }
                    findings.append(finding)
                    
        except Exception as e:
            print(f"Warning: Error parsing Trivy JSON: {e}")
        
        return findings

    def aggregate_reports(self):
        """Aggregate all available security reports"""
        print(f"Scanning for reports in: {self.reports_dir}")
        
        # SpotBugs (XML)
        spotbugs_files = list(self.reports_dir.glob(f"spotbugs-{self.timestamp}.xml"))
        if spotbugs_files:
            print(f"Processing SpotBugs report: {spotbugs_files[0]}")
            findings = self.parse_spotbugs_xml(spotbugs_files[0])
            self.consolidated_report["findings_by_tool"]["SpotBugs"] = findings
            self.consolidated_report["metadata"]["tools_used"].append("SpotBugs")
        
        # PMD (JSON or XML)
        pmd_json_files = list(self.reports_dir.glob(f"pmd-{self.timestamp}.json"))
        pmd_xml_files = list(self.reports_dir.glob(f"pmd-{self.timestamp}.xml"))
        
        if pmd_json_files:
            print(f"Processing PMD JSON report: {pmd_json_files[0]}")
            findings = self.parse_pmd_json(pmd_json_files[0])
            self.consolidated_report["findings_by_tool"]["PMD"] = findings
            self.consolidated_report["metadata"]["tools_used"].append("PMD")
        elif pmd_xml_files:
            print(f"Processing PMD XML report: {pmd_xml_files[0]}")
            findings = self.parse_pmd_xml(pmd_xml_files[0])
            self.consolidated_report["findings_by_tool"]["PMD"] = findings
            self.consolidated_report["metadata"]["tools_used"].append("PMD")
        
        # Snyk
        snyk_files = list(self.reports_dir.glob(f"snyk-{self.timestamp}.json"))
        if snyk_files:
            print(f"Processing Snyk report: {snyk_files[0]}")
            findings = self.parse_snyk_json(snyk_files[0])
            self.consolidated_report["findings_by_tool"]["Snyk"] = findings
            self.consolidated_report["metadata"]["tools_used"].append("Snyk")
        
        # OWASP Dependency-Check
        owasp_files = list(self.reports_dir.glob(f"dependency-check-{self.timestamp}.json"))
        if owasp_files:
            print(f"Processing OWASP Dependency-Check report: {owasp_files[0]}")
            findings = self.parse_dependency_check_json(owasp_files[0])
            self.consolidated_report["findings_by_tool"]["OWASP Dependency-Check"] = findings
            self.consolidated_report["metadata"]["tools_used"].append("OWASP Dependency-Check")
        
        # Trivy Filesystem
        trivy_fs_files = list(self.reports_dir.glob(f"trivy-fs-{self.timestamp}.json"))
        if trivy_fs_files:
            print(f"Processing Trivy Filesystem report: {trivy_fs_files[0]}")
            findings = self.parse_trivy_json(trivy_fs_files[0], "Filesystem")
            self.consolidated_report["findings_by_tool"]["Trivy Filesystem"] = findings
            self.consolidated_report["metadata"]["tools_used"].append("Trivy Filesystem")
        
        # Trivy Image
        trivy_image_files = list(self.reports_dir.glob(f"trivy-image-{self.timestamp}.json"))
        if trivy_image_files:
            print(f"Processing Trivy Image report: {trivy_image_files[0]}")
            findings = self.parse_trivy_json(trivy_image_files[0], "Image")
            self.consolidated_report["findings_by_tool"]["Trivy Image"] = findings
            self.consolidated_report["metadata"]["tools_used"].append("Trivy Image")
        
        # Calculate summary statistics
        self.calculate_summary()
        
        # Save consolidated report
        output_file = self.reports_dir / f"consolidated-report-{self.timestamp}.json"
        with open(output_file, 'w') as f:
            json.dump(self.consolidated_report, f, indent=2)
        
        print(f"\nConsolidated report saved to: {output_file}")
        return output_file

    def calculate_summary(self):
        """Calculate summary statistics from all findings"""
        for tool, findings in self.consolidated_report["findings_by_tool"].items():
            for finding in findings:
                severity = finding.get("severity", "MEDIUM")
                
                # Update summary counts
                self.consolidated_report["summary"]["total_findings"] += 1
                
                if severity == "CRITICAL":
                    self.consolidated_report["summary"]["critical"] += 1
                    self.consolidated_report["critical_issues"].append(finding)
                elif severity == "HIGH":
                    self.consolidated_report["summary"]["high"] += 1
                    self.consolidated_report["critical_issues"].append(finding)
                elif severity == "MEDIUM":
                    self.consolidated_report["summary"]["medium"] += 1
                elif severity == "LOW":
                    self.consolidated_report["summary"]["low"] += 1
                else:
                    self.consolidated_report["summary"]["info"] += 1
                
                # Add to all findings
                self.consolidated_report["all_findings"].append(finding)
        
        # Sort critical issues by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.consolidated_report["critical_issues"].sort(
            key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 2)
        )

    def print_summary(self):
        """Print summary to console"""
        summary = self.consolidated_report["summary"]
        
        print("\n" + "="*60)
        print("SECURITY SCAN EXECUTIVE SUMMARY")
        print("="*60)
        print(f"\nScan Date: {self.consolidated_report['metadata']['scan_date']}")
        print(f"Project: {self.consolidated_report['metadata']['project']}")
        print(f"Tools Used: {', '.join(self.consolidated_report['metadata']['tools_used'])}")
        print("\n" + "-"*60)
        print("FINDINGS SUMMARY")
        print("-"*60)
        print(f"Total Findings:    {summary['total_findings']}")
        print(f"  Critical:        {summary['critical']}")
        print(f"  High:            {summary['high']}")
        print(f"  Medium:          {summary['medium']}")
        print(f"  Low:             {summary['low']}")
        print(f"  Info:            {summary['info']}")
        print("\n" + "-"*60)
        print("FINDINGS BY TOOL")
        print("-"*60)
        
        for tool, findings in self.consolidated_report["findings_by_tool"].items():
            print(f"{tool}: {len(findings)} findings")
        
        print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(description='Aggregate security scan reports')
    parser.add_argument('--timestamp', help='Timestamp for report files', default=None)
    parser.add_argument('--reports-dir', help='Directory containing reports', default='security-reports')
    
    args = parser.parse_args()
    
    aggregator = SecurityReportAggregator(
        reports_dir=args.reports_dir,
        timestamp=args.timestamp
    )
    
    output_file = aggregator.aggregate_reports()
    aggregator.print_summary()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
