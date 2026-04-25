#!/usr/bin/env python3
"""
Security Scan PDF Report Generator
Creates a professional executive summary PDF from consolidated security scan results
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, 
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

class SecurityPDFReport:
    def __init__(self, consolidated_json_path, output_path=None):
        self.json_path = Path(consolidated_json_path)
        self.output_path = output_path or self.json_path.parent / f"executive-summary-{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Load consolidated data
        with open(self.json_path, 'r') as f:
            self.data = json.load(f)
        
        # Setup document
        self.doc = SimpleDocTemplate(
            str(self.output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        # Setup styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Story (content) container
        self.story = []

    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#4a4a4a'),
            spaceAfter=12,
            alignment=TA_CENTER,
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c5aa0'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Subsection header
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#4a4a4a'),
            spaceAfter=6,
            spaceBefore=6,
            fontName='Helvetica-Bold'
        ))

    def _get_severity_color(self, severity):
        """Get color for severity level"""
        colors_map = {
            'CRITICAL': colors.HexColor('#8B0000'),
            'HIGH': colors.HexColor('#DC143C'),
            'MEDIUM': colors.HexColor('#FF8C00'),
            'LOW': colors.HexColor('#FFD700'),
            'INFO': colors.HexColor('#4682B4')
        }
        return colors_map.get(severity, colors.grey)

    def _create_cover_page(self):
        """Create cover page"""
        # Title
        title = Paragraph("Security Scan Executive Summary", self.styles['CustomTitle'])
        self.story.append(title)
        self.story.append(Spacer(1, 0.3*inch))
        
        # Project info
        project = self.data['metadata']['project']
        scan_date = datetime.fromisoformat(self.data['metadata']['scan_date']).strftime('%B %d, %Y at %H:%M')
        
        subtitle = Paragraph(f"<b>Project:</b> {project}", self.styles['CustomSubtitle'])
        self.story.append(subtitle)
        
        date_para = Paragraph(f"<b>Scan Date:</b> {scan_date}", self.styles['CustomSubtitle'])
        self.story.append(date_para)
        
        self.story.append(Spacer(1, 0.5*inch))
        
        # Summary box
        summary = self.data['summary']
        total = summary['total_findings']
        
        summary_data = [
            ['Total Findings', str(total)],
            ['Critical', str(summary['critical'])],
            ['High', str(summary['high'])],
            ['Medium', str(summary['medium'])],
            ['Low', str(summary['low'])],
            ['Info', str(summary['info'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5aa0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#ffebee')),
            ('BACKGROUND', (0, 2), (-1, 2), colors.HexColor('#ffcdd2')),
            ('BACKGROUND', (0, 3), (-1, 3), colors.HexColor('#ffe0b2')),
            ('BACKGROUND', (0, 4), (-1, 4), colors.HexColor('#fff9c4')),
            ('BACKGROUND', (0, 5), (-1, 5), colors.HexColor('#e3f2fd')),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ]))
        
        self.story.append(summary_table)
        self.story.append(Spacer(1, 0.5*inch))
        
        # Tools used
        tools = ', '.join(self.data['metadata']['tools_used'])
        tools_para = Paragraph(f"<b>Security Tools Used:</b><br/>{tools}", self.styles['Normal'])
        self.story.append(tools_para)
        
        self.story.append(PageBreak())

    def _create_severity_chart(self):
        """Create pie chart for severity distribution"""
        summary = self.data['summary']
        
        # Skip if no findings
        if summary['total_findings'] == 0:
            return None
        
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 100
        pie.height = 100
        
        # Data
        data = []
        labels = []
        colors_list = []
        
        if summary['critical'] > 0:
            data.append(summary['critical'])
            labels.append(f"Critical ({summary['critical']})")
            colors_list.append(colors.HexColor('#8B0000'))
        
        if summary['high'] > 0:
            data.append(summary['high'])
            labels.append(f"High ({summary['high']})")
            colors_list.append(colors.HexColor('#DC143C'))
        
        if summary['medium'] > 0:
            data.append(summary['medium'])
            labels.append(f"Medium ({summary['medium']})")
            colors_list.append(colors.HexColor('#FF8C00'))
        
        if summary['low'] > 0:
            data.append(summary['low'])
            labels.append(f"Low ({summary['low']})")
            colors_list.append(colors.HexColor('#FFD700'))
        
        if summary['info'] > 0:
            data.append(summary['info'])
            labels.append(f"Info ({summary['info']})")
            colors_list.append(colors.HexColor('#4682B4'))
        
        pie.data = data
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        
        for i, color in enumerate(colors_list):
            pie.slices[i].fillColor = color
        
        drawing.add(pie)
        return drawing

    def _create_executive_summary(self):
        """Create executive summary section"""
        self.story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        summary = self.data['summary']
        total = summary['total_findings']
        
        # Risk assessment
        if summary['critical'] > 0:
            risk_level = "CRITICAL"
            risk_color = "red"
            risk_text = f"This application has {summary['critical']} critical vulnerabilities that require immediate attention."
        elif summary['high'] > 0:
            risk_level = "HIGH"
            risk_color = "orange"
            risk_text = f"This application has {summary['high']} high-severity vulnerabilities that should be addressed promptly."
        elif summary['medium'] > 0:
            risk_level = "MEDIUM"
            risk_color = "yellow"
            risk_text = f"This application has {summary['medium']} medium-severity issues that should be reviewed."
        else:
            risk_level = "LOW"
            risk_color = "green"
            risk_text = "This application has a low security risk profile."
        
        risk_para = Paragraph(
            f"<b>Overall Risk Level: <font color='{risk_color}'>{risk_level}</font></b><br/><br/>{risk_text}",
            self.styles['Normal']
        )
        self.story.append(risk_para)
        self.story.append(Spacer(1, 0.2*inch))
        
        # Summary text
        summary_text = f"""
        A comprehensive security scan was performed using {len(self.data['metadata']['tools_used'])} different 
        security tools, identifying a total of {total} findings across various severity levels. 
        The scan included Static Application Security Testing (SAST), dependency vulnerability scanning, 
        and container image analysis.
        """
        
        self.story.append(Paragraph(summary_text, self.styles['Normal']))
        self.story.append(Spacer(1, 0.2*inch))
        
        # Add chart
        chart = self._create_severity_chart()
        if chart:
            self.story.append(chart)
        
        self.story.append(Spacer(1, 0.3*inch))

    def _create_findings_by_tool(self):
        """Create findings by tool section"""
        self.story.append(Paragraph("Findings by Security Tool", self.styles['SectionHeader']))
        
        for tool, findings in self.data['findings_by_tool'].items():
            if not findings:
                continue
            
            # Tool header
            self.story.append(Paragraph(f"{tool} ({len(findings)} findings)", self.styles['SubsectionHeader']))
            
            # Count by severity
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            for finding in findings:
                severity = finding.get('severity', 'MEDIUM')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Create summary table
            tool_data = [['Severity', 'Count']]
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity_counts[sev] > 0:
                    tool_data.append([sev, str(severity_counts[sev])])
            
            if len(tool_data) > 1:
                tool_table = Table(tool_data, colWidths=[2*inch, 1.5*inch])
                tool_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                ]))
                
                self.story.append(tool_table)
            
            self.story.append(Spacer(1, 0.2*inch))

    def _create_critical_issues(self):
        """Create critical and high issues section"""
        critical_issues = self.data.get('critical_issues', [])
        
        if not critical_issues:
            self.story.append(Paragraph("Critical & High Priority Issues", self.styles['SectionHeader']))
            self.story.append(Paragraph("No critical or high severity issues found.", self.styles['Normal']))
            return
        
        self.story.append(PageBreak())
        self.story.append(Paragraph("Critical & High Priority Issues", self.styles['SectionHeader']))
        
        # Limit to top 20 issues for PDF
        top_issues = critical_issues[:20]
        
        for idx, issue in enumerate(top_issues, 1):
            severity = issue.get('severity', 'MEDIUM')
            tool = issue.get('tool', 'Unknown')
            issue_type = issue.get('type', 'Unknown')
            message = issue.get('message', 'No description')
            
            # Truncate long messages
            if len(message) > 200:
                message = message[:200] + "..."
            
            issue_header = f"<b>{idx}. [{severity}] {issue_type}</b>"
            self.story.append(Paragraph(issue_header, self.styles['Normal']))
            
            issue_details = f"<b>Tool:</b> {tool}<br/><b>Description:</b> {message}"
            
            # Add package info if available
            if 'package' in issue:
                issue_details += f"<br/><b>Package:</b> {issue['package']}"
            
            # Add file info if available
            if 'file' in issue:
                issue_details += f"<br/><b>File:</b> {issue['file']}"
                if 'line' in issue:
                    issue_details += f" (Line {issue['line']})"
            
            self.story.append(Paragraph(issue_details, self.styles['Normal']))
            self.story.append(Spacer(1, 0.15*inch))
        
        if len(critical_issues) > 20:
            note = f"<i>Note: Showing top 20 of {len(critical_issues)} critical/high issues. See full JSON report for complete details.</i>"
            self.story.append(Paragraph(note, self.styles['Normal']))

    def _create_recommendations(self):
        """Create recommendations section"""
        self.story.append(PageBreak())
        self.story.append(Paragraph("Recommendations & Next Steps", self.styles['SectionHeader']))
        
        summary = self.data['summary']
        
        recommendations = []
        
        if summary['critical'] > 0:
            recommendations.append(
                f"<b>1. Address Critical Vulnerabilities:</b> Immediately remediate {summary['critical']} "
                "critical vulnerabilities. These pose the highest risk to the application."
            )
        
        if summary['high'] > 0:
            recommendations.append(
                f"<b>2. Fix High-Severity Issues:</b> Prioritize fixing {summary['high']} high-severity "
                "vulnerabilities within the next sprint."
            )
        
        if summary['medium'] > 0:
            recommendations.append(
                f"<b>3. Review Medium-Severity Findings:</b> Evaluate {summary['medium']} medium-severity "
                "issues and plan remediation based on risk assessment."
            )
        
        recommendations.append(
            "<b>4. Implement Continuous Scanning:</b> Integrate these security scans into your CI/CD pipeline "
            "to catch vulnerabilities early in the development process."
        )
        
        recommendations.append(
            "<b>5. Regular Updates:</b> Keep all dependencies and base images up to date to minimize "
            "exposure to known vulnerabilities."
        )
        
        recommendations.append(
            "<b>6. Security Training:</b> Provide security awareness training to development teams to "
            "prevent common vulnerabilities."
        )
        
        for rec in recommendations:
            self.story.append(Paragraph(rec, self.styles['Normal']))
            self.story.append(Spacer(1, 0.1*inch))

    def generate(self):
        """Generate the PDF report"""
        print(f"Generating PDF report from: {self.json_path}")
        
        # Build all sections
        self._create_cover_page()
        self._create_executive_summary()
        self._create_findings_by_tool()
        self._create_critical_issues()
        self._create_recommendations()
        
        # Build PDF
        self.doc.build(self.story)
        
        print(f"PDF report generated: {self.output_path}")
        return self.output_path

def main():
    parser = argparse.ArgumentParser(description='Generate PDF executive summary from security scan results')
    parser.add_argument('--timestamp', help='Timestamp for report files', default=None)
    parser.add_argument('--reports-dir', help='Directory containing reports', default='security-reports')
    parser.add_argument('--input', help='Input consolidated JSON file', default=None)
    parser.add_argument('--output', help='Output PDF file path', default=None)
    
    args = parser.parse_args()
    
    # Determine input file
    if args.input:
        input_file = Path(args.input)
    elif args.timestamp:
        input_file = Path(args.reports_dir) / f"consolidated-report-{args.timestamp}.json"
    else:
        # Find most recent consolidated report
        reports_dir = Path(args.reports_dir)
        consolidated_files = list(reports_dir.glob("consolidated-report-*.json"))
        if not consolidated_files:
            print("Error: No consolidated report found. Run generate-executive-summary.py first.")
            return 1
        input_file = max(consolidated_files, key=lambda p: p.stat().st_mtime)
    
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        return 1
    
    # Determine output file
    if args.output:
        output_file = Path(args.output)
    elif args.timestamp:
        output_file = Path(args.reports_dir) / f"executive-summary-{args.timestamp}.pdf"
    else:
        output_file = None
    
    # Generate PDF
    try:
        pdf_generator = SecurityPDFReport(input_file, output_file)
        pdf_generator.generate()
        return 0
    except Exception as e:
        print(f"Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
