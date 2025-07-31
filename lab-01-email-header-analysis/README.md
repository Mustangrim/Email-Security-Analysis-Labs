# Email Header Analysis Basics Lab 01: Email Forensics and Spoofing Detection

## Lab Overview

**Lab Focus:** Comprehensive email header analysis, SMTP spoofing detection, and professional security tool utilization for email forensics investigation  
**Difficulty:** Foundation    
**Author:** Mykyta Palamarchuk  
**Role:** SOC Analyst | Email Security Specialist & Threat Intelligence Researcher  
**Certification:** CompTIA Security+ (SY0-701)

### Environment Specifications
- **Platform:** Microsoft Outlook with enterprise email infrastructure
- **Administrative Privileges:** Email client access with header analysis capabilities
- **Business Context:** ComTech corporate environment with email security monitoring
- **Technology Focus:** Email header forensics, MXToolbox analysis, spoofing detection, CEO fraud investigation

---

## Learning Objectives

Upon completion of this lab, participants will demonstrate:

1. **Email architecture understanding** including envelope, header, and body component analysis
2. **SMTP security assessment** covering spoofing detection and mail relay investigation
3. **Professional tool proficiency** using MXToolbox Email Header Analyzer for forensic analysis
4. **Header forensics capabilities** extracting IP addresses, routing information, and authentication data
5. **Social engineering detection** identifying CEO fraud and supplier impersonation attacks
6. **Enterprise security correlation** analyzing email threats within corporate security frameworks

---

## Business Scenario

You are a SOC analyst at ComTech, a technology services company, responsible for investigating suspicious email activities reported by employees. Recent security awareness training has resulted in increased reporting of potentially malicious emails, including suspected phishing attempts and social engineering attacks. Your objective is to conduct comprehensive email header analysis to determine the legitimacy of reported emails, identify spoofing attempts, and provide actionable intelligence for incident response and security awareness programs.

---

## Theoretical Foundation

### Email Architecture Components

Modern email communication relies on a three-component structure that enables both functionality and security analysis opportunities for cybersecurity professionals.

![Email Components Diagram](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-email-components-diagram.png)

**Email Component Analysis:**

**Envelope Layer:**
- Contains SMTP routing information (To/From addresses for delivery)
- Processed by mail servers during transmission
- Not visible to end users but accessible through header analysis
- Critical for identifying spoofing attempts and mail relay investigation

**Header Section:**
- Metadata container including sender information, timestamps, and routing data
- Contains authentication records (SPF, DKIM, DMARC results)
- Provides forensic evidence for email investigation and threat analysis
- Includes "Received" chains showing complete email transmission path

**Body Content:**
- Actual message content visible to recipients
- May contain malicious links, attachments, or social engineering content
- Subject to content filtering and malware scanning
- Often used in conjunction with header analysis for comprehensive threat assessment

### SMTP Security Vulnerabilities

The Simple Mail Transfer Protocol (SMTP) contains inherent security weaknesses that enable email spoofing and impersonation attacks commonly exploited by threat actors.

**MAIL FROM Command Exploitation:**
SMTP communication utilizes command-based interaction between email clients and servers. The MAIL FROM command specifies the sender's email address but lacks authentication verification, enabling attackers to specify fraudulent sender addresses without technical restrictions.

**Spoofing Attack Methodology:**
Threat actors exploit SMTP's trust-based design by manipulating the MAIL FROM command to impersonate legitimate senders, including:
- Corporate executives (CEO fraud campaigns)
- Trusted suppliers and business partners  
- Financial institutions and service providers
- Internal IT support and administrative personnel

**Defense Strategy:**
Email header analysis provides the primary detection mechanism for spoofing attempts by examining "Received" headers that document the actual transmission path, revealing discrepancies between claimed and actual message origins.

---

## Lab Exercises

### Exercise 1: Outlook Email Header Investigation

#### Task 1.1: Email Header Access and Analysis

**Objective:** Master email header extraction techniques using Microsoft Outlook for forensic investigation.

**Investigation Scenario:** A ComTech employee has received a "Phishing Awareness Email" during security training. Your task is to analyze the email headers to identify routing information and verify message authenticity.

**Access Credentials:**
- **Username:** emmanuel.toller@commensuratetechnology.com
- **Password:** ********

**Email Header Extraction Procedure:**

1. **Launch Microsoft Outlook** and authenticate using provided credentials
2. **Locate Phishing Awareness Email** in the inbox for header analysis
3. **Access message details** by clicking the downward arrow in the email's top-right corner
4. **Select "View message details"** to display complete header information

![Outlook Phishing Email View](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-outlook-phishing-email-view.png)

**Header Analysis Interface:**

![Outlook Message Details Access](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-outlook-message-details-access.png)

**Forensic Investigation Results:**

![Email Headers Raw Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-email-headers-raw-analysis.png)

**Investigation Question:**
**What is one of the IP addresses that the email was received from?**

**Analysis Results:**
- **Source IP Address:** 10.255.255.254
- **Routing Context:** Internal mail server infrastructure
- **Security Assessment:** Legitimate internal training email delivery

**Forensic Value:** IP address extraction from "Received" headers provides critical routing information for email authenticity verification and threat actor infrastructure identification during security investigations.

---

### Exercise 2: Professional Email Analysis with MXToolbox

#### Task 2.1: MXToolbox Email Header Analyzer Implementation

**Objective:** Utilize industry-standard email analysis tools for comprehensive header examination and security assessment.

**Tool Introduction:** MXToolbox provides professional-grade email analysis capabilities used by security professionals for monitoring, investigating, and analyzing email infrastructure. The Email Header Analyzer component transforms raw header data into human-readable format with diagnostic information including hop delays, anti-spam results, and authentication status.

**MXToolbox Analysis Interface:**

![MXToolbox Header Analyzer](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-mxtoolbox-header-analyzer.png)

**Analysis Procedure:**
1. **Navigate to MXToolbox Email Header Analyzer** (mxtoolbox.com/EmailHeaders.aspx)
2. **Extract complete email headers** from Phishing Awareness Email
3. **Paste header content** into MXToolbox analysis interface
4. **Execute comprehensive analysis** and review diagnostic results

**Professional Analysis Results:**

![MXToolbox Results Overview](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-mxtoolbox-results-overview.png)

#### Task 2.2: Advanced Header Metadata Analysis

**Objective:** Extract specific metadata elements for comprehensive email security assessment.

**Detailed Analysis Results:**

![MXToolbox Priority Importance Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-mxtoolbox-priority-importance-analysis.png)

**Investigation Questions:**

1. **What is the Priority of the email?**
   - **Analysis Result:** Normal priority level (standard business communication)

2. **What is the Importance of the email?**
   - **Analysis Result:** Normal importance designation (routine security training)

3. **What domain is listed in the X-MS-Exchange-Organization-AuthSource header value?**
   - **Analysis Result:** commensuratetechnology.com (legitimate internal domain)

**Security Assessment:** Email metadata analysis confirms legitimate internal communication with appropriate priority levels and authentic domain authentication, consistent with authorized security training activities.

---

### Exercise 3: Suspicious Email Investigation

#### Task 3.1: Supplier Impersonation Analysis

**Objective:** Investigate suspected supplier impersonation attack using advanced email forensics techniques.

**Investigation Scenario:** Emmanuel Toller has received an email claiming to be from TechLake, a known ComTech supplier. The email contains an urgent invoice with an executable attachment, triggering security awareness protocols and requiring immediate analysis.

**Social Engineering Indicators:**
- **Urgency tactics** designed to bypass security procedures
- **Executable attachment** (.exe file) disguised as invoice
- **External sender warning** indicating non-internal origin
- **Pressure techniques** encouraging immediate action

![TechLake Suspicious Email](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-techlake-suspicious-email.png)

**Analysis Procedure:**
1. **Extract email headers** from suspected TechLake communication
2. **Utilize MXToolbox analysis** for comprehensive header examination
3. **Identify sender authentication** and routing anomalies
4. **Correlate findings** with known supplier communication patterns

**Investigation Question:**
**Which email address was the email sent from?**

**Forensic Analysis:** Header examination reveals sender address discrepancies and authentication failures, confirming supplier impersonation attempt requiring immediate security response and user education.

#### Task 3.2: CEO Fraud Investigation

**Objective:** Conduct advanced investigation of executive impersonation attack using professional forensic techniques.

**Investigation Scenario:** Emmanuel has received a follow-up email allegedly from ComTech CEO Hewie Westly, claiming the TechLake invoice is legitimate and requesting immediate payment. This represents a sophisticated CEO fraud attempt requiring comprehensive analysis.

**CEO Fraud Attack Methodology:**
- **Executive impersonation** using spoofed display names
- **Authority exploitation** leveraging organizational hierarchy
- **Social pressure tactics** encouraging policy violations
- **Financial fraud objectives** targeting unauthorized payments

**Advanced Forensic Analysis:**

![CEO Fraud Email Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab01-ceo-fraud-email-analysis.png)

**Critical Analysis Elements:**
- **Display Name Spoofing:** Email client shows executive name and profile
- **Reply-To Header Manipulation:** Response directed to threat actor address
- **Authentication Bypass:** Spoofed sender information bypassing casual inspection

**Investigation Question:**
**What is the Reply-To email address?**

**Forensic Results:** Reply-To header analysis reveals external threat actor address, confirming CEO fraud attempt with sophisticated social engineering tactics designed to exploit organizational trust and authority structures.

**Security Response:** Immediate incident escalation required with executive notification, security awareness reinforcement, and email filtering rule implementation to prevent similar attacks.

---

## Technical Assessment

### Email Forensics Proficiency
- Email header extraction and analysis using Microsoft Outlook professional interface
- Raw header interpretation for IP address identification and routing analysis
- Professional tool utilization for comprehensive email security assessment

### Security Tool Mastery
- MXToolbox Email Header Analyzer implementation for diagnostic analysis
- Metadata extraction and interpretation for priority, importance, and authentication verification
- Industry-standard workflow integration for enterprise security operations

### Threat Detection Capabilities
- SMTP spoofing identification through header analysis and authentication verification
- Social engineering attack recognition including urgency tactics and authority exploitation
- CEO fraud detection using Reply-To header analysis and sender verification techniques

### Professional Investigation Skills
- Systematic email forensics methodology for comprehensive threat assessment
- Multi-source analysis correlation between header data and threat intelligence
- Evidence-based security recommendations for incident response and prevention

---

## SOC Applications

### Operational Use Cases
- **Email Incident Response:** Systematic investigation of reported phishing and social engineering attempts
- **Supplier Communication Verification:** Authentication of vendor and partner email communications
- **Executive Impersonation Detection:** CEO fraud and authority-based social engineering identification
- **Security Awareness Support:** Technical validation of user-reported suspicious email activities

### Security Metrics Enhancement
- **Email Authentication Monitoring:** SPF, DKIM, and DMARC validation for organizational email security
- **Threat Actor Infrastructure Identification:** IP address and routing analysis for threat intelligence correlation
- **Social Engineering Pattern Recognition:** Attack methodology documentation for security awareness training
- **Incident Response Automation:** Header analysis integration with SIEM and security orchestration platforms

### Enterprise Security Integration
- **Email Security Gateway Configuration:** Header analysis results integration with filtering and quarantine systems
- **User Education Program Support:** Real-world attack examples for security awareness training enhancement
- **Threat Intelligence Enrichment:** Email-based threat actor attribution and infrastructure mapping
- **Compliance Documentation:** Email forensics evidence collection for regulatory and legal requirements

---

## Lab Completion

**Skills Validated:**
- Email architecture understanding and component analysis for security assessment
- Professional email header analysis using Microsoft Outlook and MXToolbox
- SMTP spoofing detection and authentication verification techniques
- Social engineering attack identification including CEO fraud and supplier impersonation
- Advanced forensic analysis using Reply-To header examination and metadata correlation

**Technical Competencies:**
- Enterprise email client proficiency for security investigation workflows
- Industry-standard security tool utilization for comprehensive email analysis
- Systematic forensic methodology for email-based threat investigation
- Professional documentation and evidence collection for incident response activities

**Professional Applications:**
- SOC analyst email investigation workflows for enterprise security operations
- Security awareness training support using real-world attack examples
- Incident response procedures for email-based security threats
- Threat intelligence correlation and infrastructure analysis capabilities

---

*This foundational laboratory establishes essential email forensics skills required for SOC operations, providing practical experience with professional security tools and real-world attack scenarios commonly encountered in enterprise environments.*
