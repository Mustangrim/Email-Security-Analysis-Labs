# Email Challenge Lab 02: Multi-Threat Email Investigation and Advanced Analysis

## Lab Overview

**Lab Focus:** Comprehensive multi-scenario email threat investigation using professional security tools and advanced forensic techniques  
**Difficulty:** Intermediate    
**Author:** Mykyta Palamarchuk  
**Role:** SOC Analyst | Email Security Specialist & Threat Intelligence Researcher  
**Certification:** CompTIA Security+ (SY0-701)

### Environment Specifications
- **Platform:** Microsoft Outlook with enterprise email infrastructure and professional security tools
- **Administrative Privileges:** Email forensics access with attachment analysis capabilities
- **Business Context:** ComTech corporate environment with multi-department threat investigation
- **Technology Focus:** Advanced email analysis, malware detection, SPF/DKIM validation, threat intelligence correlation

---

## Learning Objectives

Upon completion of this lab, participants will demonstrate:

1. **Advanced email forensics proficiency** including multi-tool analysis correlation and threat attribution
2. **Malware detection capabilities** using VirusTotal analysis and attachment investigation techniques
3. **Authentication protocol mastery** covering SPF, DKIM, and DMARC validation for spoofing detection
4. **Threat intelligence integration** utilizing URLscan.io, G Suite Toolbox, and MXToolbox for comprehensive analysis
5. **Social engineering investigation** identifying Bitcoin extortion, credential harvesting, and impersonation attacks
6. **Enterprise incident response** coordinating multi-department security investigations and threat containment

---

## Business Scenario

You are a Level 1 SOC Analyst at ComTech responsible for investigating a series of sophisticated email threats reported by employees across multiple departments. Recent attacks have included Google account phishing, malicious invoice attachments, account compromise notifications, Bitcoin extortion attempts, and corporate impersonation campaigns. Your objective is to conduct comprehensive forensic analysis of each reported email, determine attack methodologies, identify threat actor infrastructure, and provide actionable intelligence for enterprise security response and user awareness programs.

---

## Lab Exercises

### Exercise 1: Google Account Phishing Investigation

#### Task 1.1: Suspicious Email Analysis and IP Identification

**Objective:** Investigate Google account strengthening phishing attempt with comprehensive header analysis and threat attribution.

**Investigation Scenario:** Glenda Backus, Personnel Specialist at ComTech, has forwarded a suspicious email claiming to be from Google requesting account strengthening. The email attachment preserves header information for forensic investigation. Initial analysis indicates the linked page is not functioning as expected, suggesting potential phishing activity.

**Access Credentials:**
- **Username:** emmanuel.toller@commensuratetechnology.com
- **Password:** t0tallySecre7?

**Investigation Procedure:**
1. **Access ComTech email system** using provided credentials
2. **Locate "This looks weird" email** from Glenda Backus
3. **Download email attachment** for comprehensive forensic analysis
4. **Extract email headers** using text editor for manual analysis

**Email Header Analysis:**

![Email Attachment Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-email-attachment-analysis.png)

**Investigation Questions:**

**Question 1: What is the IP address that delivered the email to your email server?**

**Forensic Analysis Results:**
- **Delivery IP Address:** 69.168.97.48
- **Routing Analysis:** External delivery source requiring further investigation
- **Threat Intelligence:** IP address correlation with known phishing infrastructure

#### Task 1.2: SPF Authentication Analysis Using G Suite Toolbox

**Objective:** Utilize professional email authentication tools for SPF validation and sender verification.

**G Suite Toolbox Analysis:**

![G Suite Toolbox Interface](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-gsuite-toolbox-interface.png)

**Analysis Procedure:**
1. **Copy complete email header content** from downloaded attachment
2. **Navigate to G Suite Toolbox** email analysis interface
3. **Paste header information** for comprehensive authentication analysis
4. **Review SPF validation results** and authentication status

**Authentication Analysis Results:**

![G Suite Analysis Results](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-gsuite-analysis-results.png)

**SPF Status Analysis:**

![SPF Status Softfail](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-spf-status-softfail.png)

**Question 2: According to G Suite Toolbox, what is the SPF status?**

**Authentication Results:**
- **SPF Status:** softfail with IP Unknown!
- **Security Assessment:** Email sent from unauthorized IP address not explicitly authorized by domain SPF record
- **Threat Indicator:** SPF softfail suggests potential spoofing or compromised sending infrastructure

#### Task 1.3: Malicious URL Identification and Analysis

**Objective:** Extract and analyze suspicious URLs from email content using professional URL analysis tools.

**URL Extraction Process:**

![URL Extractor Tool](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-url-extractor-tool.png)

**URL Analysis Procedure:**
1. **Utilize URL Extractor tool** (miniwebtool.com/url-extractor/)
2. **Paste complete email content** for comprehensive URL extraction
3. **Identify suspicious URLs** that deviate from legitimate Google infrastructure
4. **Document malicious URLs** for threat intelligence correlation

**Malicious URL Detection:**

![Malicious URL Extracted](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-malicious-url-extracted.png)

**Question 3: Which URL stands out as malicious in this email?**

**Threat Analysis Results:**
- **Malicious URL:** http://router-0cad8d00-3843-4f68-9764-b243b4457d97.westeurope.cloudapp.azure.com
- **Infrastructure Analysis:** Azure cloud hosting with suspicious subdomain structure
- **Attack Vector:** Google login page impersonation hosted on compromised infrastructure

#### Task 1.4: URLscan.io Threat Classification

**Objective:** Utilize professional URL reputation analysis for attack type classification and threat assessment.

**URLscan.io Analysis:**

![URLscan Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-urlscan-analysis.png)

**Threat Classification Results:**

![Phishing Attack Confirmed](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-phishing-attack-confirmed.png)

**Question 4: If you scan the malicious URL with urlscan.io, what type of attack is this?**

**Threat Intelligence Results:**
- **Attack Classification:** Phishing
- **Target Brand:** Google account services
- **Threat Assessment:** Credential harvesting campaign targeting corporate users
- **Security Response:** Immediate URL blocking and user awareness notification required

---

### Exercise 2: Malicious Invoice Investigation

#### Task 2.1: VirusTotal Malware Analysis

**Objective:** Investigate suspicious invoice attachment using professional malware analysis tools and scripting language identification.

**Investigation Scenario:** ComTech accounting department received an invoice from unknown company and forwarded to security team for verification before opening attachment. Initial assessment suggests potential malware distribution campaign targeting financial processes.

**Investigation Procedure:**
1. **Locate "This does not look right" email** in investigation queue
2. **Download suspicious attachment** for malware analysis
3. **Upload attachment to VirusTotal** for comprehensive security scanning
4. **Analyze categorization tags** for malware characteristics identification

**VirusTotal Analysis Results:**

![VirusTotal JavaScript Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-virustotal-javascript-analysis.png)

**Question: According to VirusTotal in the categorization tags at the top of the results page, which scripting language is used by the malware that is attached to the email?**

**Malware Analysis Results:**
- **Scripting Language:** JavaScript
- **Threat Classification:** Malicious document with embedded JavaScript
- **Attack Vector:** Document-based malware targeting accounting processes
- **Security Response:** Attachment quarantine and user education required

---

### Exercise 3: Account Compromise Investigation

#### Task 3.1: Threatening Email Analysis and FQDN Investigation

**Objective:** Investigate account compromise notification for legitimacy assessment and threat actor infrastructure analysis.

**Investigation Scenario:** Glenda Backus received threatening email claiming account compromise. Analysis required to determine legitimacy and identify potential extortion campaign characteristics.

**Investigation Procedure:**
1. **Locate "Have I really been hacked?" email** for forensic analysis
2. **Extract email headers** using established procedures
3. **Identify "Received: from" FQDN** for sender infrastructure analysis
4. **Assess domain legitimacy** and threat actor attribution

**Email Header Analysis:**

![Email Headers FQDN Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-email-headers-fqdn-analysis.png)

**FQDN Investigation Results:**

![Suspicious Domain Hackzed](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-suspicious-domain-hackzed.png)

**Question: What is the origin "Received: from" FQDN?**

**Threat Intelligence Results:**
- **Origin FQDN:** serv1.youarehackzed.ga
- **Domain Analysis:** Suspicious domain with deceptive naming (hackzed vs hacked)
- **Threat Assessment:** Scam campaign using intimidation tactics and deceptive infrastructure
- **Security Response:** Domain blocking and user reassurance required

---

### Exercise 4: Bitcoin Extortion Investigation

#### Task 4.1: Delivery Time Analysis and IP Investigation

**Objective:** Investigate Bitcoin demand email for legitimacy assessment using delivery time analysis and sender infrastructure investigation.

**Investigation Scenario:** Edie Eads from Sales received Bitcoin demand letter requiring analysis to determine threat legitimacy and appropriate security response.

**Investigation Procedure:**
1. **Locate "Is it true, does someone know?" email** for analysis
2. **Utilize MXToolbox** for comprehensive delivery analysis
3. **Extract delivery timing information** from email headers
4. **Identify sender IP address** for threat intelligence correlation

**MXToolbox Delivery Analysis:**

![MXToolbox Delivery Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-mxtoolbox-delivery-analysis.png)

**Delivery Time Investigation:**

![Delivery Time 282 Days](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-delivery-time-282-days.png)

**Email Header Analysis:**

![Bitcoin Email Headers](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-bitcoin-email-headers.png)

**Investigation Questions:**

**Question 1: According to MX Toolbox, how long did it take for this email to arrive?**
- **Delivery Time:** 24364800 seconds (approximately 282 days)
- **Analysis:** Anomalous delivery time indicating potential email spoofing or system manipulation

**Question 2: What is the IP address that delivered the email to your email server?**
- **Delivery IP:** 133.242.140.203
- **Threat Assessment:** Extended delivery time suggests fraudulent email characteristics

---

### Exercise 5: Corporate Brand Impersonation Investigation

#### Task 5.1: FedEx Spoofing Analysis and Legitimate Infrastructure Comparison

**Objective:** Investigate FedEx billing email for corporate brand impersonation using comparative analysis with legitimate infrastructure.

**Investigation Scenario:** Accounting department received FedEx billing email requiring verification against legitimate FedEx infrastructure to identify potential impersonation campaign.

**Investigation Procedure:**
1. **Locate "Something wrong here" email** for FedEx billing analysis
2. **Extract "Received: from" IP address** from email headers
3. **Utilize MXToolbox SuperTool** to identify legitimate FedEx mail server infrastructure
4. **Compare suspicious IP** with legitimate FedEx infrastructure

**FedEx Header Analysis:**

![FedEx Headers Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-fedex-headers-analysis.png)

**Legitimate FedEx Infrastructure Verification:**

![MXToolbox FedEx Legitimate IP](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-mxtoolbox-fedex-legitimate-ip.png)

**Investigation Questions:**

**Question 1: What is the first "Received: from" IP address of Fedex_Billing.eml?**
- **Suspicious IP:** 135.101.115.149
- **Source Analysis:** Non-FedEx infrastructure indicating impersonation attempt

**Question 2: According to MX Toolbox SuperTool, what is the actual FedEx mail server IP address?**
- **Legitimate FedEx IP:** 204.135.242.58
- **Comparison Analysis:** Significant discrepancy confirming FedEx impersonation campaign

---

### Exercise 6: Credential Harvesting Investigation

#### Task 6.1: Helpdesk Impersonation and Reply-To Analysis

**Objective:** Investigate helpdesk credential request for internal impersonation campaign using advanced header analysis and reply path investigation.

**Investigation Scenario:** Mary Robert from R&D forwarded suspicious helpdesk email requesting credentials, violating company security policy and requiring immediate investigation.

**Investigation Procedure:**
1. **Locate "IT asking for our credentials?" email** for analysis
2. **Extract sender IP address** from email headers
3. **Analyze Reply-To header** for response destination analysis
4. **Utilize G Suite Toolbox** for delivery time analysis

**Helpdesk Header Analysis:**

![Helpdesk Headers Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-helpdesk-headers-analysis.png)

**Reply-To Spoofing Investigation:**

![Reply-To Spoofing](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-reply-to-spoofing.png)

**G Suite Delivery Analysis:**

![G Suite Delivery Time](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-gsuite-delivery-time.png)

**Investigation Questions:**

**Question 1: The attached Helpdesk_Request.eml email appears to come from helpdesk@commensuratetechnology.com, what is the message origin IP?**
- **Origin IP:** 117.4.117.46
- **Analysis:** External IP suggesting helpdesk impersonation attempt

**Question 2: If you reply to this email, who will actually receive it?**
- **Reply-To Address:** helpdesk@comnensuratetechnology.com
- **Spoofing Analysis:** Typosquatting domain (comnensuratetechnology vs commensuratetechnology)

**Question 3: According to G Suite Toolbox, what is the result of "delivered after"?**
- **Delivery Time:** 7 hours
- **Analysis:** Extended delivery time for internal communication indicating external routing

---

### Exercise 7: Microsoft Account Security Investigation

#### Task 7.1: Legitimate Email Verification Using Comprehensive Authentication Analysis

**Objective:** Investigate Microsoft app connection notification for legitimacy using multi-tool authentication verification and IP reputation analysis.

**Investigation Scenario:** Winnifred Forrest from R&D received Microsoft email regarding new app connection requiring verification to determine legitimacy and appropriate security response.

**Investigation Procedure:**
1. **Locate "New app connection?" email** for Microsoft legitimacy analysis
2. **Extract sender IP address** using MXToolbox analysis
3. **Utilize ipinfo.io** for IP ownership verification
4. **Perform SPF and DKIM validation** using MXToolbox tools

**Microsoft Email Analysis:**

![Microsoft MXToolbox Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-microsoft-mxtoolbox-analysis.png)

**IP Address Investigation:**

![Microsoft IP Analysis](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-microsoft-ip-analysis.png)

**IP Ownership Verification:**

![IPInfo Company Lookup](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-ipinfo-company-lookup.png)

**SPF Authentication Verification:**

![SPF Check Results](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-spf-check-results.png)

![SPF Pass Status](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-spf-pass-status.png)

**DKIM Authentication Verification:**

![DKIM Check Results](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-dkim-check-results.png)

![DKIM Pass Status](https://raw.githubusercontent.com/Mustangrim/Email-Security-Analysis-Labs/main/assets/screenshots/lab02-dkim-pass-status.png)

**Investigation Questions:**

**Question 1: What is the first "Received: from" IP address of New_app_connected_to_your_Microsoft_account.eml?**
- **Sender IP:** [Analysis from MXToolbox results]
- **Infrastructure:** Microsoft legitimate infrastructure

**Question 2: According to ipinfo.io, what is the origin IP's company name?**
- **Company:** Microsoft Corporation
- **Verification:** Legitimate Microsoft infrastructure confirmed

**Question 3: According to MX Toolbox, what is the result of SPF Syntax Check?**
- **SPF Status:** Pass
- **Authentication:** Valid SPF record with authorized sender

**Question 4: According to MX Toolbox, what is the result of DKIM Syntax Check?**
- **DKIM Status:** Pass
- **Authentication:** Valid DKIM signature confirming message integrity

**Legitimacy Assessment:** Comprehensive authentication analysis confirms legitimate Microsoft communication with valid SPF/DKIM signatures and authorized infrastructure.

---

## Technical Assessment

### Advanced Email Forensics Proficiency
- Multi-scenario threat investigation using coordinated analysis tools and techniques
- Email attachment analysis including malware detection and scripting language identification
- Comprehensive header analysis for IP extraction, FQDN investigation, and routing analysis
- Professional tool integration including G Suite Toolbox, MXToolbox, VirusTotal, and URLscan.io

### Authentication Protocol Mastery
- SPF validation and failure analysis for spoofing detection and sender verification
- DKIM signature verification for message integrity and authentication validation
- Multi-tool authentication correlation for comprehensive legitimacy assessment
- Domain comparison analysis for typosquatting and impersonation detection

### Threat Intelligence Integration
- URL reputation analysis using URLscan.io for phishing campaign identification
- IP address investigation using ipinfo.io for infrastructure attribution and ownership verification
- Malware analysis using VirusTotal for threat classification and scripting language identification
- Delivery time analysis for anomaly detection and fraud identification

### Social Engineering Investigation
- Bitcoin extortion analysis including timing anomaly detection and infrastructure assessment
- Corporate impersonation investigation covering FedEx, Microsoft, and internal helpdesk spoofing
- Credential harvesting detection using Reply-To header analysis and typosquatting identification
- Multi-department threat correlation for enterprise-wide security assessment

---

## SOC Applications

### Operational Use Cases
- **Multi-Threat Email Investigation:** Coordinated analysis of sophisticated email campaigns targeting multiple departments
- **Brand Impersonation Detection:** Corporate identity theft identification including FedEx, Google, and Microsoft spoofing
- **Authentication Failure Analysis:** SPF/DKIM validation failure investigation for spoofing detection and prevention
- **Malware Distribution Investigation:** JavaScript-based malware detection in document attachments and email content

### Security Metrics Enhancement
- **Threat Campaign Correlation:** Multi-scenario attack pattern identification for threat actor attribution
- **Authentication Protocol Effectiveness:** SPF/DKIM success rates and failure analysis for email security optimization
- **URL Reputation Integration:** Phishing URL detection rates and threat intelligence correlation for proactive blocking
- **Social Engineering Success Rates:** User reporting effectiveness and security awareness training impact assessment

### Enterprise Security Integration
- **Email Security Gateway Enhancement:** Multi-tool analysis integration for automated threat detection and quarantine
- **User Awareness Program Development:** Real-world attack examples for comprehensive security training programs
- **Incident Response Coordination:** Multi-department threat investigation procedures and communication protocols
- **Threat Intelligence Platform Integration:** Email-based IOC extraction and threat actor infrastructure mapping

---

## Lab Completion

**Skills Validated:**
- Advanced multi-scenario email threat investigation using professional security tools
- Comprehensive malware analysis including VirusTotal integration and scripting language identification
- Authentication protocol validation including SPF, DKIM, and sender verification techniques
- Social engineering detection covering Bitcoin extortion, credential harvesting, and corporate impersonation
- Threat intelligence correlation using URL reputation, IP analysis, and infrastructure attribution

**Technical Competencies:**
- Professional security tool integration including G Suite Toolbox, MXToolbox, VirusTotal, and URLscan.io
- Advanced email forensics including header analysis, attachment investigation, and authentication validation
- Multi-department incident coordination and threat assessment for enterprise security operations
- Comprehensive documentation and evidence collection for security incident response and user education

**Professional Applications:**
- SOC analyst multi-threat investigation workflows for complex email security incidents
- Enterprise incident response coordination across multiple departments and threat vectors
- Security awareness training development using real-world attack examples and professional analysis
- Threat intelligence integration and infrastructure analysis for proactive security enhancement

---

*This intermediate laboratory develops advanced email security analysis skills through comprehensive multi-scenario investigations, preparing SOC analysts for complex enterprise threat environments and sophisticated attack campaigns.*
