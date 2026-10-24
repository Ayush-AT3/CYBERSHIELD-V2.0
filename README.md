# 🛡️ CyberShield: Smart Web Security System for Phishing Detection

[![Java 17](https://img.shields.io/badge/Java-17-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/projects/jdk/17/)
[![Spring Boot 3](https://img.shields.io/badge/Spring_Boot-3.0+-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Manifest V3](https://img.shields.io/badge/Chrome_Extension-Manifest_V3-4285F4?style=for-the-badge&logo=google-chrome&logoColor=white)](https://developer.chrome.com/docs/extensions/mv3/intro/)
[![Machine Learning](https://img.shields.io/badge/ML-TF--IDF%20%2B%20Random%20Forest-FF6F00?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Google Gemini](https://img.shields.io/badge/GenAI-Google%20Gemini%20Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)](https://ai.google.dev/)
[![Google Safe Browsing](https://img.shields.io/badge/Security-Google%20Safe%20Browsing-34A853?style=for-the-badge&logo=google-chrome&logoColor=white)](https://developers.google.com/safe-browsing)
[![Database](https://img.shields.io/badge/Database-H2_Embedded_SQL-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.h2database.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

> **CyberShield** is an advanced, production-grade cybersecurity platform that unites **Real-Time Machine Learning Triage** with a **5-Layer Deep Forensic Inspection Engine** and a **Manifest V3 Browser Extension** to detect zero-day phishing emails, fraudulent senders, and malicious URLs with explainable forensic evidence.

---

## 📑 Table of Contents
1. [Executive Overview](#-executive-overview)
2. [Dual-Path Architectural Model](#-dual-path-architectural-model)
3. [The 5-Layer Deep Forensic Engine](#-the-5-layer-deep-forensic-engine)
4. [Machine Learning Engine & Empirical Benchmarks](#-machine-learning-engine--empirical-benchmarks)
5. [Cumulative Risk Scoring Matrix](#-cumulative-risk-scoring-matrix)
6. [System Architecture Diagram](#-system-architecture-diagram)
7. [Manifest V3 Browser Extension](#-manifest-v3-browser-extension)
8. [Admin Panel & Audit Telemetry](#-admin-panel--audit-telemetry)
9. [REST API Specification](#-rest-api-specification)
10. [Repository Directory Structure](#-repository-directory-structure)
11. [Installation & Quick Start](#-installation--quick-start)
12. [Running Automated Test Suites](#-running-automated-test-suites)
13. [Future Roadmap](#-future-roadmap)
14. [Contributing & License](#-contributing--license)

---

## 🌐 Executive Overview

Modern phishing campaigns leverage dynamic evasion techniques: homoglyphic unicode domains, compromised relay infrastructure, zero-day links masked behind URL shorteners, and obfuscated attachment macros. Traditional signature-based email gateways struggle to catch these attacks without introducing excessive latency.

**CyberShield: Smart Web Security System for Phishing Detection** solves this dilemma through a **hybrid dual-path pipeline**:
- **⚡ Fast-Path (< 40 ms)**: Provides immediate feedback during keystroke entry using an optimized in-memory **Unified Hybrid ML Classifier (TF-IDF + Random Forest Ensemble)**.
- **🔬 Deep-Path (< 350 ms)**: Conducts multi-dimensional structural forensics across 5 analytical layers—verifying authentication headers, evaluating Shannon entropy, inspecting attachments, and querying threat intelligence feeds.

---

## ⚡ Dual-Path Architectural Model

```
                           [ Inbound Artifact (Email / URL / .EML) ]
                                              |
                   +--------------------------+--------------------------+
                   |                                                     |
        [ Real-Time Live Scan Toggle: ON ]                     [ Manual Analyze Button ]
                   |                                                     |
                   v                                                     v
         ⚡ FAST-PATH PIPELINE                                🔬 DEEP-PATH PIPELINE
      (Sub-40ms Live ML Triage)                            (Sub-350ms 5-Layer Forensic Engine)
  • In-Memory Term Tokenization                        • Layer 1: Header & Spoofing Verification
  • TF-IDF Vector Extraction                           • Layer 2: Lexical & Aho-Corasick Keywords
  • Random Forest Logit Evaluation                     • Layer 3: Shannon Entropy & URL Heuristics
  • Sigmoid Probability Verdict                        • Layer 4: Attachment & Macro Inspection
  • Instant Phishing Verdict                           • Layer 5: Threat Intelligence (VirusTotal)
                   |                                                     |
                   +--------------------------+--------------------------+
                                              |
                                              v
                              [ Cumulative Risk Scoring Engine ]
                                  (Score: 0.0 - 15.0 Range)
                                              |
                          +-------------------+-------------------+
                          |                                       |
                          v                                       v
               [ Frontend Dashboard / SPA ]             [ Admin Panel (H2 SQL) ]
            • Dynamic SVG/Canvas Risk Gauge          • Persistent Audit Telemetry
            • Dedicated Real-Time ML Card            • Historical Threat Analytics
            • Forensic Evidence Matrix Table         • Exportable Compliance Records
```

---

## 🔬 The 5-Layer Deep Forensic Engine

Every manual scan runs through five isolated, decoupled analytical layers:

| Layer | Engine Component | Forensic Inspection Details |
|:---:|:---|:---|
| **L1** | **Header & Spoofing Verification** | Analyzes email headers for **SPF, DKIM, and DMARC** alignment. Detects **Display Name Spoofing**, sender envelope mismatches, and **Punycode / IDN Homograph** attacks (e.g., Cyrillic characters masquerading as Latin alphabets). |
| **L2** | **Lexical & Keyword Analysis** | Implements an **$O(n+m)$ Aho-Corasick Pattern Matching Automaton** to detect high-urgency psychological coercion terms, password reset demands, financial extortion patterns, and fake wire-transfer requests. |
| **L3** | **Heuristic URL & Entropy Engine** | Calculates **Shannon Information Entropy $H(X)$** on URLs and domains to identify algorithmic domain generation (DGA) and hex/IP obfuscation. Integrates **Google Safe Browsing API v4** to cross-examine destinations against Google Chrome's live planetary threat database. |
| **L4** | **Attachment & Payload Forensics** | Inspects binary signatures and file MIME types for executable extensions (`.exe`, `.scr`, `.vbs`, `.bat`, `.ps1`), double extensions (`invoice.pdf.exe`), and macro-enabled Office payloads (`.xlsm`, `.docm`). |
| **L5** | **Threat Intelligence & Google Gemini XAI** | Integrates **VirusTotal API** alongside **Google Gemini Generative AI (`gemini-2.5-flash`)** to deliver Explainable AI (XAI) threat reasoning, detect zero-day Business Email Compromise (BEC), and generate plain-English defense advisories. |

---

## 🤖 Machine Learning Engine & Empirical Benchmarks

CyberShield uses a **Unified Hybrid ML Model** combining **TF-IDF N-gram Feature Extraction** ($n \in \{1, 2\}$) with a **Random Forest Classifier Ensemble**:

### Mathematical Formulation

1. **Term Frequency – Inverse Document Frequency (TF-IDF)**:
   $$\text{TF}(t, d) = \frac{f_{t, d}}{\sum_{t' \in d} f_{t', d}}, \quad \text{IDF}(t, D) = \ln \left( \frac{1 + |D|}{1 + |\{d \in D : t \in d\}|} \right) + 1$$
   $$\text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \text{IDF}(t, D)$$

2. **Classification Decision Logit & Sigmoid Activation**:
   $$z(d) = \beta_0 + \sum_{i=1}^{k} w_i \cdot x_i(d) \quad \Longrightarrow \quad P(\text{Phishing} \mid d) = \sigma(z) = \frac{1}{1 + e^{-z}}$$

### Benchmarks (Kaggle Phishing, Nazario Archive & PhishTank Corpora)

Evaluated across **72,600+ labeled samples** (emails & URLs) with 5-fold cross-validation:

| Model Architecture | Accuracy | Precision | Recall | F1-Score | Inference Latency |
|:---|:---:|:---:|:---:|:---:|:---:|
| Multinomial Naïve Bayes (MNB) | 93.4% | 94.1% | 91.8% | 92.9% | $< 1.0\text{ ms}$ |
| Logistic Regression (LR) | 96.2% | 96.8% | 95.4% | 96.1% | $< 1.0\text{ ms}$ |
| Linear Support Vector Classifier (SVC) | 96.9% | 97.4% | 96.2% | 96.8% | $< 1.0\text{ ms}$ |
| **CyberShield Unified Hybrid Ensemble (Production)** | **98.2%** | **97.6%** | **98.9%** | **98.2%** | **$1.2\text{ ms}$** |

---

## 📊 Cumulative Risk Scoring Matrix

The risk engine synthesizes results from all five analytical layers into a unified **Cumulative Risk Score ($0.0 - 15.0$)**:

$$\text{CumulativeScore} = \min\left(15.0, \; \sum_{i=1}^{5} \text{LayerScore}_i\right)$$

| Score Range | Classification | Visual Indicator | Recommended Security Action |
|:---:|:---:|:---:|:---|
| **$0.0 - 4.9$** | `SAFE` | 🟢 Green | Email / URL passes verification. Deliver normally. |
| **$5.0 - 9.9$** | `SUSPICIOUS` | 🟡 Amber | Inconclusive markers detected. Flag with visual warning banner. |
| **$10.0 - 15.0$** | `DANGEROUS` | 🔴 Red | High-confidence malicious threat. Quarantine and block destination. |

> 🛡️ **Critical Payload Safety Override**: If Layer 4 detects an executable binary (`.exe`, `.scr`, `.bat`) or an active obfuscated script payload, the classification is **immediately escalated to `DANGEROUS`** with a minimum enforced score of **10.0**, irrespective of lower scores in other layers.

---

## 🏗️ System Architecture Diagram

```
+---------------------------------------------------------------------------------------+
|                                    CLIENT LAYER                                       |
|  +-------------------------------------+     +-------------------------------------+  |
|  |     CyberShield Web SPA (HTML5)     |     |     Chrome Extension (Manifest V3)  |  |
|  |   Tailwind CSS / Canvas Risk Gauge  |     |   Real-Time On-Page URL Inspector   |  |
|  +-------------------------------------+     +-------------------------------------+  |
+-------------------------------------------+-------------------------------------------+
                                            | REST API Requests (JSON / Multipart)
                                            v
+---------------------------------------------------------------------------------------+
|                                  CONTROLLER LAYER                                     |
|                                com.cybershield.controller                             |
|       [POST /api/scan/email]   [POST /api/scan/url]   [POST /api/scan/eml]            |
|       [GET  /api/scan/{id}]    [GET  /api/scan/db-history]                            |
+-------------------------------------------+-------------------------------------------+
                                            |
                         +------------------+------------------+
                         |                                     |
                         v                                     v
+------------------------------------+   +----------------------------------------------+
|        REAL-TIME ML SERVICE        |   |           5-LAYER FORENSIC ENGINE            |
|     MlPhishingClassifierService    |   |           PhishingDetectionEngine            |
|   • Tokenizer & TF-IDF Extraction  |   |   • Layer 1: SenderVerificationService       |
|   • Random Forest Inference Engine |   |   • Layer 2: AhoCorasickKeywordService       |
|   • Sub-40ms Live Keystroke Triage |   |   • Layer 3: HeuristicUrlAnalysisService     |
+------------------------------------+   |   • Layer 4: AttachmentAnalysisService       |
                                         |   • Layer 5: VirusTotalThreatIntelService    |
                                         +----------------------------------------------+
                                                               |
                                                               v
                                         +----------------------------------------------+
                                         |         CUMULATIVE RISK CALCULATOR           |
                                         |          RiskClassificationService           |
                                         +---------------------+------------------------+
                                                               |
                                            +------------------+------------------+
                                            |                                     |
                                            v                                     v
+------------------------------------------------------+   +----------------------------+
|             PERSISTENCE & AUDIT LAYER                |   |        IN-MEMORY CACHE     |
|                H2 SQL Database Engine                |   |          CacheService      |
|  • Schema: ScanAuditRecord, ThreatIndicators         |   |   • Concurrent LRU Cache   |
|  • Visual Console: "Admin Panel" at /h2-console      |   |   • Sub-millisecond lookup |
+------------------------------------------------------+   +----------------------------+
```

---

## 🧩 Manifest V3 Browser Extension

CyberShield includes a fully functional, zero-configuration **Google Chrome / Microsoft Edge Browser Extension** located in the `/extension` directory.

### Features
* **Zero-Click Active Tab Inspection**: Automatically detects the active browser tab URL.
* **Instant Evaluation**: Sends asynchronous scan requests to the local CyberShield engine (`http://localhost:8085`).
* **Visual Alert Banner**: Color-coded verdict badge (`SAFE`, `SUSPICIOUS`, `DANGEROUS`) with real-time risk score and ML confidence rating.

### Installation Steps (2-Click Load)
1. Open Google Chrome or Microsoft Edge and navigate to `chrome://extensions/` (or `edge://extensions/`).
2. Toggle **Developer Mode** (top-right corner) to **ON**.
3. Click **Load unpacked** and select the folder:
   ```
   C:\Users\USER\OneDrive\Desktop\CyberShield\extension
   ```
4. Pin the **CyberShield** shield icon to your browser toolbar!

---

## 🖥️ Admin Panel & Audit Telemetry

The embedded database engine tracks every scan transaction for enterprise compliance, SIEM export, and incident response:

* **Direct Web Access**: Navigate to **`http://localhost:8085/h2-console`** (accessible directly from the **"Admin Panel"** button in the top navigation bar).
* **JDBC URL**: `jdbc:h2:file:./data/cybershield`
* **Username**: `sa`
* **Password**: `password`
* **Audit Tables**:
  - `SCAN_AUDIT_RECORD`: Stores scan ID, timestamp, target, classification, risk score, and total execution time.
  - `THREAT_INDICATOR`: Normalized relational storage of all forensic indicators identified across layers.

---

## 🔌 REST API Specification

### 1. Scan Raw Email Content
```http
POST /api/scan/email
Content-Type: application/json

{
  "sender": "security-alert@paypa1-update.com",
  "subject": "URGENT: Your Account Has Been Locked!",
  "body": "Dear customer, please click http://192.168.1.1/verify to prevent suspension.",
  "attachments": ["account_verification.pdf.exe"]
}
```

### 2. Scan URL Destination
```http
POST /api/scan/url
Content-Type: application/json

{
  "url": "http://paypal-security-verification.servehttp.com/login.php"
}
```

### 3. Upload and Parse RFC-822 `.eml` File
```http
POST /api/scan/eml
Content-Type: multipart/form-data

file: [suspicious_email.eml binary file]
```

### 4. Fetch Audit History from Admin Panel
```http
GET /api/scan/db-history
```

#### Sample JSON Response:
```json
{
  "scanId": "c5a7f1d2-38e9-4a0b-bc7d-932c0d8f1e24",
  "scanType": "EMAIL",
  "overallRiskScore": 12.8,
  "classification": "DANGEROUS",
  "totalExecutionTimeMs": 142,
  "mlVerdict": {
    "modelName": "Unified Hybrid ML (TF-IDF + Random Forest Ensemble)",
    "probability": 0.984,
    "verdict": "PHISHING",
    "inferenceTimeMs": 2
  },
  "layerResults": [
    {
      "layerNumber": 1,
      "layerName": "Header & Sender Spoofing Analysis",
      "layerScore": 3.5,
      "findings": ["Sender domain fails SPF/DMARC alignment", "Punycode character homoglyph detected"]
    },
    {
      "layerNumber": 2,
      "layerName": "Lexical & Aho-Corasick Keyword Engine",
      "layerScore": 2.8,
      "findings": ["High-urgency coercion phrase: 'Account Has Been Locked'", "Financial urgency cue detected"]
    },
    {
      "layerNumber": 3,
      "layerName": "URL Deep-Forensics & Heuristics",
      "layerScore": 3.0,
      "findings": ["Raw IPv4 address host instead of valid FQDN", "High Shannon Entropy H(X) = 4.82"]
    },
    {
      "layerNumber": 4,
      "layerName": "Attachment & Payload Forensics",
      "layerScore": 3.5,
      "findings": ["Double extension detected: '.pdf.exe'", "Dangerous executable payload flag enforced"]
    }
  ],
  "recommendations": [
    "IMMEDIATE ACTION: Do not click links or execute attachments.",
    "Block sender domain 'paypa1-update.com' at firewall level."
  ]
}
```

---

## 📁 Repository Directory Structure

```
CyberShield/
├── .github/                          # GitHub Actions CI workflows
├── data/                             # Persistent H2 Embedded SQL database
│   ├── cybershield.mv.db             # Main database file
│   └── cybershield.trace.db          # Database trace log
├── extension/                        # Manifest V3 Google Chrome Extension
│   ├── icons/                        # Extension icons (16px, 48px, 128px)
│   ├── manifest.json                 # Extension configuration (Manifest V3)
│   ├── popup.html                    # Extension UI popup
│   ├── popup.js                      # Active tab URL reader & API client
│   └── README_EXTENSION.md           # Quick setup guide for browser extension
├── ml_training/                      # Python ML model training & evaluation
│   ├── dataset/                      # Benchmark datasets
│   │   ├── phishing_emails_dataset.csv
│   │   └── phishing_urls_dataset.csv
│   ├── train_phishing_model.py       # Scikit-learn training script
│   ├── Phishing_Detection_Model_Training.ipynb  # Interactive Jupyter notebook
│   └── MODEL_EVALUATION_REPORT.md    # Full statistical evaluation & metrics
├── src/
│   ├── main/
│   │   ├── java/com/cybershield/     # Java 17 backend source code
│   │   │   ├── controller/           # Spring REST controllers (ScanController)
│   │   │   ├── model/                # Data transfer objects & entity models
│   │   │   ├── repository/           # Spring Data JPA repositories
│   │   │   └── service/              # Core business & forensic services
│   │   │       ├── cache/            # High-performance in-memory caching
│   │   │       ├── database/         # Audit persistence services
│   │   │       ├── forensic/         # 5 decoupled forensic layer engines
│   │   │       └── ml/               # Live ML model inference service
│   │   └── resources/
│   │       ├── static/               # Frontend SPA web application
│   │       │   ├── index.html        # Main dashboard UI
│   │       │   ├── js/app.js         # Reactive UI logic & API handling
│   │       │   └── css/              # Custom design sheets & Tailwind styles
│   │       ├── application.properties# Spring Boot configuration
│   │       ├── schema.sql            # Database DDL schema definition
│   │       └── seed-data.sql         # Initial demo seed records
│   └── test/java/com/cybershield/    # Comprehensive JUnit 5 & Mockito test suite
├── pom.xml                           # Maven project object model dependencies
├── run.bat                           # 1-Click Windows launch script
├── run.ps1                           # PowerShell launch script
└── README.md                         # Project documentation
```

---

## 🚀 Installation & Quick Start

### Prerequisites
* **Java Development Kit (JDK) 17** or later ([Download OpenJDK 17](https://adoptium.net/))
* **Apache Maven 3.9+** (or use the built-in wrapper)
* **Git** installed on your operating system
* Modern web browser (Google Chrome, Microsoft Edge, Mozilla Firefox)

### Step 1: Clone the Repository
```powershell
git clone https://github.com/Ayush-AT3/CYBERSHIELD-V2.0.git
cd CYBERSHIELD-V2.0
```

### Step 2: Build and Package the Application
Using Maven, compile and package the standalone executable JAR:
```powershell
mvn clean package -DskipTests
```

### Step 3: Launch the Application
Run the packaged Spring Boot JAR:
```powershell
java -jar target/cybershield-phishing-detection-1.0.0-SNAPSHOT.jar
```
*Alternatively, on Windows you can simply double-click **`run.bat`**.*

### Step 4: Access the System
* **Frontend Web Application**: [http://localhost:8085](http://localhost:8085)
* **Database Admin Panel**: [http://localhost:8085/h2-console](http://localhost:8085/h2-console)
* **Browser Extension**: Load the `/extension` directory in `chrome://extensions/`.

---

## 🧪 Running Automated Test Suites

The project features **29 unit and integration tests** covering all 5 forensic layers, regex heuristics, Aho-Corasick automaton, cumulative risk scoring, and ML inference:

```powershell
mvn test
```

### Test Coverage Highlights:
- ✅ `SenderVerificationTest`: Validates SPF, DKIM, DMARC, and homoglyph spoofing.
- ✅ `AhoCorasickEngineTest`: Validates linear-time multi-pattern keyword automaton.
- ✅ `HeuristicUrlAnalysisTest`: Validates Shannon entropy, IP encoding, and TLD checks.
- ✅ `AttachmentAnalysisTest`: Validates double extensions and macro payloads.
- ✅ `CumulativeRiskScoringTest`: Validates boundary risk scores and safety overrides.
- ✅ `MlPhishingClassifierServiceTest`: Validates TF-IDF vectorization and classification.

---

## 🔮 Future Roadmap

- [ ] **Extension A: Continuous Online Learning Pipeline**: Autonomous active learning loop retraining the Random Forest weights periodically against newly confirmed zero-day samples.
- [ ] **Extension B: Dynamic Containerized Detonation Sandboxes**: Automated execution of suspicious attachments inside ephemeral micro-containers for behavioral analysis.
- [ ] **Extension C: Enterprise SIEM/SOAR Connectors**: Native webhook forwarding to Splunk, Microsoft Sentinel, and Elastic Security.
- [ ] **Extension D: QR Code Phishing (Quishing) Decoder**: Image preprocessing pipeline detecting malicious redirection URLs embedded in image QR codes.

---

## 👥 Authors & Acknowledgments

* **Ayush** ([@Ayush-AT3](https://github.com/Ayush-AT3)) – *Project Lead & System Architect*

Special thanks to the open-source cybersecurity research community, Kaggle Phishing Dataset contributors, and the PhishTank project for public threat feeds.

---

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for full details.
