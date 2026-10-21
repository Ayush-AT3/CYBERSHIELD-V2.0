# CyberShield: Smart Web Security System for Phishing Detection

![GitHub release (latest by date)](https://img.shields.io/github/v/release/yourusername/cybershield)
![License](https://img.shields.io/github/license/yourusername/cybershield)
![Java 17](https://img.shields.io/badge/Java-17-orange)
![Spring Boot 3](https://img.shields.io/badge/Spring%20Boot-3.0-green)

## 📖 Overview
CyberShield is a **real‑time phishing detection platform** built with Spring Boot 3 and Java 17. It provides two scanning paths:
- **⚡ Fast‑Path** – lightweight hybrid‑ML inference (TF‑IDF + Random‑Forest) for sub‑second triage of emails and URLs.
- **🔬 Deep‑Path** – a five‑layer forensic engine that extracts rich indicators, calculates Shannon entropy, and produces an explainable risk score.

The system stores every scan in an embedded **H2 database**, which we expose through an **Admin Panel** (formerly H2 Console). A modern SPA UI visualises risk scores, forensic findings and historical audit logs.

## ✨ Key Features
- Unified hybrid‑ML model for both email and URL analysis.
- Real‑time live scan (< 40 ms) and deep scan (< 350 ms).
- Explainable AI (XAI) – each risk decision is backed by transparent evidence.
- Interactive dashboard with cumulative risk gauge, layer‑wise breakdown, and advisory actions.
- Full‑stack Maven project – easy to build, test, and extend.

## 📦 Tech Stack
| Layer | Technology |
|------|------------|
| Backend | Spring Boot 3, Java 17, Maven 3.9, H2 Database |
| Frontend | HTML5, Tailwind CSS, Vanilla JS (ES6) |
| ML | TF‑IDF + Random‑Forest (trained on Kaggle Phishing, Nazario, PhishTank) |
| DevOps | Maven Wrapper, Git, GitHub Actions (CI) |

## 🛠️ Prerequisites
- **Java 17** (set `JAVA_HOME`)
- **Maven 3.9+** (the wrapper is included)
- **Git** (for source control)
- **Internet** (to download Maven dependencies on first build)

## 🚀 Quick Start (Windows PowerShell)
```powershell
# 1️⃣ Clone the repository (once you have created it on GitHub)
git clone https://github.com/yourusername/cybershield.git
cd .\cybershield

# 2️⃣ Build the application (skip tests for a fast build)
./mvnw.cmd package -DskipTests

# 3️⃣ Run the JAR
java -jar target\cybershield-phishing-detection-1.0.0-SNAPSHOT.jar
```
The service starts on **http://localhost:8085**. Open the UI in a browser and explore the **Admin Panel** at `http://localhost:8085/h2-console` (now labelled *Admin Panel*).

## 🧪 Running Tests
```powershell
./mvnw.cmd test
```
All 29 unit/integration tests should pass.

## 📂 Project Structure
```
cybershield/
├─ src/main/java/               # Java source code
│  └─ com/cybershield/...       # Controllers, Services, Models
├─ src/main/resources/static/   # SPA assets (HTML, CSS, JS)
│  ├─ index.html                # Main UI page
│  └─ js/app.js                # Front‑end logic
├─ src/main/resources/          # application.properties, DB schema
├─ pom.xml                       # Maven build descriptor
└─ README.md                     # This file
```

## 📸 Screenshots & UI Mockups
Add screenshots to the `screenshots/` folder and reference them below:

![Home Dashboard](screenshots/home.png)
*Home screen with risk gauge and navigation tabs.*

![Admin Panel](screenshots/admin-panel.png)
*Admin Panel (formerly H2 Console) displaying audit history.*

## 🔗 API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan/email` | Scan an email body (fast‑path or deep‑path based on toggle). |
| `POST` | `/api/scan/url`   | Scan a URL string. |
| `GET`  | `/api/scan/db-history` | Retrieve historic scans stored in the Admin Panel. |

## 🤝 Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/awesome‑feature`).
3. Commit your changes with clear messages.
4. Open a Pull Request targeting `main`.
5. Follow the **Code of Conduct** and ensure all tests pass.

## 📄 License
This project is licensed under the **MIT License** – see the `LICENSE` file for details.

---
*Generated with assistance from Google Antigravity.*