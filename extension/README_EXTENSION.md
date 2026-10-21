# CyberShield Real-Time Chrome Extension Setup Guide

This browser extension provides **Real-Time Active Web Protection** by evaluating active browser URLs against the **CyberShield 5-Layer Hybrid & AI/ML Detection Engine** running on `http://localhost:8085`.

---

## How to Install in Google Chrome or Microsoft Edge (2-Click Load)

1. Open **Google Chrome** (or Edge).
2. In the address bar, navigate to:
   ```
   chrome://extensions/
   ```
   *(For Microsoft Edge: `edge://extensions/`)*
3. Enable **Developer Mode** in the top right corner.
4. Click the button: **"Load unpacked"**.
5. Select the `extension` folder located inside your CyberShield project:
   ```
   C:\Users\USER\OneDrive\Desktop\CyberShield\extension
   ```
6. The extension **CyberShield - Real-Time Phishing Protection** is now loaded! Pin the shield icon to your browser toolbar.

---

## How to Demonstrate Real-Time Protection to Your Guide

1. Make sure the CyberShield application is running (double-click `run.bat` or run via VS Code).
2. Open any website in your browser (e.g. `https://google.com` or a test phishing URL).
3. Click the **CyberShield shield icon** in your Chrome toolbar.
4. The extension instantly shows:
   - **Active Web Destination URL**
   - **Real-Time 5-Layer Risk Score** (0.0 to 15.0 scale)
   - **AI/ML Model Verdict & Confidence** (`LEGITIMATE` / `PHISHING` with percentage)
   - **Color-coded verdict banner** (Green for Safe, Amber for Suspicious, Red for Dangerous)
