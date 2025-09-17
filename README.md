# NPM Attack Detector

This tool helps detect whether your project is affected by the recent **npm supply chain attack** that compromised multiple popular packages (`chalk`, `debug`, `strip-ansi`, etc.).  
It scans your project for **known malicious versions** as well as suspicious **obfuscated code patterns** that may indicate compromise.

## 🚨 Background
A number of popular npm packages were compromised and republished with malicious code designed to **intercept cryptocurrency transactions** and exfiltrate sensitive data.  
Anyone installing these versions may have been exposed accidentally. This detector provides a quick way to audit your environment.

---

## 📦 Features
- Detects **known malicious versions** of compromised packages.  
- Scans **package.json** and **package-lock.json** for suspicious dependencies.  
- Searches installed code for **obfuscation / malicious behavior signatures**.  
- Works cross-platform:
  - ✅ macOS (Apple Silicon + Intel)  
  - ✅ Windows (x64)  
  - ✅ Linux  

---

## 🔧 Installation
Clone or download the repository and place the detector in your project root.

Requirements:
- Python 3.7+  

---

## ▶️ Usage
Run the provided helper script depending on your system:

### On macOS / Linux
```bash
chmod +x run_detector.sh
./run_detector.sh
```

### On Windows
```bat
run_detector.bat
```

Alternatively, run Python directly:
```bash
python3 npm_attack_detector.py
```

---

## 📋 Output
- Generates a **detection report** showing:
  - Compromised package versions found  
  - Obfuscated malicious patterns detected  
  - Severity rating (Critical / High / Medium / Clean)  

Example output:
```
[CRITICAL] Found malicious package: chalk v5.2.0
[HIGH] Detected obfuscated eval() usage in node_modules/strip-ansi
[CLEAN] No suspicious patterns detected in other packages
```

---

## 🚑 What to Do if Compromised
If the report shows **CRITICAL** or **HIGH severity findings**:
1. **Immediately disconnect** the affected system from the internet  
2. **Uninstall compromised packages** from `node_modules` and lockfiles  
3. **Audit and restore cryptocurrency accounts/wallets** if applicable  
4. Rotate any potentially exposed **API keys or credentials**  
5. Reinstall safe versions with:
   ```bash
   npm install chalk@&lt;safe_version&gt;
   ```

---

## ⚠️ Disclaimer
This tool is a **best-effort detection utility** based on known IOCs (Indicators of Compromise).  
It is **not a substitute for a full SCA (Software Composition Analysis) or malware scan**.  
Always validate package integrity manually before production deployments.
