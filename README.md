<h1>🛡️ St3wart CLI</h1>
<h3>A Cross-Platform Windows Security Management Tool</h3>

<p>
<img src="https://img.shields.io/badge/Language-PowerShell-blue" alt="PowerShell">
<img src="https://img.shields.io/github/license/johndcode/St3wartCLI" alt="License">
</p>

---

### ✨ Overview  
St3wart is a **lightweight, configurable Windows security management tool**.  
Administrators can define security checks via JSON and automate policy enforcement, vulnerability reporting, and remediation.  

Latest version (`v0.1`) includes:  
- Check and remediate **PowerShell, Registry, and File-based vulnerabilities**  
- Generate actionable **reports**  
- Schedule periodic security checks

For the development story and a detailed writeup, check out the blog post here:  
[A look at my Windows desktop and server vulnerability management tool](https://www.johndcode.com/posts/St3wart/)  

---

### ⚡ Installation
Download the compiled binary from the [GitHub repository](https://github.com/JohnDCode/St3wartCLI-Publish) and add it to your PATH.

---

### 🖥️ Core Features
- **Check** → Scan Windows machines against defined security baselines
- **Secure** → Automatically remediate findings
- **Report** → Generate PDF reports of actions taken
- **Schedule** → Automate recurring checks

---

### 📊 Example JSON Checks
```json
[
{
    "ID": "TEST-001",
    "Description": "Windows Firewall Domain Profile Log Size Configured",
    "CheckType": "PowerShell",
    "CheckCommand": "Get-NetFireWallProfile -Profile Domain | Select-Object -ExpandProperty LogMaxSizeKilobytes",
    "FindData": "16384",
    "Operator": "LessThan",
    "SecureCommand": "Set-NetFirewallProfile -Profile Domain -LogMaxSizeKilobytes 16384"
},
{
    "ID": "TEST-002",
    "Description": "Windows Remote Registry Service Disabled",
    "CheckType": "Registry",
    "Key": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry",
    "Value": "Start",
    "SecureValue": 4,
    "FindData": "4",
    "Operator": "NotEqualTo"
},
{
    "ID": "TEST-003",
    "Description": "SSH Server Config File Disallows Empty Passwords",
    "CheckType": "File",
    "Path": "C:/ProgramData/ssh/sshd_config",
    "SecureText": "PermitEmptyPasswords no",
    "FindData": "PermitEmptyPasswords yes",
    "Operator": "Contains"
}
]
```

---

### ⚙️ Commands & Syntax
Command | Description | Syntax
--- | --- | ---
`check` | Scan a machine for vulnerabilities | `St3wart.exe check [OPTIONS] <JSON BANK PATH>`
`exempt` | Add or remove exemptions | `St3wart.exe exempt [OPTIONS] <ADD/REMOVE> <VULN ID>`
`report` | Generate PDF report for an action | `St3wart.exe report [OPTIONS] <ACTION TYPE> <ACTION GUID>`
`schedule` | Schedule recurring commands | `St3wart.exe schedule [OPTIONS] <COMMAND> <PERIOD TIME IN DAYS>`
`secure` | Automatically remediate findings | `St3wart.exe secure [OPTIONS] <JSON BANK PATH> <CHECK GUID>`
`vuln` | Query a vulnerability's details | `St3wart.exe vuln [OPTIONS] <JSON BANK PATH> <VULN ID>`

---

### 🔮 Roadmap
Planned improvements for future versions:
- Remote scanning across multiple systems
- Support for macOS and Linux
- Enhanced report generation and configurable logs
- Extended scheduling and automation capabilities

---

### 📫 Contact Me  
- 📧 Email: **johndavidabe101@gmail.com**  
- 💼 LinkedIn: [linkedin.com/in/johndcode](https://linkedin.com/in/johndcode)  
- 🧑‍💻 GitHub: [github.com/johndcode](https://github.com/johndcode)  

⭐ If you like this project, consider giving it a star on GitHub!
