# 🛡️ WinLog Detector — SOC Analyst Toolkit

A professional Windows Event Log detection & response toolkit for SOC analysts. Built with Next.js, deployable to Vercel in one click.

## 🚀 Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/YOUR_USERNAME/windows-log-detector)

## ✨ Features

- 🔍 Search by Event ID, name, MITRE technique, or keyword
- 🗂️ Filter by Category, Severity, Log Source
- 💻 Copy-ready PowerShell commands for every event
- 🎯 MITRE ATT&CK mappings
- 🧯 SOC response & remediation steps
- 📤 Export filtered results as JSON
- 🌙 Dark SOC dashboard theme
- 📱 Responsive design

## 📦 Covered Events

| Event ID | Name | Category |
|----------|------|----------|
| 4625 | Failed Login | Authentication |
| 4624 | Successful Login | Authentication |
| 4672 | Special Privileges Assigned | Privilege Escalation |
| 4720 | User Account Created | Account Management |
| 4726 | User Account Deleted | Account Management |
| 4688 | Process Creation | Process |
| 5156 | Network Connection Allowed | Network |
| 4663 | File/Object Access | File System |
| 4104 | PowerShell Script Block Logging | PowerShell |
| 4103 | PowerShell Module Logging | PowerShell |
| 6416 | USB Device Inserted | Device |
| 6005 | System Startup | System |
| 6006 | System Shutdown | System |
| Sysmon 1 | Process Create | Process |
| Sysmon 3 | Network Connection | Network |
| Sysmon 11 | File Creation | File System |

## 🛠️ Local Development

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

## 📁 Project Structure

```
windows-log-detector/
├── pages/
│   ├── _app.js          # Global styles
│   └── index.js         # Main page
├── components/
│   ├── Header.js        # Search bar + actions
│   ├── Sidebar.js       # Filter panel
│   ├── EventCard.js     # Event detail card
│   └── StatsBar.js      # Stats summary bar
├── data/
│   └── events.js        # Full event dataset
├── public/
│   └── favicon.ico
├── package.json
├── next.config.js
└── vercel.json
```

## 📤 Deploy Steps

1. Push this repo to GitHub
2. Go to [vercel.com](https://vercel.com)
3. Click "New Project" → Import your GitHub repo
4. Click Deploy — done! ✅

No environment variables needed.

---

Built for SOC analysts, cybersecurity students, and freelance portfolio projects.
