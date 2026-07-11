<div align="center">

[🇬🇧 English](./README_EN.md) | [🇮🇷 فارسی](./README_FA.md)

</div>

<div align="center">

# 🛡️ Proxy Pro Advanced

### ⚡ A powerful, all-in-one proxy collector, tester & manager

**Version `v1.0.7`** • Built with ❤️ for speed, accuracy and simplicity

![Node](https://img.shields.io/badge/Node.js-%E2%89%A518-339933?style=for-the-badge&logo=node.js&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)
![Made with love](https://img.shields.io/badge/Made%20with-%E2%9D%A4-red?style=for-the-badge)

</div>

---

## 🌟 What is Proxy Pro Advanced?

**Proxy Pro Advanced** is a professional command-line tool that helps you:

- 🔎 **Collect** thousands of proxies from public and private sources
- ⚙️ **Test** them at high speed with smart concurrency
- 🎯 **Sort & filter** the ones that actually work
- 🔐 **Handle** authenticated (user/pass) proxies safely and separately
- 📁 **Export** clean, ready-to-use lists (`alive.txt`, `alive_with_auth.txt`, and more)

Whether you are a **beginner** running your first test or an **advanced user** who needs high concurrency, geo-filtering and anonymity checks — this tool has you covered.

---

## ✨ Highlights

| 🚀 Feature | 📖 Description |
|---|---|
| **Smart Public Collector** | Grabs fresh proxies from curated public sources |
| **Private Sources** | Add your own private lists (with or without user/pass) |
| **Two-Phase Testing** | First quick TCP check, then deep HTTP validation |
| **Anonymity Detection** | Elite / Anonymous / Transparent classification |
| **Geo Lookup** | Detects country of each working proxy |
| **Auth Proxies Support** | Full `user:pass@host:port` handling |
| **Separate Auth Output** | Auth proxies exported to their own dedicated file |
| **Balanced / Fast / Deep Modes** | Pick the trade-off between speed and accuracy |
| **Beautiful CLI** | Modern colored menu with keyboard shortcuts |

---

## 📦 Installation (for Beginners)

### 1️⃣ Install Node.js (once)
Download the **LTS** version from [nodejs.org](https://nodejs.org) and install it.

### 2️⃣ Download this tool
Click the green **Code → Download ZIP** button on GitHub and extract it.

### 3️⃣ Run the installer (Windows)
Double-click **`INSTALL_FIRST.bat`** and wait a few seconds.

### 4️⃣ Start the tool
Double-click **`RUN.bat`** — that's it! 🎉

> 💡 **Linux / macOS users:** open a terminal in the folder and run:
> ```bash
> npm install
> node proxy-pro.js
> ```

---

## 🎮 Main Menu Tour

```
┌────────────────────────────────────────────────┐
│   Mode : balanced  Two-Phase: on  Conc: 150    │
│   Anon: on  Geo: on                            │
├────────────────────────────────────────────────┤
│  1) Collect proxies (Smart / Private / Both)   │
│  2) Test proxies                               │
│  3) View results                               │
│  4) Settings                                   │
│  H) Help — full guide                          │
│  0) Exit                                       │
└────────────────────────────────────────────────┘
```

### 🧭 Quick usage
1. Press **`1`** to collect proxies (choose Smart, Private, or Both)
2. Press **`2`** to test them
3. Press **`3`** to view the results folder

---

## 📂 Output Files

After a test finishes, you'll find these files in the `results/` folder:

| 📄 File | 🎯 Contents |
|---|---|
| `alive.txt` | All working **public** proxies (no auth) |
| `alive_with_auth.txt` | Working **authenticated** proxies with **full `user:pass`** visible |
| `dead.txt` | Proxies that failed |
| `summary.txt` | Full test statistics |
| `by_country/` | Alive proxies split per country |
| `by_anonymity/` | Elite / Anonymous / Transparent buckets |

> 🔒 **Privacy note:** `alive_with_auth.txt` shows full credentials because it's *your* file on *your* machine. Never share it publicly.

---

## ⚙️ Configuration

Open **`config.json`** to tweak:

- 🧵 `concurrency` — how many proxies to test in parallel (default `150`)
- ⏱️ `timeoutMs` — per-request timeout
- 🎚️ `mode` — `fast` / `balanced` / `deep`
- 🌍 `geo` — enable/disable country lookup
- 🕶️ `anonymity` — enable/disable anonymity classification

---

## 🆘 Troubleshooting

<details>
<summary><b>❓ The menu feels stuck</b></summary>

Update to **v1.0.7** — menu input was hardened so number choices work normally after test/stop prompts.
</details>

<details>
<summary><b>❓ Authenticated proxies aren't being detected</b></summary>

Make sure they're in the format `user:pass@host:port` or `host:port:user:pass`.
</details>

<details>
<summary><b>❓ Auto-collect keeps mixing my private proxies</b></summary>

Fixed in v1.0.5 — option **5 (Both)** now keeps Private and Smart sources fully isolated.
</details>

---

## 💬 Contact & Feedback

<div align="center">

Have a question, idea, or bug report? Reach out on Telegram:

### 📩 **[@Hunter23_S](https://t.me/Hunter23_S)**

</div>

---

## ⭐ Support the Project

<div align="center">

If **Proxy Pro Advanced** helped you or you liked the project,
please give it a **⭐ Star** on GitHub — it really keeps development going!

### 🌟 **Thank you for your support!** 🌟

</div>
