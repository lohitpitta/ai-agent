# 🛡️ DepGuard AI

### AI-Powered Dependency Vulnerability Scanner

DepGuard AI is a Python-based security tool that scans npm projects for known dependency vulnerabilities.

It analyzes project dependencies, checks for known security issues using the OSV vulnerability database, and generates an HTML security report.

The project also integrates AI-powered decision-making to support vulnerability analysis.

## ✨ Features

- **Dependency Scanning:** Extracts dependency information from npm project files.
- **Vulnerability Detection:** Checks dependencies against the OSV database.
- **Version Matching:** Uses deterministic logic to match package versions with known vulnerabilities.
- **AI-Powered Analysis:** Uses AI-based decision-making to support vulnerability assessment.
- **SQLite Database:** Stores scan information and findings.
- **HTML Reports:** Generates detailed security reports.
- **Streamlit Dashboard:** Provides a simple web interface to run scans and download reports.

## 🛠️ Tech Stack

- Python
- Streamlit
- OSV API
- SQLite
- HTML and CSS
- AI integration

## 📁 Project Structure

```text
DepGuard-AI/
│
├── ai/                  # AI decision-making components
├── database/            # Database operations
├── reports/             # HTML report generation
├── scanner/             # Dependency scanning logic
├── vulnerability/       # Vulnerability lookup and version matching
├── tests/               # Automated tests
│
├── app.py               # Main scanning application
├── ui.py                # Streamlit web dashboard
├── requirements.txt     # Python dependencies
├── .env.example         # Example environment configuration
├── .gitignore           # Git ignore rules
└── README.md            # Project documentation
```

## ⚙️ Requirements

Before getting started, make sure you have:

- Python installed
- Node.js and npm for working with npm projects
- Git
- A GitHub account to clone the repository

## 🚀 Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Move into the project directory:

```bash
cd DepGuard-AI
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\Activate.ps1
```

On Linux or Kali Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

If the project requires API keys or other environment variables, configure them in a local `.env` file using `.env.example` as a reference.

**Never upload your `.env` file or secret API keys to GitHub.**

## 💻 Usage

DepGuard AI provides two ways to work with the scanner.

### Option 1: Command-Line Interface

Run a scan against an npm project:

```bash
python app.py scan "path/to/your/npm-project"
```

For example, on Windows:

```powershell
python app.py scan "D:\Projects\test-project"
```

The scanner analyzes the project dependencies and generates a security report.

### Option 2: Web Dashboard

Start the Streamlit dashboard:

```bash
python -m streamlit run ui.py
```

Then:

1. Open the local URL displayed in the terminal.
2. Enter the path to your npm project.
3. Click **Start Security Scan**.
4. Review the scan output and available results.
5. Download the generated HTML security report.

## 🔍 How It Works

DepGuard AI follows these steps:

1. **Project Input:** Accepts an npm project directory.
2. **Dependency Extraction:** Reads dependency information from project files, including `package-lock.json`.
3. **Vulnerability Lookup:** Queries the OSV database for known vulnerabilities.
4. **Version Matching:** Compares package versions with vulnerability information using deterministic logic.
5. **AI Analysis:** Applies AI-powered decision-making as part of the analysis workflow.
6. **Database Storage:** Stores scan information and findings in SQLite.
7. **Report Generation:** Produces an HTML report containing security findings.

## 📊 Output

The scanner generates an HTML security report containing vulnerability-related findings.

The report helps users review detected issues and investigate potentially vulnerable dependencies.

A finding should be reviewed before deciding whether a dependency needs to be updated.

## 🔐 Security Considerations

- Scan only projects you own or have permission to assess.
- Keep API keys and credentials private.
- Do not commit `.env` files or other secrets.
- Review vulnerability findings before making dependency changes.
- Treat scan results as security guidance, not a guarantee that a project is completely secure.

## 🧪 Testing

Run the automated tests using:

```bash
python -m pytest
```

## 🎯 Project Goal

The goal of DepGuard AI is to make dependency security analysis easier by combining vulnerability database lookups, deterministic version matching, AI-assisted analysis, and readable security reports.

## 👨‍💻 Author

Developed as a cybersecurity project focused on software dependency security and vulnerability analysis.

## 📄 License

Add a license to this repository if you intend to distribute the project under specific reuse permissions.
