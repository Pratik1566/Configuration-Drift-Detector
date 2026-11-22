# AI-Assisted Configuration Drift Detector

An AI-assisted configuration drift detection platform that identifies differences between current server configurations and approved security baselines. It detects potential security misconfigurations, evaluates risks, and uses AI to explain detected issues.

The application supports both custom security baselines and a built-in standard security baseline.

## 🚀 Features

- **Configuration Drift Detection:** Compares current configurations against approved baselines.
- **Custom Baseline:** Upload your own configuration baseline for comparison.
- **Standard Security Baseline:** Use predefined security rules when you do not have a custom baseline.
- **Security Risk Assessment:** Identifies potential security issues and evaluates their risk.
- **AI-Powered Explanations:** Uses AI to explain detected configuration changes and potential risks.
- **Dual AI Provider Support:**
  - Ollama for locally running AI models.
  - Google Gemini for cloud-based AI explanations.
- **Manual Verification:** Marks checks that require manual review.
- **Review Decisions:** Allows findings to be reviewed and recorded.
- **Dashboard:** Displays configuration analysis and security findings.
- **Report Generation:** Supports JSON, CSV, and PDF reports.
- **Automated Testing:** Includes tests for important project functionality.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Streamlit | User interface |
| Ollama | Local AI inference |
| Google Gemini | Cloud-based AI inference |
| Qwen2.5:3B | Local language model |
| JSON | Configuration and baseline data |
| CSV | Report generation |
| PDF | Report generation |
| Pytest | Automated testing |
| Git & GitHub | Version control |

## 📂 Project Structure

```text
Drift_Detector-Project-0-/
│
├── app.py
├── core.py
├── ui.py
│
├── ai_provider.py
├── ai_explainer.py
├── explain.py
│
├── security_baseline.py
├── data.py
├── ssh_drift.py
├── ssh_parser.py
│
├── tests/
│
├── reports/
├── .streamlit/
│
├── baseline.json
├── current.json
├── baseline_sshd_config
├── current_sshd_config
├── sample_sshd_config
│
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## ⚙️ Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Pratik1566/Drift_Detector-Project-0-.git
cd Drift_Detector-Project-0-
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

### 3. Activate the Virtual Environment

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure the AI Provider

The application supports two AI providers:

**Option A: Ollama (Local AI)**

1. Install Ollama from https://ollama.com/
2. Pull the Qwen2.5 model:

```bash
ollama pull qwen2.5:3b
```

3. Make sure Ollama is running on your machine.

**Option B: Google Gemini (Cloud AI)**

1. Obtain a Google Gemini API key.
2. Configure the API key using the environment variable or Streamlit secrets setting expected by the application.
3. Keep API keys private. Never commit them to GitHub.

### 6. Run the Application

```bash
python -m streamlit run app.py
```

The application will open in your browser.

## 🔍 How It Works

1. **Select a Baseline:** Upload a custom baseline or choose the built-in standard security baseline.
2. **Provide Configuration:** Upload or select the current configuration files for analysis.
3. **Detect Drift:** The detection engine compares the current configuration with the selected baseline.
4. **Evaluate Risk:** Identified differences are evaluated using predefined security rules.
5. **AI Explanation:** The selected AI provider explains relevant findings.
6. **Review Findings:** Users can review findings and record decisions.
7. **Generate Reports:** Export the analysis in JSON, CSV, or PDF format.

## 🧠 AI Architecture

The project combines rule-based configuration analysis with AI-generated explanations.

- **Rule-Based Engine:** Performs the actual configuration comparison and identifies potential drift.
- **Ollama:** Provides local AI inference using a locally hosted model.
- **Google Gemini:** Provides cloud-based AI explanations.
- **AI Explanation Layer:** Converts technical findings into understandable explanations.

AI explanations complement the rule-based detection engine; they do not replace its security checks.

## ☁️ Deployment

The application can be deployed using Streamlit Community Cloud.

For cloud deployment:

- Push the project to a GitHub repository.
- Connect the repository to Streamlit Community Cloud.
- Set the main application file to `app.py`.
- Configure the required Gemini API key through the deployment's secrets settings if using Gemini.
- Do not commit API keys or other secrets.

**Note:** A locally running Ollama instance on your computer is not automatically accessible to a cloud-hosted application. Use a supported cloud AI provider, such as Gemini, for cloud deployment unless you have separately configured a secure and accessible Ollama service.

## 🔐 Security Considerations

- Do not upload confidential production configuration files to an untrusted environment.
- Never expose API keys, passwords, or private credentials.
- Review detected findings before making configuration changes.
- The application is designed for configuration analysis and reporting; it does not automatically modify production server configurations.

## 🔮 Future Improvements

- Support for additional server configuration formats.
- Expanded security baseline coverage.
- More detailed risk analysis.
- Additional AI provider integrations.
- Improved reporting and visualization.
- Extended automated test coverage.

## 👨‍💻 Repository

GitHub: https://github.com/Pratik1566/Drift_Detector-Project-0-

## 📄 License

This project is distributed under the license included in this repository.