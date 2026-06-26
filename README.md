# ⚙️ JS Arsenal 

**JS Arsenal** by *Pankajkryadav* is a powerful, multi-processed graphical tool designed for Bug Bounty Hunters and Security Researchers. It automatically analyzes JavaScript files (via URLs) to extract sensitive information, endpoints, secrets, and potential vulnerabilities.

Built with Python and a sleek CustomTkinter interface, JS Arsenal scales to handle thousands of URLs rapidly by leveraging multiprocessing.

## ✨ Features

- **Fast & Multi-processed**: Utilizes all available CPU cores to fetch and analyze URLs concurrently.
- **Sleek GUI**: Modern, user-friendly interface powered by `customtkinter`.
- **All-in-One SecretFind**: A curated master regex that grabs endpoints, secrets, cloud URLs, subdomains, JS APIs, emails, and parameters in one go.
- **Scope Filtering**: Only process URLs that match specific keywords (e.g., `api.example.com`, `example`).
- **Detailed Reporting**: Exports results cleanly into categorized `.txt` files and generates a beautiful `.html` report.
- **Customizable**: Toggle exactly what you want to search for, or add your own custom regex patterns.

## 🧰 Extraction Capabilities

JS Arsenal categorizes its extraction modules into three main tabs:

### 🕵️ Common Recon
- Endpoints & Paths
- Parameters
- Subdomains
- Email Addresses
- Source Code Comments
- Technology Fingerprinting
- Third-Party Integrations

### 🔬 Advanced Analysis
- Cloud URLs (S3, Azure, GCS, etc.)
- JavaScript Variables
- Form Endpoints (`action=`)
- Copyright & Version Info
- Social Media Links
- JavaScript API Endpoints (`fetch`, `axios`)
- GraphQL Schema Discovery

### 🏹 Vulnerability Hunting
- Secrets & API Keys
- JSON Web Tokens (JWTs)
- Security Header Analysis
- Vulnerability Code Patterns (`.innerHTML`, `dangerouslySetInnerHTML`, etc.)
- `postMessage` Listener Discovery
- **Custom Regex Search**

## ⚙️ Installation

1. **Clone the repository** (or download the files):
   ```bash
   git clone https://github.com/pankajkryadav/js-arsenal.git
   cd js-arsenal
   ```

2. **Install the dependencies**:
   Make sure you have Python 3 installed. Then run:
   ```bash
   pip install -r Requirements.txt
   ```

## 🚀 How to Use

1. **Launch the application**:
   ```bash
   python main.py
   ```
2. **Input URLs**: 
   - Click **Browse...** to select a `.txt` file containing a list of JS URLs (one URL per line).
   - *OR* paste your URLs directly into the provided text box.
3. **Configure Scope (Optional)**: Enable the Scope Filter and provide keywords to only analyze matching URLs.
4. **Select Output Directory**: Click **Browse...** to choose where the results and the HTML report will be saved.
5. **Select Extraction Modules**: Go through the tabs (Common Recon, Advanced Analysis, Vulnerability Hunting) and check the boxes for the data you want to extract.
6. **Start Analysis**: Click the **▶️ START ANALYSIS** button. You can monitor the progress bar and real-time logs in the application.

## 📊 Output format

Once the analysis is complete, navigate to your selected output folder. You will find:
- Individual `.txt` files for each selected category (e.g., `endpoints.txt`, `secrets.txt`).
- `report.html`: A beautiful, styled HTML report summarizing all findings per URL.

## ⚠️ Disclaimer

This tool is created for **educational purposes and ethical security research** only. You must have explicit permission from the target before performing any reconnaissance or security testing. The author is not responsible for any misuse or damage caused by this program.

