## 🕵️‍♂️ **007 Certs - The Ultimate Certificate Analysis Tool**

--------------------------------------------
🔥 **What is 007 Certs?**

Inspired by the legendary secret agent James Bond, 007 Certs is your secret weapon for investigating certificates, detecting insecure pinning, and analyzing suspicious .der files in your apps. Fast, precise, and stylish – the James Bond of certificates. 🕶️

🎯 "Because not every certificate has a license to pass."

🔥 What is 007 Certs?

Inspired by the legendary secret agent James Bond, 007 Certs is your secret weapon for dissecting Android APKs and exposing certificate misuse. Whether you're analyzing leaked private keys, detecting insecure pinning, or scanning for .der files, this tool is built for cyber operatives who leave no key unchecked. 🕶️

🛠️ **Key Features**
✅ **APK Decompilation** – Automatically uses apktool to unpack APKs for analysis.

🔐 **Private Key Validation** – Uses OpenSSL to verify private keys and flags them as CRITICAL if valid.

📜 **Certificate Matching** – Compares certificate + private key pairs using OpenSSL (x509 + rsa) for cryptographic validation.

🔍 **Certificate File Discovery** – Recursively scans for .crt, .pem, and .key files inside the app.

💥 **Executable Inspection** – Searches ELF or Mach-O binaries for embedded SHA-256 hashes and .der references.

📁 **Configuration File Analysis** – Detects references to certificates or weak configurations in .json, .plist, and .xml files.

⚙️ **Advanced Checks** – Finds hardcoded keys, insecure flags (usesCleartextTraffic, debuggable), and pinning mechanisms.

🧠 **Automatic Risk Score** – Assigns a final security risk level: LOW, MEDIUM, HIGH, or CRITICAL.

📊 **Report Generation** – Outputs findings in .txt, .json, and .html, plus a clear human-readable summary.

--------------------------------------------
🚀 **How to Use**


1️⃣ Install OpenSSL (if not already installed):
```
sudo apt install openssl
sudo apt install apktool openssl python3 -y
pip install termcolor

```
2️⃣ Clone this repository:
```
git clone https://github.com/yourusername/007-certs.git
cd 007-certs
```
3️⃣ Run the script and investigate your app:
```
python3 007certs.py /path/to/your.apk

```
Or run it on an already extracted folder:
```
python3 007certs.py /path/to/unpacked/folder
```

![image](https://github.com/user-attachments/assets/8ebda133-2671-499e-91af-ef1df8c08d80)

4️⃣ Check the generated report in analysis_report.txt to uncover hidden secrets. 🕵️

 📝 Sample Output

🚀 Starting analysis with 007Certs...
🔍 Looking for certificates (.crt, .pem, .key)...
🧪 Validating key + certificate pairs...
📂 Scanning configuration files...
📊 Generating final report...
✅ Report saved: analysis_report.txt
📄 Summary saved: analysis_report_summary.txt
🛡️ Final Risk Score: CRITICAL

🔍 What Do the Results Mean?
🔐 **Valid Private Key** → [CRITICAL] → Could allow MitM or spoofing if used in production.

📜 **Public Certificate** → [INFO] → Can indicate backend trust relationships.

❌ **Superficial File** → [POTENTIALLY IRRELEVANT] → No real cert data, just suspicious extension.

⚙️ **Pinning / Validation Detected** → [MODERATE-HIGH] → Might indicate protections or potential bypass points.

🧪 **Matching Cert+Key Pair** → Validated cryptographically via OpenSSL.

--------------------------------------------
🚧 **Run with Docker**

1️⃣ Build the Docker image:
```
docker build -t 007certs .
```

2️⃣ Run the container and analyze your app:
```
docker run --rm -v $(pwd)/data:/app/data 007certs /app/data
```

3️⃣ Check the generated report in the mounted "data" directory.


--------------------------------------------
📝 **Example Output**

![image](https://github.com/user-attachments/assets/4ff57694-afcc-4a7f-9ff7-305749ba397b)

--------------------------------------------

🔎 **What’s Next?**
📌 **What Do Your Findings Mean?**

🟢 **Safe Certificate:** SHA-256 pinning is properly applied. All good. 😎

⚠️ **Issue Detected:** Exposed private keys or weak pinning. 🚨

😂 **Funny Situation:** You spent hours analyzing something irrelevant, but hey, it's all part of the game! 🎭

Ready to dive into the world of certificates? 007 Certs has your back! 🏆


🎖️ License to Certify! 🚀
