🕵️‍♂️ **007 Certs - The Ultimate Certificate Analysis Tool**

--------------------------------------------
🔥 **What is 007 Certs?**

Inspired by the legendary secret agent James Bond, 007 Certs is your secret weapon for investigating certificates, detecting insecure pinning, and analyzing suspicious .der files in your apps. Fast, precise, and stylish – the James Bond of certificates. 🕶️

🎯 "Because not every certificate has a license to pass."

--------------------------------------------
🛠️ **Main Features**

✅ **Hunt for .der Files** – Finds all certificates hidden in your app. 🔎

✅ **Certificate X-Ray** – Detects private keys and verifies SHA-256 pinning. 🏴‍☠️

✅ **Hacking the Executable** – Searches for SHA-256 hashes and hidden references. 💾

✅ **Scans Configuration Files** – Finds traces in .plist, .json, and .xml files. 🗃️

✅ **Comprehensive Report** – Documents all findings for easy analysis. 📑


--------------------------------------------
🚀 **How to Use**


1️⃣ Install OpenSSL (if not already installed):
```
sudo apt install openssl
```
2️⃣ Clone this repository:
```
git clone https://github.com/yourusername/007-certs.git
```
3️⃣ Run the script and investigate your app:
```
python3 certs_007.py /path/to/extracted_directory
```
![image](https://github.com/user-attachments/assets/8ebda133-2671-499e-91af-ef1df8c08d80)

4️⃣ Check the generated report in analysis_report.txt to uncover hidden secrets. 🕵️


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
