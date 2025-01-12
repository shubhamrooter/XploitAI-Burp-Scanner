# XploitAI Burp - Scanner

XploitAI Burp - Scanner is a Burp Suite extension designed to enhance web application security testing by integrating AI-based vulnerability detection and threat intelligence. It automates the process of scanning URLs, detecting vulnerabilities, and generating detailed reports.

---

## Features

- **AI-Powered Vulnerability Detection**: Utilizes machine learning models to predict potential vulnerabilities in web applications.
- **Threat Intelligence Integration**: Cross-checks responses with a threat intelligence database to identify known malicious patterns.
- **Interactive Terminal**: Includes an embedded terminal for executing system commands directly within the extension.
- **Vulnerability Reporting**: Generates comprehensive reports of detected vulnerabilities for further analysis.
- **User-Friendly Interface**: Provides a clean and intuitive UI with tabs for request/response inspection, vulnerable URLs, and terminal access.
- **Context Menu Options**: Allows users to delete selected or all URLs with ease.
- **Credits and About Section**: Includes an "About" tab with developer information and social links.

---

## Installation

1. **Download the Extension**:
   - Clone or download the repository containing the extension code.

2. **Install Dependencies**:
   - Ensure you have the required Python libraries installed:
     ```bash
     pip install -r requirements.txt
     ```

3. **Load the Extension in Burp Suite**:
   - Open Burp Suite.
   - Navigate to the **Extensions** tab.
   - Click on **Add** and select the extension file (`XploitAI_Burp_Scanner.py`).
   - The extension will load, and you should see the **XploitAI Burp - Scanner** tab in the UI.

---

## Usage

1. **Proxy Traffic**:
   - Use Burp Suite's Proxy tool to capture HTTP requests and responses.

2. **Scan URLs**:
   - Click the **Scan All URLs** button to scan all captured URLs for vulnerabilities.

3. **View Vulnerabilities**:
   - Click the **Show Vulnerable URLs** button to view a list of URLs with detected vulnerabilities.

4. **Generate Reports**:
   - Use the **Generate Report** button to create a detailed report of all vulnerabilities.

5. **Terminal**:
   - Access the embedded terminal in the **Terminal** tab to execute system commands.

6. **Credits**:
   - Visit the **About** tab to learn more about the developer and the tool.

---

## Screenshots

![Main Interface](image/main_interface.png)  
*Main Interface of XploitAI Burp - Scanner*

![Vulnerable URLs](image/vulnerable_urls.png)  
*List of Vulnerable URLs*

![Terminal](image/terminal.png)  
*Embedded Terminal for Command Execution*

---

## Developer Information

- **Developer**: Shubham Rooter (Shubham Tiwari)
- **GitHub**: [shubhamrooter](https://github.com/shubhamrooter)
- **LinkedIn**: [Shubham Tiwari](https://www.linkedin.com/in/shubham-tiwari09/)
- **Twitter**: [shubhamtiwari_r](https://x.com/shubhamtiwari_r)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Thanks to the Burp Suite team for providing an extensible platform.
- Special thanks to the open-source community for their contributions to AI and security research.

---

## Support

For any issues, feature requests, or feedback, please open an issue on the [GitHub repository](https://github.com/shubhamrooter/XploitAI-Burp-Scanner).
