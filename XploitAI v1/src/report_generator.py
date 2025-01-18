class ReportGenerator:
    def generate_report(self, vulnerabilities):
        report = "Vulnerability Report:\n\n"
        for url, data in vulnerabilities.items():
            report += "URL: {}\n".format(url)
            report += "Vulnerabilities: {}\n\n".format(", ".join(data["vulnerabilities"]))
        return report