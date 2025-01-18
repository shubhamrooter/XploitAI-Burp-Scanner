from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory
from javax.swing import (
    JPanel, JTextPane, JScrollPane, JList, JSplitPane, BorderFactory,
    ListSelectionModel, JButton, DefaultListModel, JTabbedPane, JPopupMenu,
    JMenuItem, JLabel, JTextField, JToolBar, JTextArea, JOptionPane, ImageIcon, JProgressBar
)
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout, Color, Font
from java.awt.event import KeyEvent, KeyAdapter, MouseAdapter, MouseEvent
from java.lang import Thread, Runnable
from java.util import ArrayList, Collections
from ai_model import AIModel
from threat_intelligence import ThreatIntelligence
from report_generator import ReportGenerator
from utils import Log
from custom_rules_loader import CustomRulesLoader
from vulnerability_scanner import VulnerabilityScanner
import subprocess
import json
import os
import sys
from threading import Lock  # Added for thread safety


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    def __init__(self):
        self._callbacks = None
        self._helpers = None
        self.url_list = Collections.synchronizedList(ArrayList())  # Thread-safe list
        self.vulnerabilities = {}
        self.vulnerabilities_lock = Lock()  # Lock for thread-safe access to vulnerabilities
        self.vulnerable_urls_model = DefaultListModel()
        self.vulnerable_urls_list = None

        # Initialize the logger
        self.log = Log()

        # Initialize AI model, threat intelligence, and custom rules
        self.ai_model = None
        self.threat_intel = None
        self.rules_loader = None

        # Load AI model, threat intelligence, and custom rules
        self.load_ai_model()
        self.load_threat_intelligence()
        self.load_custom_rules()

        # Initialize scanner
        if self.ai_model and self.threat_intel and self.rules_loader:
            self.scanner = VulnerabilityScanner(self.rules_loader, self.threat_intel, self.ai_model)
            self.log.log("Scanner initialized successfully.")
        else:
            self.scanner = None
            self.log.log("Scanner initialization failed due to missing dependencies.")

        # Other initialization code remains unchanged
        self.report_generator = ReportGenerator()
        self.tabbed_pane = JTabbedPane()
        self.vulnerable_tab_index = -1
        self.url_count_label = JLabel("Total URLs: 0")
        self.vulnerable_url_count_label = JLabel("Vulnerable URLs: 0")
        self.terminal_panel = None
        self.signature_image_path = os.path.abspath("../image/rooter.png")  # Correct path
        self.progress_bar = JProgressBar()
        self.max_display_length = 10000
        self.load_more_button = JButton("Load More", actionPerformed=self.load_more_data)

    def load_ai_model(self):
        model_path = os.path.abspath("../models/model.pkl")
        if os.path.exists(model_path):
            try:
                self.ai_model = AIModel(model_path)
                self.log.log("AI model loaded successfully from: {}".format(model_path))
            except Exception as e:
                self.log.log("Error loading model: {}".format(str(e)))
                self.ai_model = None  # Ensure ai_model is None if loading fails
        else:
            self.log.log("Model file not found at: {}".format(model_path))
            self.ai_model = None  # Ensure ai_model is None if file is missing

    def load_threat_intelligence(self):
        threat_intel_path = os.path.abspath("../data/threat_intelligence.json")
        if os.path.exists(threat_intel_path):
            try:
                with open(threat_intel_path, "r") as f:
                    threat_intel_data = json.load(f)  # Validate JSON
                self.threat_intel = ThreatIntelligence(threat_intel_data)
                self.log.log("Threat intelligence loaded successfully from: {}".format(threat_intel_path))
            except Exception as e:
                self.log.log("Error loading threat intelligence: {}".format(str(e)))
                self.threat_intel = None  # Ensure threat_intel is None if loading fails
        else:
            self.log.log("Threat intelligence file not found at: {}".format(threat_intel_path))
            self.threat_intel = None  # Ensure threat_intel is None if file is missing

    def load_custom_rules(self):
        custom_rules_path = os.path.abspath("../data/custom_rules.json")
        if os.path.exists(custom_rules_path):
            try:
                with open(custom_rules_path, "r") as f:
                    custom_rules_data = json.load(f)  # Validate JSON
                self.rules_loader = CustomRulesLoader(custom_rules_data)
                self.log.log("Custom rules loaded successfully from: {}".format(custom_rules_path))
            except Exception as e:
                self.log.log("Error loading rules: {}".format(str(e)))
                self.rules_loader = None  # Ensure rules_loader is None if loading fails
        else:
            self.log.log("Custom rules file not found at: {}".format(custom_rules_path))
            self.rules_loader = None  # Ensure rules_loader is None if file is missing

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XploitAI Burp - Scanner")
        self.main_panel = self.create_main_panel()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        self.log.log("Extension registered and HTTP listener added")

        # Add Terminal Tab
        self.terminal_panel = TerminalPanel(self)
        self.tabbed_pane.addTab("Terminal", self.terminal_panel)

        # Add About/Credit Tab
        self.add_about_tab()

    def add_about_tab(self):
        about_panel = JPanel(BorderLayout())
        about_panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))

        content_panel = JPanel()
        content_panel.setLayout(BorderLayout(10, 10))

        try:
            signature_icon = ImageIcon(self.signature_image_path)
            signature_label = JLabel(signature_icon)
            signature_label.setHorizontalAlignment(JLabel.CENTER)
            content_panel.add(signature_label, BorderLayout.NORTH)
        except Exception as e:
            self.log.log("Failed to load signature image: {}".format(str(e)))

        text_panel = JPanel()
        text_panel.setLayout(FlowLayout(FlowLayout.CENTER))

        title_label = JLabel("XploitAI Burp - Scanner")
        title_label.setFont(Font("Arial", Font.BOLD, 18))
        title_label.setForeground(Color(255, 140, 0))
        text_panel.add(title_label)

        developer_label = JLabel("Developed by: Shubham Rooter")
        developer_label.setFont(Font("Arial", Font.PLAIN, 14))
        text_panel.add(developer_label)

        github_label = JLabel("GitHub: https://github.com/shubhamrooter")
        github_label.setFont(Font("Arial", Font.PLAIN, 14))
        text_panel.add(github_label)

        linkedin_label = JLabel("LinkedIn: https://www.linkedin.com/in/shubham-tiwari09/")
        linkedin_label.setFont(Font("Arial", Font.PLAIN, 14))
        text_panel.add(linkedin_label)

        twitter_label = JLabel("Twitter: https://x.com/shubhamtiwari_r")
        twitter_label.setFont(Font("Arial", Font.PLAIN, 14))
        text_panel.add(twitter_label)

        thank_you_label = JLabel("Thank you for using XploitAI!")
        thank_you_label.setFont(Font("Arial", Font.PLAIN, 14))
        thank_you_label.setForeground(Color(0, 128, 0))
        text_panel.add(thank_you_label)

        content_panel.add(text_panel, BorderLayout.CENTER)
        about_panel.add(content_panel, BorderLayout.CENTER)
        self.tabbed_pane.addTab("About", about_panel)

    def getTabCaption(self):
        return "XploitAI Burp - Scanner"

    def getUiComponent(self):
        return self.tabbed_pane

    def create_main_panel(self):
        main_panel = JPanel(BorderLayout())
        main_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Header Panel
        header_panel = JPanel()
        header_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        header_label = JLabel("XploitAI Burp - Scanner")
        header_label.setFont(Font("Arial", Font.BOLD, 18))
        header_label.setForeground(Color(255, 140, 0))
        header_panel.add(header_label)
        main_panel.add(header_panel, BorderLayout.NORTH)

        # URL List
        self.url_list_model = DefaultListModel()
        self.url_list_component = JList(self.url_list_model)
        self.url_list_component.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        url_list_panel = JPanel(BorderLayout())
        url_list_panel.setBorder(BorderFactory.createTitledBorder("Captured URLs"))
        url_list_panel.add(JScrollPane(self.url_list_component), BorderLayout.CENTER)

        # Add right-click menu to URL list
        self.url_list_component.addMouseListener(URLListMouseListener(self))

        # Request Panel
        request_panel = JPanel(BorderLayout())
        request_label = JLabel("Request")
        request_label.setFont(Font("Arial", Font.BOLD, 14))
        request_label.setForeground(Color(255, 140, 0))
        request_panel.add(request_label, BorderLayout.NORTH)

        # Request Tabs (Raw, Pretty, Hex)
        self.request_tabbed_pane = self.create_tabbed_pane("request")
        request_panel.add(self.request_tabbed_pane, BorderLayout.CENTER)

        # Response Panel
        response_panel = JPanel(BorderLayout())
        response_label = JLabel("Response")
        response_label.setFont(Font("Arial", Font.BOLD, 14))
        response_label.setForeground(Color(255, 140, 0))
        response_panel.add(response_label, BorderLayout.NORTH)

        # Response Tabs (Raw, Pretty, Hex)
        self.response_tabbed_pane = self.create_tabbed_pane("response")
        response_panel.add(self.response_tabbed_pane, BorderLayout.CENTER)

        # Request/Response Split Pane
        request_response_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, request_panel, response_panel)
        request_response_split.setResizeWeight(0.5)

        # Toolbar for Buttons
        toolbar = JToolBar()
        toolbar.setFloatable(False)
        toolbar.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))

        # Add buttons to the toolbar
        scan_button = JButton("Scan All URLs", actionPerformed=self.scan_all_urls)
        report_button = JButton("Generate Report", actionPerformed=self.generate_report)
        show_vulnerable_button = JButton("Show Vulnerable URLs", actionPerformed=self.show_vulnerable_urls)
        credit_button = JButton("Credits", actionPerformed=self.show_credits)

        # Customize buttons
        scan_button.setBackground(Color(0, 128, 0))
        scan_button.setForeground(Color.WHITE)
        scan_button.setFont(Font("Arial", Font.BOLD, 12))
        scan_button.setBorderPainted(False)

        report_button.setBackground(Color(0, 0, 255))
        report_button.setForeground(Color.WHITE)
        report_button.setFont(Font("Arial", Font.BOLD, 12))
        report_button.setBorderPainted(False)

        show_vulnerable_button.setBackground(Color(255, 165, 0))
        show_vulnerable_button.setForeground(Color.WHITE)
        show_vulnerable_button.setFont(Font("Arial", Font.BOLD, 12))
        show_vulnerable_button.setBorderPainted(False)

        credit_button.setBackground(Color(128, 0, 128))
        credit_button.setForeground(Color.WHITE)
        credit_button.setFont(Font("Arial", Font.BOLD, 12))
        credit_button.setBorderPainted(False)

        toolbar.add(scan_button)
        toolbar.addSeparator()
        toolbar.add(report_button)
        toolbar.addSeparator()
        toolbar.add(show_vulnerable_button)
        toolbar.addSeparator()
        toolbar.add(credit_button)

        # URL Count Panel
        url_count_panel = JPanel()
        url_count_panel.setLayout(FlowLayout(FlowLayout.RIGHT))
        url_count_panel.add(self.url_count_label)

        # Vulnerable URL Count Panel
        vulnerable_url_count_panel = JPanel()
        vulnerable_url_count_panel.setLayout(FlowLayout(FlowLayout.RIGHT))
        vulnerable_url_count_panel.add(self.vulnerable_url_count_label)

        # Progress Bar
        self.progress_bar.setVisible(False)
        self.progress_bar.setStringPainted(True)

        # Combine Toolbar, URL Count Panel, and Progress Bar
        control_panel = JPanel(BorderLayout())
        control_panel.add(toolbar, BorderLayout.WEST)
        control_panel.add(url_count_panel, BorderLayout.EAST)
        control_panel.add(vulnerable_url_count_panel, BorderLayout.NORTH)
        control_panel.add(self.progress_bar, BorderLayout.SOUTH)

        # Main Split Pane
        main_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, url_list_panel, request_response_split)
        main_split.setResizeWeight(0.2)
        main_panel.add(main_split, BorderLayout.CENTER)
        main_panel.add(control_panel, BorderLayout.SOUTH)

        # Add URL selection listener
        self.url_list_component.addListSelectionListener(URLSelectionListener(self))

        # Add main panel to the first tab
        self.tabbed_pane.addTab("Main", main_panel)

        return main_panel

    def show_credits(self, event):
        """
        Display credits information in a dialog box.
        """
        credits_message = (
            "XploitAI Burp - Scanner\n\n"
            "Developed by: Shubham Rooter\n"
            "GitHub: https://github.com/shubhamrooter\n"
            "LinkedIn: https://www.linkedin.com/in/shubham-tiwari09/\n"
            "Twitter: https://x.com/shubhamtiwari_r\n\n"
            "Thank you for using XploitAI!"
        )
        JOptionPane.showMessageDialog(
            self.tabbed_pane,
            credits_message,
            "Credits",
            JOptionPane.INFORMATION_MESSAGE
        )

    def create_tabbed_pane(self, pane_type):
        """
        Create a tabbed pane for either request or response with Raw, Pretty, and Hex views.
        """
        tabbed_pane = JTabbedPane()

        # Raw Text Pane
        raw_text_pane = JTextPane()
        raw_text_pane.setEditable(False)
        raw_text_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        raw_scroll_pane = JScrollPane(raw_text_pane)
        tabbed_pane.addTab("Raw", raw_scroll_pane)

        # Pretty Text Pane
        pretty_text_pane = JTextPane()
        pretty_text_pane.setEditable(False)
        pretty_text_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        pretty_scroll_pane = JScrollPane(pretty_text_pane)
        tabbed_pane.addTab("Pretty", pretty_scroll_pane)

        # Hex Text Pane
        hex_text_pane = JTextPane()
        hex_text_pane.setEditable(False)
        hex_text_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        hex_scroll_pane = JScrollPane(hex_text_pane)
        tabbed_pane.addTab("Hex", hex_scroll_pane)

        # Store references to the text panes based on the pane type
        if pane_type == "request":
            self.request_raw_text_pane = raw_text_pane
            self.request_pretty_text_pane = pretty_text_pane
            self.request_hex_text_pane = hex_text_pane
        elif pane_type == "response":
            self.response_raw_text_pane = raw_text_pane
            self.response_pretty_text_pane = pretty_text_pane
            self.response_hex_text_pane = hex_text_pane

        return tabbed_pane

    def load_more_data(self, event):
        """
        Load additional data for large requests/responses when the "Load More" button is clicked.
        """
        selected_url = self.url_list_component.getSelectedValue()
        if selected_url:
            actual_url = selected_url.split(". ", 1)[1]
            if actual_url in self.vulnerabilities:
                # Get the full request and response
                full_request = self.vulnerabilities[actual_url]["request"]
                full_response = self.vulnerabilities[actual_url]["response"]

                # Update the UI with the full data
                self.request_raw_text_pane.setText(full_request)
                self.response_raw_text_pane.setText(full_response)

                # Pretty print JSON (if applicable)
                self.pretty_print_json(self.request_pretty_text_pane, full_request)
                self.pretty_print_json(self.response_pretty_text_pane, full_response)

                # Convert to hex (if applicable)
                self.request_hex_text_pane.setText(self.convert_to_hex(full_request))
                self.response_hex_text_pane.setText(self.convert_to_hex(full_response))

                # Disable the "Load More" button after loading full data
                self.load_more_button.setEnabled(False)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag != self._callbacks.TOOL_PROXY:
            return

        url = str(messageInfo.getUrl())

        # Use a lock to ensure thread-safe access to vulnerabilities
        with self.vulnerabilities_lock:
            if url not in self.vulnerabilities:
                self.vulnerabilities[url] = {"request": "", "response": "", "vulnerabilities": []}
                self.add_url_to_list(url)
                self.update_url_count()

            if messageIsRequest:
                request = messageInfo.getRequest()
                if request:
                    request_str = self._helpers.bytesToString(request)
                    self.vulnerabilities[url]["request"] = request_str
                    self.log.log("Request captured for URL: {}".format(url))  # Log the request
            else:
                response = messageInfo.getResponse()
                if response:
                    response_str = self._helpers.bytesToString(response)
                    self.vulnerabilities[url]["response"] = response_str
                    self.log.log("Response captured for URL: {}".format(url))  # Log the response

        # Run the URL processing in a background thread
        Thread(lambda: self.process_url(url)).start()

    def process_url(self, url):
        """
        Process the URL to detect vulnerabilities.
        """
        if not self.scanner:
            self.log.log("Scanner is not initialized. Skipping URL processing.")
            return

        # Scan the URL for vulnerabilities
        self.scan_url(url)

    def add_url_to_list(self, url):
        count = self.url_list.size() + 1
        numbered_url = "{0}. {1}".format(count, url)  # Fixed for Python 2.7
        self.url_list.add(numbered_url)
        self.update_url_list_ui()

    def update_url_list_ui(self):
        # Synchronize access to the URL list to avoid ConcurrentModificationException
        synchronized_list = self.url_list
        self.url_list_model.clear()
        for url in synchronized_list:
            self.url_list_model.addElement(url)

        # Update the URL count label
        self.update_url_count()

    def update_url_count(self):
        self.url_count_label.setText("Total URLs: {}".format(self.url_list_model.size()))

    def scan_url(self, url):
        if not self.scanner:
            self.log.log("Scanner is not initialized. Skipping URL scan.")
            return

        response = self.vulnerabilities[url]["response"]
        findings = self.scanner.scan(self.vulnerabilities[url]["request"], response)
        predictions = self.ai_model.predict(url) if self.ai_model else []
        with self.vulnerabilities_lock:
            self.vulnerabilities[url]["vulnerabilities"] = findings + predictions
        self.log.log("Vulnerabilities detected for {}: {}".format(url, findings + predictions))

        if findings or predictions:
            if not self.vulnerable_urls_model.contains(url):
                self.vulnerable_urls_model.addElement(url)
                self.update_vulnerable_url_count()

    def update_vulnerable_url_count(self):
        # Update the vulnerable URL count label
        self.vulnerable_url_count_label.setText("Vulnerable URLs: {}".format(self.vulnerable_urls_model.size()))

    def scan_all_urls(self, event):
        if not self.scanner:
            self.log.log("Scanner is not initialized. Cannot scan URLs.")
            return

        self.progress_bar.setVisible(True)
        self.progress_bar.setIndeterminate(True)
        self.progress_bar.setString("Scanning URLs...")

        def scan_task():
            for url in list(self.vulnerabilities.keys()):
                self.scan_url(url)
            self.progress_bar.setVisible(False)
            self.progress_bar.setIndeterminate(False)
            self.progress_bar.setString("")
            
            # Update UI safely after processing
            javax.swing.SwingUtilities.invokeLater(lambda: self.update_url_list_ui())

        Thread(scan_task).start()

    def show_vulnerable_urls(self, event):
        if self.vulnerable_tab_index == -1:
            vulnerable_panel = JPanel(BorderLayout())
            self.vulnerable_urls_list = JList(self.vulnerable_urls_model)
            self.vulnerable_urls_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            vulnerable_panel.add(JScrollPane(self.vulnerable_urls_list), BorderLayout.CENTER)
            vulnerable_panel.setBorder(BorderFactory.createTitledBorder("Vulnerable URLs"))
            self.vulnerable_urls_list.addMouseListener(VulnerableURLListMouseListener(self))
            self.vulnerable_tab_index = self.tabbed_pane.getTabCount()
            self.tabbed_pane.addTab("Vulnerable URLs", vulnerable_panel)
        else:
            vulnerable_panel = self.tabbed_pane.getComponentAt(self.vulnerable_tab_index)
            self.vulnerable_urls_list = vulnerable_panel.getComponent(0).getViewport().getView()
            self.vulnerable_urls_list.setModel(self.vulnerable_urls_model)

        self.tabbed_pane.setSelectedIndex(self.vulnerable_tab_index)
        sys.stderr.write("Vulnerable URLs: {}\n".format(list(self.vulnerable_urls_model.toArray())))  # Log vulnerable URLs

    def generate_report(self, event):
        report = self.report_generator.generate_report(self.vulnerabilities)
        with open("vulnerability_report.txt", "w") as f:
            f.write(report)
        self.log.log("Vulnerability report generated.")

    def createMenuItems(self, invocation):
        """
        Create context menu items for the Burp Suite UI.
        """
        self.context = invocation
        menu_items = ArrayList()  # Use ArrayList to store menu items

        # Add "Delete Selected URL" menu item
        delete_selected = JMenuItem("Delete Selected URL")
        delete_selected.addActionListener(lambda x: self.delete_selected_url(None))
        menu_items.add(delete_selected)

        # Add "Delete All URLs" menu item
        delete_all = JMenuItem("Delete All URLs")
        delete_all.addActionListener(lambda x: self.delete_all_urls(None))
        menu_items.add(delete_all)

        return menu_items

    def delete_selected_url(self, event):
        selected_url = self.url_list_component.getSelectedValue()
        if selected_url:
            actual_url = selected_url.split(". ", 1)[1]
            self.url_list_model.removeElement(selected_url)
            self.vulnerable_urls_model.removeElement(actual_url)
            with self.vulnerabilities_lock:
                del self.vulnerabilities[actual_url]
            self.update_url_count()
            self.update_vulnerable_url_count()
            self.renumber_urls()
            self.log.log("Deleted URL: {}".format(actual_url))

    def delete_all_urls(self, event):
        self.url_list_model.clear()
        self.vulnerable_urls_model.clear()
        with self.vulnerabilities_lock:
            self.vulnerabilities.clear()
        self.update_url_count()
        self.update_vulnerable_url_count()
        self.log.log("Deleted all URLs")

    def renumber_urls(self):
        self.url_list_model.clear()
        for index, url in enumerate(self.vulnerabilities.keys(), start=1):
            numbered_url = "{0}. {1}".format(index, url)  # Fixed for Python 2.7
            self.url_list_model.addElement(numbered_url)

    def convert_to_hex(self, text):
        return " ".join("{0:02x}".format(ord(c)) for c in text)

    def pretty_print_json(self, text_pane, text):
        try:
            parsed_json = json.loads(text)
            formatted_json = json.dumps(parsed_json, indent=4)
            self.apply_color_coding(text_pane, formatted_json)
        except ValueError as e:
            self.log.log("JSON parsing error: {}".format(str(e)))
            formatted_text = text.replace("&", "&\n").replace("?", "?\n").replace("{", "{\n").replace("}", "\n}")
            text_pane.setText(formatted_text)

    def apply_color_coding(self, text_pane, text):
        text_pane.setText("")
        style_context = StyleContext()
        header_style = style_context.addStyle("HeaderStyle", None)
        StyleConstants.setForeground(header_style, Color.BLUE)
        body_style = style_context.addStyle("BodyStyle", None)
        StyleConstants.setForeground(body_style, Color.BLACK)
        parts = text.split("\n\n", 1)
        headers = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        doc = text_pane.getStyledDocument()
        doc.insertString(doc.getLength(), headers + "\n\n", header_style)
        doc.insertString(doc.getLength(), body, body_style)


class TerminalPanel(JPanel):
    def __init__(self, extender):
        self.extender = extender
        self.setLayout(BorderLayout())
        self.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Terminal Output Area
        self.terminal_output = JTextArea()
        self.terminal_output.setEditable(False)
        self.terminal_output.setFont(Font("Monospaced", Font.PLAIN, 14))
        self.terminal_output.setBackground(Color.BLACK)
        self.terminal_output.setForeground(Color.WHITE)
        self.terminal_output.setCaretColor(Color.WHITE)
        output_scroll = JScrollPane(self.terminal_output)
        self.add(output_scroll, BorderLayout.CENTER)

        # Terminal Input Field
        self.terminal_input = JTextField()
        self.terminal_input.setFont(Font("Monospaced", Font.PLAIN, 14))
        self.terminal_input.setBackground(Color.BLACK)
        self.terminal_input.setForeground(Color.WHITE)
        self.terminal_input.setCaretColor(Color.WHITE)
        self.terminal_input.addKeyListener(TerminalKeyListener(self))
        self.add(self.terminal_input, BorderLayout.SOUTH)

    def execute_command(self, command):
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            self.terminal_output.append("> {}\n{}\n".format(command, output.decode('utf-8')))  # Fixed for Python 2.7
        except subprocess.CalledProcessError as e:
            self.terminal_output.append("> {}\nError: {}\n".format(command, e.output.decode('utf-8')))  # Fixed for Python 2.7
        except Exception as e:
            self.terminal_output.append("> {}\nError: {}\n".format(command, str(e)))  # Fixed for Python 2.7
        self.terminal_output.setCaretPosition(self.terminal_output.getDocument().getLength())


class TerminalKeyListener(KeyAdapter):
    def __init__(self, terminal_panel):
        self.terminal_panel = terminal_panel

    def keyPressed(self, event):
        if event.getKeyCode() == KeyEvent.VK_ENTER:
            command = self.terminal_panel.terminal_input.getText().strip()
            if command:
                self.terminal_panel.execute_command(command)
                self.terminal_panel.terminal_input.setText("")


class URLSelectionListener(ListSelectionListener):
    def __init__(self, extender):
        self.extender = extender

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            selected_url = self.extender.url_list_component.getSelectedValue()
            if selected_url:
                actual_url = selected_url.split(". ", 1)[1]
                if actual_url in self.extender.vulnerabilities:
                    # Display request
                    request = self.extender.vulnerabilities[actual_url]["request"]
                    response = self.extender.vulnerabilities[actual_url]["response"]

                    # Truncate large data
                    max_length = 10000  # Adjust as needed
                    if len(request) > max_length:
                        request = request[:max_length] + "\n... [TRUNCATED]"
                    if len(response) > max_length:
                        response = response[:max_length] + "\n... [TRUNCATED]"

                    self.extender.request_raw_text_pane.setText(request)
                    self.extender.pretty_print_json(self.extender.request_pretty_text_pane, request)
                    self.extender.request_hex_text_pane.setText(self.extender.convert_to_hex(request))

                    # Display response
                    self.extender.response_raw_text_pane.setText(response)
                    self.extender.pretty_print_json(self.extender.response_pretty_text_pane, response)
                    self.extender.response_hex_text_pane.setText(self.extender.convert_to_hex(response))


class URLListMouseListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def mouseClicked(self, event):
        if event.getButton() == MouseEvent.BUTTON3:  # Right-click
            menu = self.extender.createMenuItems(None)
            menu.show(event.getComponent(), event.getX(), event.getY())


class VulnerableURLListMouseListener(MouseAdapter):
    def __init__(self, extender):
        self.extender = extender

    def mouseClicked(self, event):
        if event.getButton() == MouseEvent.BUTTON3:  # Right-click
            menu = self.extender.createMenuItems(None)
            menu.show(event.getComponent(), event.getX(), event.getY())


class BackgroundTask(Runnable):
    def __init__(self, extender, url):
        self.extender = extender
        self.url = url

    def run(self):
        self.extender.scan_url(self.url)