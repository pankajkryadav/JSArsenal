# ui.py
import customtkinter
from tkinter import filedialog
import multiprocessing
import os
from core_engine import CoreEngine

class MainFrame(customtkinter.CTkFrame):
    def __init__(self, master):
        super().__init__(master)
        self.engine = CoreEngine()
        self.total_urls = 0
        self.processed_urls = 0
        
        # --- UI WIDGETS (Unchanged) ---
        # (... The entire block of widget creation code is exactly the same as before ...)
        self.grid_columnconfigure(0, weight=1); self.grid_columnconfigure(1, weight=2); self.grid_rowconfigure(0, weight=1)
        self.left_frame = customtkinter.CTkFrame(self); self.left_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew"); self.left_frame.grid_rowconfigure(1, weight=1)
        self.right_frame = customtkinter.CTkFrame(self); self.right_frame.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="nsew"); self.right_frame.grid_rowconfigure(0, weight=1); self.right_frame.grid_columnconfigure(0, weight=1)
        self.io_frame = customtkinter.CTkFrame(self.left_frame); self.io_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew"); self.io_frame.grid_columnconfigure(0, weight=1)
        self.file_label = customtkinter.CTkLabel(self.io_frame, text="Select URL File (.txt):"); self.file_label.grid(row=0, column=0, padx=10, pady=(10,5), sticky="w")
        self.file_entry_frame = customtkinter.CTkFrame(self.io_frame, fg_color="transparent"); self.file_entry_frame.grid(row=1, column=0, padx=10, pady=(0,5), sticky="ew"); self.file_entry_frame.grid_columnconfigure(0, weight=1)
        self.file_entry = customtkinter.CTkEntry(self.file_entry_frame, placeholder_text="Path to your URL file..."); self.file_entry.grid(row=0, column=0, sticky="ew")
        self.browse_button = customtkinter.CTkButton(self.file_entry_frame, text="Browse...", command=self.select_url_file, width=80); self.browse_button.grid(row=0, column=1, padx=(5,0))
        self.paste_label = customtkinter.CTkLabel(self.io_frame, text="...OR Paste URLs Below:"); self.paste_label.grid(row=2, column=0, padx=10, pady=(5, 0), sticky="w")
        self.url_textbox = customtkinter.CTkTextbox(self.io_frame, height=120); self.url_textbox.grid(row=3, column=0, padx=10, pady=10, sticky="ew")
        self.scope_frame = customtkinter.CTkFrame(self.io_frame); self.scope_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew"); self.scope_frame.grid_columnconfigure(1, weight=1)
        self.scope_checkbox = customtkinter.CTkCheckBox(self.scope_frame, text="Enable Scope Filter"); self.scope_checkbox.grid(row=0, column=0, padx=10, pady=10)
        self.scope_keywords_entry = customtkinter.CTkEntry(self.scope_frame, placeholder_text="example.com, api.example"); self.scope_keywords_entry.grid(row=0, column=1, padx=(0,10), pady=10, sticky="ew")
        self.output_label = customtkinter.CTkLabel(self.io_frame, text="Save Results To Folder:"); self.output_label.grid(row=5, column=0, padx=10, pady=(5,0), sticky="w")
        self.output_entry_frame = customtkinter.CTkFrame(self.io_frame, fg_color="transparent"); self.output_entry_frame.grid(row=6, column=0, padx=10, pady=(0,5), sticky="ew"); self.output_entry_frame.grid_columnconfigure(0, weight=1)
        self.output_entry = customtkinter.CTkEntry(self.output_entry_frame, placeholder_text="Path to your results folder..."); self.output_entry.grid(row=0, column=0, sticky="ew")
        self.output_browse_button = customtkinter.CTkButton(self.output_entry_frame, text="Browse...", command=self.select_output_folder, width=80); self.output_browse_button.grid(row=0, column=1, padx=(5,0))
        self.html_report_checkbox = customtkinter.CTkCheckBox(self.io_frame, text="Save HTML Report (in output folder)"); self.html_report_checkbox.grid(row=7, column=0, padx=10, pady=10, sticky="w"); self.html_report_checkbox.select()
        self.options_frame = customtkinter.CTkFrame(self.left_frame); self.options_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew"); self.options_frame.grid_rowconfigure(0, weight=1); self.options_frame.grid_columnconfigure(0, weight=1)
        self.tab_view = customtkinter.CTkTabview(self.options_frame); self.tab_view.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.common_recon_tab = self.tab_view.add("Common Recon 🕵️"); self.advanced_analysis_tab = self.tab_view.add("Advanced Analysis 🔬"); self.vuln_hunting_tab = self.tab_view.add("Vulnerability Hunting 🏹")
        self.secretfind_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="SecretFind (All-in-One Discovery)"); self.secretfind_checkbox.pack(anchor="w", padx=20, pady=5)
        self.endpoints_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="Endpoints & Paths"); self.endpoints_checkbox.pack(anchor="w", padx=20, pady=5)
        self.params_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="Parameters"); self.params_checkbox.pack(anchor="w", padx=20, pady=5)
        self.subdomains_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="Subdomains"); self.subdomains_checkbox.pack(anchor="w", padx=20, pady=5)
        self.emails_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="Email Addresses"); self.emails_checkbox.pack(anchor="w", padx=20, pady=5)
        self.comments_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="Source Code Comments"); self.comments_checkbox.pack(anchor="w", padx=20, pady=5)
        self.tech_fingerprint_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="Technology Fingerprinting"); self.tech_fingerprint_checkbox.pack(anchor="w", padx=20, pady=5)
        self.integrations_checkbox = customtkinter.CTkCheckBox(self.common_recon_tab, text="Third-Party Integrations"); self.integrations_checkbox.pack(anchor="w", padx=20, pady=5)
        self.cloud_urls_checkbox = customtkinter.CTkCheckBox(self.advanced_analysis_tab, text="Cloud URLs (S3, Azure, GCS)"); self.cloud_urls_checkbox.pack(anchor="w", padx=20, pady=5)
        self.js_vars_checkbox = customtkinter.CTkCheckBox(self.advanced_analysis_tab, text="JavaScript Variables"); self.js_vars_checkbox.pack(anchor="w", padx=20, pady=5)
        self.form_endpoints_checkbox = customtkinter.CTkCheckBox(self.advanced_analysis_tab, text="Form Endpoints (action=)"); self.form_endpoints_checkbox.pack(anchor="w", padx=20, pady=5)
        self.version_info_checkbox = customtkinter.CTkCheckBox(self.advanced_analysis_tab, text="Copyright & Version Info"); self.version_info_checkbox.pack(anchor="w", padx=20, pady=5)
        self.social_media_checkbox = customtkinter.CTkCheckBox(self.advanced_analysis_tab, text="Social Media Links"); self.social_media_checkbox.pack(anchor="w", padx=20, pady=5)
        self.js_api_checkbox = customtkinter.CTkCheckBox(self.advanced_analysis_tab, text="JavaScript API Endpoints"); self.js_api_checkbox.pack(anchor="w", padx=20, pady=5)
        self.graphql_checkbox = customtkinter.CTkCheckBox(self.advanced_analysis_tab, text="GraphQL Schema Discovery"); self.graphql_checkbox.pack(anchor="w", padx=20, pady=5)
        self.secrets_checkbox = customtkinter.CTkCheckBox(self.vuln_hunting_tab, text="Secrets & API Keys"); self.secrets_checkbox.pack(anchor="w", padx=20, pady=5)
        self.jwt_checkbox = customtkinter.CTkCheckBox(self.vuln_hunting_tab, text="JSON Web Tokens (JWTs)"); self.jwt_checkbox.pack(anchor="w", padx=20, pady=5)
        self.security_headers_checkbox = customtkinter.CTkCheckBox(self.vuln_hunting_tab, text="Security Header Analysis"); self.security_headers_checkbox.pack(anchor="w", padx=20, pady=5)
        self.vuln_patterns_checkbox = customtkinter.CTkCheckBox(self.vuln_hunting_tab, text="Vulnerability Code Patterns"); self.vuln_patterns_checkbox.pack(anchor="w", padx=20, pady=5)
        self.postmessage_checkbox = customtkinter.CTkCheckBox(self.vuln_hunting_tab, text="postMessage Listener Discovery"); self.postmessage_checkbox.pack(anchor="w", padx=20, pady=5)
        self.custom_regex_frame = customtkinter.CTkFrame(self.vuln_hunting_tab, fg_color="transparent"); self.custom_regex_frame.pack(fill="x", padx=15, pady=5)
        self.custom_regex_checkbox = customtkinter.CTkCheckBox(self.custom_regex_frame, text="Custom Regex Search"); self.custom_regex_checkbox.pack(side="left")
        self.custom_regex_entry = customtkinter.CTkEntry(self.custom_regex_frame, placeholder_text="Enter your regex pattern here..."); self.custom_regex_entry.pack(side="left", fill="x", expand=True, padx=10)
        self.controls_frame = customtkinter.CTkFrame(self.left_frame); self.controls_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew"); self.controls_frame.grid_columnconfigure(2, weight=1)
        self.start_button = customtkinter.CTkButton(self.controls_frame, text="▶️ START ANALYSIS", command=self.start_analysis_clicked); self.start_button.grid(row=0, column=0, padx=10, pady=10)
        self.stop_button = customtkinter.CTkButton(self.controls_frame, text="⏹️ STOP", state="disabled", command=self.stop_analysis_clicked); self.stop_button.grid(row=0, column=1, padx=10, pady=10)
        self.progress_bar = customtkinter.CTkProgressBar(self.controls_frame); self.progress_bar.set(0); self.progress_bar.grid(row=0, column=2, padx=10, pady=10, sticky="ew")
        self.status_label = customtkinter.CTkLabel(self.controls_frame, text="Status: Ready"); self.status_label.grid(row=0, column=3, padx=10, pady=10)
        self.log_textbox = customtkinter.CTkTextbox(self.right_frame); self.log_textbox.grid(row=0, column=0, padx=10, pady=10, sticky="nsew"); self.log_textbox.configure(state="disabled")
        self.log_textbox.tag_config("SUCCESS", foreground="#28a745"); self.log_textbox.tag_config("ERROR", foreground="#dc3545"); self.log_textbox.tag_config("WARN", foreground="#ffc107"); self.log_textbox.tag_config("INFO", foreground="#17a2b8"); self.log_textbox.tag_config("HEADER", foreground="#6f42c1")
        self.credit_label = customtkinter.CTkLabel(self.left_frame, text="developed by :- pankajkryadav", text_color="gray"); self.credit_label.grid(row=3, column=0, padx=10, pady=5, sticky="se")
        self.log_message("[*] INFO: Application loaded. Ready for analysis.")

    def start_analysis_clicked(self):
        settings = self.get_settings()
        if not (settings["url_file"] or settings["pasted_urls"]) or not settings["output_folder"]:
            self.log_message("[!] ERROR: Please provide URLs and select an output folder."); return

        self.start_button.configure(state="disabled"); self.stop_button.configure(state="normal")
        self.log_textbox.configure(state="normal"); self.log_textbox.delete("1.0", "end"); self.log_textbox.configure(state="disabled")
        self.processed_urls = 0
        
        # Create the single queue for the UI to listen to
        self.ui_queue = multiprocessing.Manager().Queue()

        urls = []
        if settings["url_file"]:
            try:
                with open(settings["url_file"], 'r', encoding='utf-8') as f: urls = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log_message(f"[!] ERROR: Could not read URL file: {e}"); self.on_analysis_finished(); return
        elif settings["pasted_urls"]:
            urls = [line.strip() for line in settings["pasted_urls"].splitlines() if line.strip()]
        
        final_urls = self.filter_urls_by_scope(urls, settings)
        if not final_urls:
            self.log_message("[!] WARN: No URLs to process."); self.on_analysis_finished(); return
            
        self.total_urls = len(final_urls)
        self.update_progress()
        
        # The UI's job is just to hand over the settings and the final URL list
        self.engine.start_analysis(settings, final_urls, self.ui_queue)
        self.after(100, self.process_ui_queue)

    def process_ui_queue(self):
        try:
            while not self.ui_queue.empty():
                msg_type, data = self.ui_queue.get_nowait()
                if msg_type == 'log': self.log_message(data)
                elif msg_type == 'progress': self.processed_urls += data; self.update_progress()
                elif msg_type == 'finished': self.on_analysis_finished(); return
        except Exception: pass
        
        if self.engine.manager_process and self.engine.manager_process.is_alive():
            self.after(100, self.process_ui_queue)
        else:
            if self.stop_button.cget("state") == "normal": self.on_analysis_finished()

    # --- The rest of the functions are unchanged helpers ---
    def stop_analysis_clicked(self):
        self.log_message("[*] INFO: Stop signal sent. Terminating processes...")
        self.engine.stop_analysis()
    def on_analysis_finished(self):
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
    def filter_urls_by_scope(self, urls, settings):
        if settings["scope_enabled"] and settings["scope_keywords"]:
            keywords = [k.strip() for k in settings["scope_keywords"].split(',') if k.strip()]
            if not keywords:
                 self.log_message("[!] WARN: Scope filter enabled but no keywords provided.")
                 return urls
            scoped_urls = [url for url in urls if any(keyword in url for keyword in keywords)]
            self.log_message(f"[*] INFO: Scope filter applied. Processing {len(scoped_urls)} of {len(urls)} total URLs.")
            return scoped_urls
        return urls
    def update_progress(self):
        if self.total_urls > 0:
            progress = float(self.processed_urls) / float(self.total_urls)
            self.progress_bar.set(progress); self.status_label.configure(text=f"Status: {self.processed_urls}/{self.total_urls}")
        else:
            self.progress_bar.set(0); self.status_label.configure(text="Status: Ready")
    def log_message(self, message, tag=None):
        if not tag:
            if message.startswith("[+] SUCCESS"): tag = "SUCCESS"
            elif message.startswith(("[!] ERROR", "[!] FATAL ERROR")): tag = "ERROR"
            elif message.startswith("[!] WARN"): tag = "WARN"
            elif message.startswith("[*] INFO"): tag = "INFO"
        self.log_textbox.configure(state="normal"); self.log_textbox.insert("end", message + "\n", tag); self.log_textbox.configure(state="disabled"); self.log_textbox.see("end")
    def get_settings(self):
        return { "url_file": self.file_entry.get(), "pasted_urls": self.url_textbox.get("1.0", "end-1c"), "output_folder": self.output_entry.get(), "scope_enabled": bool(self.scope_checkbox.get()), "scope_keywords": self.scope_keywords_entry.get(), "custom_regex_pattern": self.custom_regex_entry.get(), "save_html": bool(self.html_report_checkbox.get()), "options": { "SecretFind": bool(self.secretfind_checkbox.get()), "endpoints": bool(self.endpoints_checkbox.get()), "params": bool(self.params_checkbox.get()), "subdomains": bool(self.subdomains_checkbox.get()), "emails": bool(self.emails_checkbox.get()), "comments": bool(self.comments_checkbox.get()), "tech_fingerprint": bool(self.tech_fingerprint_checkbox.get()), "integrations": bool(self.integrations_checkbox.get()), "cloud_urls": bool(self.cloud_urls_checkbox.get()), "js_vars": bool(self.js_vars_checkbox.get()), "form_endpoints": bool(self.form_endpoints_checkbox.get()), "version_info": bool(self.version_info_checkbox.get()), "social_media": bool(self.social_media_checkbox.get()), "js_api": bool(self.js_api_checkbox.get()), "graphql": bool(self.graphql_checkbox.get()), "secrets": bool(self.secrets_checkbox.get()), "jwt": bool(self.jwt_checkbox.get()), "security_headers": bool(self.security_headers_checkbox.get()), "vuln_patterns": bool(self.vuln_patterns_checkbox.get()), "postmessage": bool(self.postmessage_checkbox.get()), "custom_regex": bool(self.custom_regex_checkbox.get()) } }
    def select_url_file(self):
        file_path = filedialog.askopenfilename(title="Select URL File", filetypes=(("Text files", "*.txt"), ("All files", "*.*")));
        if file_path: self.file_entry.delete(0, "end"); self.file_entry.insert(0, file_path)
    def select_output_folder(self):
        folder_path = filedialog.askdirectory(title="Select Output Folder");
        if folder_path: self.output_entry.delete(0, "end"); self.output_entry.insert(0, folder_path)