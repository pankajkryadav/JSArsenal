# core_engine.py
import multiprocessing
import httpx
import os
import re
from extractors import build_combined_regex, run_extractors

def worker_process(task_queue, result_queue, combined_regex_str):
    """Fetches a URL, runs extractors, and puts results into a queue for the writer."""
    combined_regex = re.compile(combined_regex_str, re.IGNORECASE | re.MULTILINE) if combined_regex_str else None
    while True:
        url = task_queue.get()
        if url is None: # Sentinel value received, exit loop
            break
        if not combined_regex:
            result_queue.put(('progress', 1))
            continue
        try:
            # Use a context manager for the client for better resource management
            with httpx.Client(follow_redirects=True, timeout=10) as client:
                response = client.get(url)
                response.raise_for_status()
                if response.text:
                    found_items = run_extractors(response.text, combined_regex)
                    if found_items:
                        result_queue.put(('result', (url, found_items)))
        except Exception as e:
            result_queue.put(('log', f"[!] ERROR: Failed on {url}: {e}"))
        result_queue.put(('progress', 1))

def writer_process(result_queue, ui_queue, settings):
    """Listens for results and writes them to files."""
    file_writers = {}
    html_writer = None
    try:
        # Open files
        for option, enabled in settings["options"].items():
            if enabled:
                file_path = os.path.join(settings["output_folder"], f"{option}.txt")
                file_writers[option] = open(file_path, 'w', encoding='utf-8')
        if settings.get("save_html"):
            html_path = os.path.join(settings["output_folder"], "report.html")
            html_writer = open(html_path, 'w', encoding='utf-8')
            html_writer.write(HTML_HEADER)

        while True:
            msg_type, data = result_queue.get()
            if msg_type == 'finished': break
            elif msg_type == 'progress': ui_queue.put(('progress', 1))
            elif msg_type == 'result':
                url, found_items = data
                ui_queue.put(('log', f"[+] SUCCESS: Found data in {url}"))
                if html_writer: html_writer.write(f'<div class="url-header">{url}</div>\n')
                if "SecretFind" in found_items:
                    writer = file_writers.get("SecretFind")
                    for item in found_items["SecretFind"]:
                        if writer: writer.write(f"{item}\n")
                        if html_writer: html_writer.write(f'<div class="finding"><span class="value">{item}</span></div>\n')
                else:
                    for category, items in found_items.items():
                        writer = file_writers.get(category)
                        for item in items:
                            if writer: writer.write(f"{item}\n")
                            if html_writer: html_writer.write(f'<div class="finding"><span class="category cat-{category}">[{category}]</span><span class="value">{item}</span></div>\n')
    finally:
        for writer in file_writers.values(): writer.close()
        if html_writer:
            html_writer.write(HTML_FOOTER); html_writer.close()

class CoreEngine:
    def __init__(self):
        self.manager_process = None

    def start_analysis(self, settings, urls, ui_queue):
        if self.manager_process and self.manager_process.is_alive():
            ui_queue.put(('log', "[!] ERROR: Analysis is already running."))
            return
        # Pass the full list of URLs directly to the manager process
        self.manager_process = multiprocessing.Process(target=self.run, args=(settings, urls, ui_queue))
        self.manager_process.start()

    def stop_analysis(self):
        if self.manager_process and self.manager_process.is_alive():
            self.manager_process.terminate()
            self.manager_process.join()

    @staticmethod
    def run(settings, urls, ui_queue):
        """The manager process now controls the entire workflow."""
        ui_queue.put(('log', "--- [*] INFO: Analysis manager started ---"))
        
        task_queue = multiprocessing.Queue()
        result_queue = multiprocessing.Queue()
        
        try:
            # 1. Manager fills the queue first
            for url in urls:
                task_queue.put(url)

            combined_regex = build_combined_regex(settings["options"], settings.get("custom_regex_pattern", ""))
            if not combined_regex:
                ui_queue.put(('log', "[!] WARN: No extractor options selected."))
                return

            cpu_count = multiprocessing.cpu_count()
            ui_queue.put(('log', f"[*] INFO: Starting {cpu_count} workers and 1 writer."))

            # 2. Add sentinel values to tell workers when to stop
            for _ in range(cpu_count):
                task_queue.put(None)

            # 3. Start the writer process
            writer = multiprocessing.Process(target=writer_process, args=(result_queue, ui_queue, settings))
            writer.start()

            # 4. Start the worker processes
            workers = [multiprocessing.Process(target=worker_process, args=(task_queue, result_queue, combined_regex.pattern)) for _ in range(cpu_count)]
            for p in workers:
                p.start()

            # 5. Wait for all processes to complete their jobs
            for p in workers:
                p.join()
            result_queue.put(('finished', None)) # Signal the writer to stop
            writer.join()

        except Exception as e:
            ui_queue.put(('log', f"[!] FATAL ERROR: {e}"))
        finally:
            ui_queue.put(('log', "[*] INFO: Analysis complete."))
            ui_queue.put(('finished', None)) # Signal the UI to stop

# --- HTML Templates (Unchanged) ---
HTML_HEADER = """<!DOCTYPE html><html><head><title>JS Arsenal Report</title><style>body { background-color: #121212; color: #e0e0e0; font-family: monospace; padding: 20px; } .container { max-width: 1200px; margin: auto; } h1 { color: #bb86fc; } .url-header { color: #6f42c1; font-weight: bold; margin-top: 25px; font-size: 1.1em; border-bottom: 1px solid #333; padding-bottom: 5px; } .finding { display: flex; align-items: center; margin-left: 20px; } .category { color: #888; min-width: 150px; } .value { color: #03dac6; } .cat-secrets, .cat-jwt { color: #cf6679; font-weight: bold; } .cat-endpoints, .cat-js_api { color: #03a9f4; } .cat-params { color: #ffeb3b; } .cat-cloud_urls { color: #ff9800; }</style></head><body><div class="container"><h1>JS Arsenal Report by Pankajkryadav</h1>"""
HTML_FOOTER = """</div></body></html>"""