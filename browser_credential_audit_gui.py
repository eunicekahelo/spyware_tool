"""
Browser Credential Security Audit Tool - GUI Version
=====================================================

Graphical user interface for the browser credential audit tool.
Uses tkinter (built into Python) for cross-platform compatibility.

EDUCATIONAL USE ONLY - For Blue Team Training and Security Posture Assessment
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import threading

# Import the audit functionality from the main script
from browser_credential_audit import BrowserCredentialAuditor


class CredentialAuditGUI:
    """
    Main GUI application for browser credential auditing.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Browser Credential Security Audit Tool")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Variables
        self.selected_browser = tk.StringVar(value="Chrome")
        self.include_history = tk.BooleanVar(value=False)
        self.include_downloads = tk.BooleanVar(value=False)
        self.audit_running = False
        self.credentials = []
        self.history = []
        self.downloads = []
        
        # Configure style
        self.setup_style()
        
        # Build UI
        self.create_widgets()
        
        # Center window
        self.center_window()
    
    def setup_style(self):
        """Configure ttk style for modern look."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Heading.TLabel', font=('Arial', 10, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 9))
    
    def center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create and layout all GUI widgets."""
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Browser Credential Security Audit Tool",
            style='Title.TLabel'
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        # Subtitle
        subtitle_label = ttk.Label(
            main_frame,
            text="For Blue Team Training & Security Posture Assessment",
            font=('Arial', 9, 'italic'),
            foreground='gray'
        )
        subtitle_label.grid(row=1, column=0, columnspan=3, pady=(0, 20))
        
        # Left panel - Controls
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Browser selection
        ttk.Label(control_frame, text="Select Browser:", style='Heading.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5)
        )
        
        browsers = ['Chrome', 'Edge', 'Brave', 'Opera', 'Vivaldi']
        browser_combo = ttk.Combobox(
            control_frame,
            textvariable=self.selected_browser,
            values=browsers,
            state='readonly',
            width=20
        )
        browser_combo.grid(row=1, column=0, sticky=tk.W, pady=(0, 15))
        
        # Include history checkbox
        history_check = ttk.Checkbutton(
            control_frame,
            text="Include Browser History",
            variable=self.include_history
        )
        history_check.grid(row=2, column=0, sticky=tk.W, pady=(0, 10))
        
        # Include downloads checkbox
        downloads_check = ttk.Checkbutton(
            control_frame,
            text="Include Download History",
            variable=self.include_downloads
        )
        downloads_check.grid(row=3, column=0, sticky=tk.W, pady=(0, 10))
        
        # Include cache files checkbox
        self.include_cache = tk.BooleanVar(value=False)
        cache_check = ttk.Checkbutton(
            control_frame,
            text="Include Cache Files (HTML/CSS/JS)",
            variable=self.include_cache
        )
        cache_check.grid(row=4, column=0, sticky=tk.W, pady=(0, 10))
        
        # Include detection checkbox
        self.include_detection = tk.BooleanVar(value=True)
        detection_check = ttk.Checkbutton(
            control_frame,
            text="Run Unauthorized Access Detection",
            variable=self.include_detection
        )
        detection_check.grid(row=5, column=0, sticky=tk.W, pady=(0, 15))
        
        # Run audit button
        self.run_button = ttk.Button(
            control_frame,
            text="Run Audit",
            command=self.run_audit,
            width=20
        )
        self.run_button.grid(row=6, column=0, sticky=tk.W, pady=(0, 10))
        
        # Export button
        self.export_button = ttk.Button(
            control_frame,
            text="Export Results",
            command=self.export_results,
            width=20,
            state='disabled'
        )
        self.export_button.grid(row=7, column=0, sticky=tk.W, pady=(0, 10))
        
        # Clear button
        clear_button = ttk.Button(
            control_frame,
            text="Clear Results",
            command=self.clear_results,
            width=20
        )
        clear_button.grid(row=8, column=0, sticky=tk.W, pady=(0, 20))
        
        # Status section
        ttk.Label(control_frame, text="Status:", style='Heading.TLabel').grid(
            row=9, column=0, sticky=tk.W, pady=(0, 5)
        )
        
        self.status_label = ttk.Label(
            control_frame,
            text="Ready",
            style='Status.TLabel',
            foreground='green'
        )
        self.status_label.grid(row=10, column=0, sticky=tk.W, pady=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(
            control_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.grid(row=11, column=0, sticky=tk.W, pady=(0, 10))
        
        # Info section
        info_frame = ttk.LabelFrame(control_frame, text="Information", padding="10")
        info_frame.grid(row=12, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        info_text = """
⚠️ EDUCATIONAL USE ONLY

Requirements:
• Close browser before running
• Must run as same Windows user
• Windows OS required (DPAPI)

This tool demonstrates how
infostealer malware extracts
browser passwords for security
training purposes.
        """
        
        ttk.Label(
            info_frame,
            text=info_text,
            font=('Arial', 8),
            justify=tk.LEFT
        ).grid(row=0, column=0, sticky=tk.W)
        
        # Right panel - Results with Notebook (Tabs)
        results_notebook = ttk.Notebook(main_frame)
        results_notebook.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Credentials Tab
        credentials_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(credentials_frame, text="Credentials")
        credentials_frame.columnconfigure(0, weight=1)
        credentials_frame.rowconfigure(0, weight=1)
        
        # History Tab
        history_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(history_frame, text="History")
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        
        # Downloads Tab
        downloads_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(downloads_frame, text="Downloads")
        downloads_frame.columnconfigure(0, weight=1)
        downloads_frame.rowconfigure(0, weight=1)
        
        # Cache Files Tab
        cache_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(cache_frame, text="Cache Files")
        cache_frame.columnconfigure(0, weight=1)
        cache_frame.rowconfigure(0, weight=1)
        
        # Downloaded Files Tab
        downloaded_files_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(downloaded_files_frame, text="Downloaded Files")
        downloaded_files_frame.columnconfigure(0, weight=1)
        downloaded_files_frame.rowconfigure(0, weight=1)
        
        # Detection Tab
        detection_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(detection_frame, text="Detection")
        detection_frame.columnconfigure(0, weight=1)
        detection_frame.rowconfigure(0, weight=1)
        
        # Credentials Results
        results_frame = ttk.LabelFrame(credentials_frame, text="Credentials", padding="10")
        results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Credentials Results header
        cred_header_frame = ttk.Frame(results_frame)
        cred_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.results_count_label = ttk.Label(
            cred_header_frame,
            text="No audit performed yet",
            style='Heading.TLabel'
        )
        self.results_count_label.grid(row=0, column=0, sticky=tk.W)
        
        # Credentials treeview (table)
        cred_tree_frame = ttk.Frame(results_frame)
        cred_tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cred_tree_frame.columnconfigure(0, weight=1)
        cred_tree_frame.rowconfigure(0, weight=1)
        
        # Create credentials treeview with scrollbars
        cred_scrollbar_y = ttk.Scrollbar(cred_tree_frame, orient=tk.VERTICAL)
        cred_scrollbar_x = ttk.Scrollbar(cred_tree_frame, orient=tk.HORIZONTAL)
        
        self.tree = ttk.Treeview(
            cred_tree_frame,
            columns=('URL', 'Username', 'Password', 'Last Used', 'Times Used'),
            show='headings',
            yscrollcommand=cred_scrollbar_y.set,
            xscrollcommand=cred_scrollbar_x.set,
            selectmode='extended'
        )
        
        # Configure columns
        self.tree.heading('URL', text='URL')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.heading('Last Used', text='Last Used')
        self.tree.heading('Times Used', text='Times Used')
        
        self.tree.column('URL', width=300, anchor=tk.W)
        self.tree.column('Username', width=200, anchor=tk.W)
        self.tree.column('Password', width=200, anchor=tk.W)
        self.tree.column('Last Used', width=150, anchor=tk.W)
        self.tree.column('Times Used', width=100, anchor=tk.CENTER)
        
        cred_scrollbar_y.config(command=self.tree.yview)
        cred_scrollbar_x.config(command=self.tree.xview)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cred_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        cred_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # History Results
        history_results_frame = ttk.LabelFrame(history_frame, text="Browser History", padding="10")
        history_results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        history_results_frame.columnconfigure(0, weight=1)
        history_results_frame.rowconfigure(1, weight=1)
        
        # History Results header
        hist_header_frame = ttk.Frame(history_results_frame)
        hist_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.history_count_label = ttk.Label(
            hist_header_frame,
            text="No history extracted yet",
            style='Heading.TLabel'
        )
        self.history_count_label.grid(row=0, column=0, sticky=tk.W)
        
        # History treeview (table)
        hist_tree_frame = ttk.Frame(history_results_frame)
        hist_tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        hist_tree_frame.columnconfigure(0, weight=1)
        hist_tree_frame.rowconfigure(0, weight=1)
        
        # Create history treeview with scrollbars
        hist_scrollbar_y = ttk.Scrollbar(hist_tree_frame, orient=tk.VERTICAL)
        hist_scrollbar_x = ttk.Scrollbar(hist_tree_frame, orient=tk.HORIZONTAL)
        
        self.history_tree = ttk.Treeview(
            hist_tree_frame,
            columns=('URL', 'Title', 'Visit Count', 'Last Visit', 'Transition'),
            show='headings',
            yscrollcommand=hist_scrollbar_y.set,
            xscrollcommand=hist_scrollbar_x.set,
            selectmode='extended'
        )
        
        # Configure history columns
        self.history_tree.heading('URL', text='URL')
        self.history_tree.heading('Title', text='Title')
        self.history_tree.heading('Visit Count', text='Visit Count')
        self.history_tree.heading('Last Visit', text='Last Visit')
        self.history_tree.heading('Transition', text='Type')
        
        self.history_tree.column('URL', width=400, anchor=tk.W)
        self.history_tree.column('Title', width=300, anchor=tk.W)
        self.history_tree.column('Visit Count', width=100, anchor=tk.CENTER)
        self.history_tree.column('Last Visit', width=150, anchor=tk.W)
        self.history_tree.column('Transition', width=120, anchor=tk.W)
        
        hist_scrollbar_y.config(command=self.history_tree.yview)
        hist_scrollbar_x.config(command=self.history_tree.xview)
        
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        hist_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hist_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Downloads Results
        downloads_results_frame = ttk.LabelFrame(downloads_frame, text="Download History", padding="10")
        downloads_results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        downloads_results_frame.columnconfigure(0, weight=1)
        downloads_results_frame.rowconfigure(1, weight=1)
        
        # Downloads Results header
        dl_header_frame = ttk.Frame(downloads_results_frame)
        dl_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.downloads_count_label = ttk.Label(
            dl_header_frame,
            text="No downloads extracted yet",
            style='Heading.TLabel'
        )
        self.downloads_count_label.grid(row=0, column=0, sticky=tk.W)
        
        # Downloads treeview (table)
        dl_tree_frame = ttk.Frame(downloads_results_frame)
        dl_tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        dl_tree_frame.columnconfigure(0, weight=1)
        dl_tree_frame.rowconfigure(0, weight=1)
        
        # Create downloads treeview with scrollbars
        dl_scrollbar_y = ttk.Scrollbar(dl_tree_frame, orient=tk.VERTICAL)
        dl_scrollbar_x = ttk.Scrollbar(dl_tree_frame, orient=tk.HORIZONTAL)
        
        self.downloads_tree = ttk.Treeview(
            dl_tree_frame,
            columns=('URL', 'Filename', 'Size', 'State', 'Danger', 'Start Time', 'Opened'),
            show='headings',
            yscrollcommand=dl_scrollbar_y.set,
            xscrollcommand=dl_scrollbar_x.set,
            selectmode='extended'
        )
        
        # Configure downloads columns
        self.downloads_tree.heading('URL', text='URL')
        self.downloads_tree.heading('Filename', text='Filename')
        self.downloads_tree.heading('Size', text='Size')
        self.downloads_tree.heading('State', text='State')
        self.downloads_tree.heading('Danger', text='Danger Type')
        self.downloads_tree.heading('Start Time', text='Start Time')
        self.downloads_tree.heading('Opened', text='Opened')
        
        self.downloads_tree.column('URL', width=350, anchor=tk.W)
        self.downloads_tree.column('Filename', width=250, anchor=tk.W)
        self.downloads_tree.column('Size', width=100, anchor=tk.CENTER)
        self.downloads_tree.column('State', width=120, anchor=tk.W)
        self.downloads_tree.column('Danger', width=120, anchor=tk.W)
        self.downloads_tree.column('Start Time', width=150, anchor=tk.W)
        self.downloads_tree.column('Opened', width=80, anchor=tk.CENTER)
        
        dl_scrollbar_y.config(command=self.downloads_tree.yview)
        dl_scrollbar_x.config(command=self.downloads_tree.xview)
        
        self.downloads_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        dl_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        dl_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Cache Files Results
        cache_results_frame = ttk.LabelFrame(cache_frame, text="Cache Files (HTML/CSS/JavaScript)", padding="10")
        cache_results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        cache_results_frame.columnconfigure(0, weight=1)
        cache_results_frame.rowconfigure(1, weight=1)
        
        cache_header_frame = ttk.Frame(cache_results_frame)
        cache_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.cache_count_label = ttk.Label(
            cache_header_frame,
            text="No cache files extracted yet",
            style='Heading.TLabel'
        )
        self.cache_count_label.grid(row=0, column=0, sticky=tk.W)
        
        cache_tree_frame = ttk.Frame(cache_results_frame)
        cache_tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cache_tree_frame.columnconfigure(0, weight=1)
        cache_tree_frame.rowconfigure(0, weight=1)
        
        cache_scrollbar_y = ttk.Scrollbar(cache_tree_frame, orient=tk.VERTICAL)
        cache_scrollbar_x = ttk.Scrollbar(cache_tree_frame, orient=tk.HORIZONTAL)
        
        self.cache_tree = ttk.Treeview(
            cache_tree_frame,
            columns=('Filename', 'Type', 'Size', 'Modified', 'Preview'),
            show='headings',
            yscrollcommand=cache_scrollbar_y.set,
            xscrollcommand=cache_scrollbar_x.set,
            selectmode='extended'
        )
        
        self.cache_tree.heading('Filename', text='Filename')
        self.cache_tree.heading('Type', text='Type')
        self.cache_tree.heading('Size', text='Size')
        self.cache_tree.heading('Modified', text='Modified')
        self.cache_tree.heading('Preview', text='Preview')
        
        self.cache_tree.column('Filename', width=300, anchor=tk.W)
        self.cache_tree.column('Type', width=100, anchor=tk.CENTER)
        self.cache_tree.column('Size', width=100, anchor=tk.CENTER)
        self.cache_tree.column('Modified', width=150, anchor=tk.W)
        self.cache_tree.column('Preview', width=300, anchor=tk.W)
        
        cache_scrollbar_y.config(command=self.cache_tree.yview)
        cache_scrollbar_x.config(command=self.cache_tree.xview)
        
        self.cache_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cache_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        cache_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Downloaded Files Results
        dl_files_results_frame = ttk.LabelFrame(downloaded_files_frame, text="Downloaded Files (Downloads Folder)", padding="10")
        dl_files_results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        dl_files_results_frame.columnconfigure(0, weight=1)
        dl_files_results_frame.rowconfigure(1, weight=1)
        
        dl_files_header_frame = ttk.Frame(dl_files_results_frame)
        dl_files_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.dl_files_count_label = ttk.Label(
            dl_files_header_frame,
            text="No files scanned yet",
            style='Heading.TLabel'
        )
        self.dl_files_count_label.grid(row=0, column=0, sticky=tk.W)
        
        dl_files_tree_frame = ttk.Frame(dl_files_results_frame)
        dl_files_tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        dl_files_tree_frame.columnconfigure(0, weight=1)
        dl_files_tree_frame.rowconfigure(0, weight=1)
        
        dl_files_scrollbar_y = ttk.Scrollbar(dl_files_tree_frame, orient=tk.VERTICAL)
        dl_files_scrollbar_x = ttk.Scrollbar(dl_files_tree_frame, orient=tk.HORIZONTAL)
        
        self.dl_files_tree = ttk.Treeview(
            dl_files_tree_frame,
            columns=('Filename', 'Type', 'Size', 'Suspicious', 'Modified', 'Indicators'),
            show='headings',
            yscrollcommand=dl_files_scrollbar_y.set,
            xscrollcommand=dl_files_scrollbar_x.set,
            selectmode='extended'
        )
        
        self.dl_files_tree.heading('Filename', text='Filename')
        self.dl_files_tree.heading('Type', text='Type')
        self.dl_files_tree.heading('Size', text='Size')
        self.dl_files_tree.heading('Suspicious', text='Suspicious')
        self.dl_files_tree.heading('Modified', text='Modified')
        self.dl_files_tree.heading('Indicators', text='Indicators')
        
        self.dl_files_tree.column('Filename', width=300, anchor=tk.W)
        self.dl_files_tree.column('Type', width=120, anchor=tk.CENTER)
        self.dl_files_tree.column('Size', width=100, anchor=tk.CENTER)
        self.dl_files_tree.column('Suspicious', width=100, anchor=tk.CENTER)
        self.dl_files_tree.column('Modified', width=150, anchor=tk.W)
        self.dl_files_tree.column('Indicators', width=200, anchor=tk.W)
        
        dl_files_scrollbar_y.config(command=self.dl_files_tree.yview)
        dl_files_scrollbar_x.config(command=self.dl_files_tree.xview)
        
        self.dl_files_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        dl_files_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        dl_files_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Detection Results
        detection_results_frame = ttk.LabelFrame(detection_frame, text="Unauthorized Access Detection", padding="10")
        detection_results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        detection_results_frame.columnconfigure(0, weight=1)
        detection_results_frame.rowconfigure(1, weight=1)
        
        detection_header_frame = ttk.Frame(detection_results_frame)
        detection_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.detection_risk_label = ttk.Label(
            detection_header_frame,
            text="No detection performed yet",
            style='Heading.TLabel'
        )
        self.detection_risk_label.grid(row=0, column=0, sticky=tk.W)
        
        detection_text_frame = ttk.Frame(detection_results_frame)
        detection_text_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        detection_text_frame.columnconfigure(0, weight=1)
        detection_text_frame.rowconfigure(0, weight=1)
        
        self.detection_text = scrolledtext.ScrolledText(
            detection_text_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            state='disabled'
        )
        self.detection_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Log/Status text area
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=8,
            wrap=tk.WORD,
            font=('Consolas', 9)
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.config(state='disabled')
        
        # Initial log message
        self.log("Application started. Ready to perform audit.")
        self.log("⚠️ EDUCATIONAL USE ONLY - For security training purposes")
    
    def log(self, message, level='INFO'):
        """Add message to log area."""
        self.log_text.config(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        if level == 'ERROR':
            prefix = f"[{timestamp}] [ERROR] "
            color = 'red'
        elif level == 'SUCCESS':
            prefix = f"[{timestamp}] [SUCCESS] "
            color = 'green'
        elif level == 'WARNING':
            prefix = f"[{timestamp}] [WARNING] "
            color = 'orange'
        else:
            prefix = f"[{timestamp}] [INFO] "
            color = 'black'
        
        self.log_text.insert(tk.END, prefix + message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def update_status(self, message, color='black'):
        """Update status label."""
        self.status_label.config(text=message, foreground=color)
        self.root.update_idletasks()
    
    def run_audit(self):
        """Run the credential audit in a separate thread."""
        if self.audit_running:
            messagebox.showwarning("Audit Running", "An audit is already in progress.")
            return
        
        browser = self.selected_browser.get()
        include_hist = self.include_history.get()
        include_dl = self.include_downloads.get()
        include_cache = self.include_cache.get()
        include_detection = self.include_detection.get()
        
        options = []
        if include_hist:
            options.append("browser history")
        if include_dl:
            options.append("download history")
        if include_cache:
            options.append("cache files")
        if include_detection:
            options.append("detection")
        options_text = "\n• Include " + ", ".join(options) if options else ""
        
        # Confirm before running
        response = messagebox.askyesno(
            "Confirm Audit",
            f"Are you ready to audit {browser}?\n\n"
            "⚠️ Make sure:\n"
            "• Browser is completely closed\n"
            "• You're running as the correct Windows user{history_text}\n\n"
            "Continue?",
            icon='warning'
        )
        
        if not response:
            return
        
        # Clear previous results
        self.clear_tree()
        
        # Start audit in thread
        self.audit_running = True
        self.run_button.config(state='disabled')
        self.export_button.config(state='disabled')
        self.progress.start()
        self.update_status("Running audit...", 'blue')
        
        thread = threading.Thread(target=self._perform_audit, args=(browser, include_hist, include_dl, include_cache, include_detection), daemon=True)
        thread.start()
    
    def _perform_audit(self, browser_name, include_history, include_downloads, include_cache, include_detection):
        """Perform the actual audit (runs in thread)."""
        try:
            self.log(f"Starting audit for {browser_name}...")
            self.log("Step 1: Initializing auditor...")
            
            # Initialize auditor
            auditor = BrowserCredentialAuditor(browser_name=browser_name)
            
            self.log("Step 2: Extracting master key from Local State...")
            auditor.master_key = auditor._get_master_key()
            self.log("✓ Master key extracted and decrypted")
            
            self.log("Step 3: Extracting credentials from Login Data...")
            credentials = auditor._extract_credentials()
            self.log(f"✓ Found {len(credentials)} saved credentials")
            
            history = []
            if include_history:
                self.log("Step 4: Extracting browser history...")
                try:
                    history = auditor._extract_history()
                    self.log(f"✓ Found {len(history)} history entries")
                except Exception as e:
                    self.log(f"⚠ History extraction failed: {str(e)}", 'WARNING')
                    history = []
            
            downloads = []
            if include_downloads:
                self.log("Step 5: Extracting download history...")
                try:
                    downloads = auditor._extract_downloads()
                    self.log(f"✓ Found {len(downloads)} download entries")
                except Exception as e:
                    self.log(f"⚠ Download extraction failed: {str(e)}", 'WARNING')
                    downloads = []
            
            cache_files = []
            if include_cache:
                self.log("Step 6: Extracting cache files (HTML/CSS/JS)...")
                try:
                    cache_files = auditor._extract_cache_files()
                    self.log(f"✓ Found {len(cache_files)} cache files")
                except Exception as e:
                    self.log(f"⚠ Cache file extraction failed: {str(e)}", 'WARNING')
                    cache_files = []
            
            # Always list downloaded files
            self.log("Step 7: Listing downloaded files from Downloads folder...")
            downloaded_files = []
            try:
                downloaded_files = auditor._list_downloaded_files()
                self.log(f"✓ Found {len(downloaded_files)} files in Downloads folder")
            except Exception as e:
                self.log(f"⚠ Downloaded files listing failed: {str(e)}", 'WARNING')
                downloaded_files = []
            
            detections = {}
            if include_detection:
                self.log("Step 8: Running unauthorized access detection...")
                try:
                    auditor.downloaded_files = downloaded_files
                    detections = auditor._detect_unauthorized_access()
                    self.log(f"✓ Detection complete. Risk level: {detections.get('risk_level', 'UNKNOWN')}")
                except Exception as e:
                    self.log(f"⚠ Detection failed: {str(e)}", 'WARNING')
                    detections = {}
            
            # Update UI in main thread
            self.root.after(0, self._audit_complete, credentials, history, downloads, cache_files, downloaded_files, detections, None)
            
        except FileNotFoundError as e:
            error_msg = str(e)
            self.log(f"File not found: {error_msg}", 'ERROR')
            self.root.after(0, self._audit_complete, [], [], [], [], [], {}, error_msg)
            
        except PermissionError as e:
            error_msg = str(e)
            self.log(f"Permission error: {error_msg}", 'ERROR')
            self.log("Make sure the browser is closed!", 'WARNING')
            self.root.after(0, self._audit_complete, [], [], [], [], [], {}, error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.log(error_msg, 'ERROR')
            self.root.after(0, self._audit_complete, [], [], [], [], [], {}, error_msg)
    
    def _audit_complete(self, credentials, history, downloads, cache_files, downloaded_files, detections, error):
        """Handle audit completion (called from main thread)."""
        self.audit_running = False
        self.progress.stop()
        self.run_button.config(state='normal')
        
        if error:
            self.update_status("Audit failed", 'red')
            messagebox.showerror("Audit Failed", error)
            self.log("Audit failed. See log for details.", 'ERROR')
        else:
            self.credentials = credentials
            self.history = history
            self.downloads = downloads
            self.cache_files = cache_files
            self.downloaded_files = downloaded_files
            self.detections = detections
            
            status_msg = f"Audit complete - {len(credentials)} credentials"
            if history:
                status_msg += f", {len(history)} history"
            if downloads:
                status_msg += f", {len(downloads)} downloads"
            if cache_files:
                status_msg += f", {len(cache_files)} cache files"
            if downloaded_files:
                status_msg += f", {len(downloaded_files)} files"
            self.update_status(status_msg, 'green')
            
            self.log(f"Audit completed successfully. Found {len(credentials)} credentials.", 'SUCCESS')
            if history:
                self.log(f"Found {len(history)} history entries.", 'SUCCESS')
            if downloads:
                self.log(f"Found {len(downloads)} download entries.", 'SUCCESS')
            if cache_files:
                self.log(f"Found {len(cache_files)} cache files.", 'SUCCESS')
            if downloaded_files:
                self.log(f"Found {len(downloaded_files)} downloaded files.", 'SUCCESS')
            if detections:
                risk = detections.get('risk_level', 'UNKNOWN')
                self.log(f"Detection complete. Risk level: {risk}", 'SUCCESS' if risk == 'LOW' else 'WARNING')
            
            if credentials:
                self.populate_tree(credentials)
                self.export_button.config(state='normal')
                
                msg = f"Successfully extracted {len(credentials)} credentials."
                if history:
                    msg += f"\nExtracted {len(history)} history entries."
                if downloads:
                    msg += f"\nExtracted {len(downloads)} download entries."
                if cache_files:
                    msg += f"\nExtracted {len(cache_files)} cache files."
                if downloaded_files:
                    msg += f"\nFound {len(downloaded_files)} files in Downloads folder."
                if detections:
                    risk = detections.get('risk_level', 'UNKNOWN')
                    msg += f"\n\nDetection Risk Level: {risk}"
                msg += "\n\n⚠️ This demonstrates what spyware would see."
                
                messagebox.showinfo("Audit Complete", msg)
            else:
                self.log("No credentials found in browser.", 'WARNING')
                messagebox.showinfo(
                    "No Credentials",
                    "No saved passwords found in the browser.\n\n"
                    "This could mean:\n"
                    "• No passwords are saved\n"
                    "• Using a different browser profile\n"
                    "• Browser data is stored elsewhere"
                )
            
            # Populate all result views
            if history:
                self.populate_history_tree(history)
            if downloads:
                self.populate_downloads_tree(downloads)
            if cache_files:
                self.populate_cache_tree(cache_files)
            if downloaded_files:
                self.populate_downloaded_files_tree(downloaded_files)
            if detections:
                self.populate_detection_results(detections)
    
    def populate_tree(self, credentials):
        """Populate the results treeview with credentials."""
        self.clear_tree()
        
        for cred in credentials:
            url = cred['url'] or '[No URL]'
            username = cred['username'] or '[No Username]'
            password = cred['password'] or '[No Password]'
            
            # Format dates
            if cred['last_used']:
                last_used = cred['last_used'].strftime('%Y-%m-%d %H:%M')
            else:
                last_used = 'Never'
            
            times_used = str(cred['times_used'] or 0)
            
            # Insert into tree
            self.tree.insert('', tk.END, values=(
                url[:80] + '...' if len(url) > 80 else url,
                username[:50] + '...' if len(username) > 50 else username,
                password[:50] + '...' if len(password) > 50 else password,
                last_used,
                times_used
            ))
        
        # Update count label
        self.results_count_label.config(
            text=f"Found {len(credentials)} credential(s)"
        )
    
    def populate_history_tree(self, history_entries):
        """Populate the history treeview with history entries."""
        # Clear existing entries
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        for entry in history_entries:
            url = entry['url'] or '[No URL]'
            title = entry['title'] or '[No Title]'
            visit_count = str(entry['visit_count'] or 0)
            
            if entry['last_visit']:
                last_visit = entry['last_visit'].strftime('%Y-%m-%d %H:%M')
            else:
                last_visit = 'Unknown'
            
            transition = entry.get('transition', 'Unknown')
            
            # Insert into tree
            self.history_tree.insert('', tk.END, values=(
                url[:100] + '...' if len(url) > 100 else url,
                title[:80] + '...' if len(title) > 80 else title,
                visit_count,
                last_visit,
                transition
            ))
        
        # Update count label
        self.history_count_label.config(
            text=f"Found {len(history_entries)} history entries"
        )
    
    def populate_downloads_tree(self, download_entries):
        """Populate the downloads treeview with download entries."""
        # Clear existing entries
        for item in self.downloads_tree.get_children():
            self.downloads_tree.delete(item)
        
        for entry in download_entries:
            url = entry['url'] or '[No URL]'
            filename = entry['filename'] or '[Unknown File]'
            size = entry['size'] or 'Unknown'
            state = entry['state'] or 'Unknown'
            danger = entry['danger_type'] or 'Unknown'
            
            if entry['start_time']:
                start_time = entry['start_time'].strftime('%Y-%m-%d %H:%M')
            else:
                start_time = 'Unknown'
            
            opened = 'Yes' if entry['opened'] else 'No'
            
            # Insert into tree
            self.downloads_tree.insert('', tk.END, values=(
                url[:100] + '...' if len(url) > 100 else url,
                filename[:80] + '...' if len(filename) > 80 else filename,
                size,
                state,
                danger,
                start_time,
                opened
            ))
        
        # Update count label
        self.downloads_count_label.config(
            text=f"Found {len(download_entries)} download entries"
        )
    
    def populate_cache_tree(self, cache_files):
        """Populate the cache files treeview."""
        for item in self.cache_tree.get_children():
            self.cache_tree.delete(item)
        
        for entry in cache_files:
            filename = entry['filename'] or '[Unknown]'
            file_type = entry['type'] or 'Unknown'
            size = entry['size'] or 'Unknown'
            modified = entry['modified'].strftime('%Y-%m-%d %H:%M') if entry.get('modified') else 'Unknown'
            preview = entry.get('preview', '')[:50] + '...' if len(entry.get('preview', '')) > 50 else entry.get('preview', '')
            
            self.cache_tree.insert('', tk.END, values=(
                filename[:80] + '...' if len(filename) > 80 else filename,
                file_type,
                size,
                modified,
                preview
            ))
        
        self.cache_count_label.config(text=f"Found {len(cache_files)} cache files")
    
    def populate_downloaded_files_tree(self, downloaded_files):
        """Populate the downloaded files treeview."""
        for item in self.dl_files_tree.get_children():
            self.dl_files_tree.delete(item)
        
        for entry in downloaded_files:
            filename = entry['filename'] or '[Unknown]'
            file_type = entry['type'] or 'Unknown'
            size = entry['size'] or 'Unknown'
            suspicious = 'YES' if entry.get('suspicious', False) else 'NO'
            modified = entry['modified'].strftime('%Y-%m-%d %H:%M') if entry.get('modified') else 'Unknown'
            indicators = ', '.join(entry.get('indicators', [])) or 'None'
            
            self.dl_files_tree.insert('', tk.END, values=(
                filename[:80] + '...' if len(filename) > 80 else filename,
                file_type,
                size,
                suspicious,
                modified,
                indicators
            ))
        
        suspicious_count = sum(1 for f in downloaded_files if f.get('suspicious', False))
        self.dl_files_count_label.config(
            text=f"Found {len(downloaded_files)} files ({suspicious_count} suspicious)"
        )
    
    def populate_detection_results(self, detections):
        """Populate the detection results text area."""
        self.detection_text.config(state='normal')
        self.detection_text.delete(1.0, tk.END)
        
        risk_level = detections.get('risk_level', 'UNKNOWN')
        risk_color = 'red' if risk_level == 'HIGH' else 'orange' if risk_level == 'MEDIUM' else 'green'
        
        self.detection_risk_label.config(
            text=f"Risk Level: {risk_level}",
            foreground=risk_color
        )
        
        output = f"UNAUTHORIZED ACCESS DETECTION RESULTS\n"
        output += "=" * 80 + "\n\n"
        output += f"Overall Risk Level: {risk_level}\n"
        output += f"Timestamp: {detections.get('timestamp', 'Unknown')}\n\n"
        
        unauthorized = detections.get('unauthorized_access', [])
        if unauthorized:
            output += f"UNAUTHORIZED ACCESS PATTERNS ({len(unauthorized)}):\n"
            output += "-" * 80 + "\n"
            for access in unauthorized:
                output += f"\nFile: {access['file']}\n"
                output += f"  Type: {access['type']}\n"
                output += f"  Risk: {access['risk']}\n"
                output += f"  Last Access: {access['last_access']}\n"
                output += f"  Description: {access['description']}\n"
                output += f"  Path: {access['path']}\n"
        else:
            output += "No unauthorized access patterns detected.\n"
        
        output += "\n"
        
        suspicious = detections.get('suspicious_files', [])
        if suspicious:
            output += f"\nSUSPICIOUS FILES ({len(suspicious)}):\n"
            output += "-" * 80 + "\n"
            for file in suspicious[:20]:  # Show first 20
                output += f"\nFile: {file['filename']}\n"
                output += f"  Type: {file['type']}\n"
                output += f"  Indicators: {', '.join(file.get('indicators', []))}\n"
                output += f"  Path: {file['path']}\n"
        else:
            output += "\nNo suspicious files detected.\n"
        
        output += "\n"
        
        threats = detections.get('threats', [])
        if threats:
            output += f"\nTHREATS DETECTED ({len(threats)}):\n"
            output += "-" * 80 + "\n"
            for threat in threats:
                output += f"\nType: {threat['type']}\n"
                output += f"  Risk: {threat['risk']}\n"
                output += f"  Description: {threat['description']}\n"
        else:
            output += "\nNo threats detected.\n"
        
        self.detection_text.insert(1.0, output)
        self.detection_text.config(state='disabled')
    
    def clear_tree(self):
        """Clear all items from the treeviews."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results_count_label.config(text="No results")
        
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self.history_count_label.config(text="No history extracted yet")
        
        for item in self.downloads_tree.get_children():
            self.downloads_tree.delete(item)
        self.downloads_count_label.config(text="No downloads extracted yet")
        
        for item in self.cache_tree.get_children():
            self.cache_tree.delete(item)
        self.cache_count_label.config(text="No cache files extracted yet")
        
        for item in self.dl_files_tree.get_children():
            self.dl_files_tree.delete(item)
        self.dl_files_count_label.config(text="No files scanned yet")
        
        self.detection_text.config(state='normal')
        self.detection_text.delete(1.0, tk.END)
        self.detection_text.config(state='disabled')
        self.detection_risk_label.config(text="No detection performed yet", foreground='black')
    
    def clear_results(self):
        """Clear all results and log."""
        self.clear_tree()
        self.credentials = []
        self.history = []
        self.downloads = []
        self.cache_files = []
        self.downloaded_files = []
        self.detections = {}
        self.export_button.config(state='disabled')
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
        self.log("Results cleared. Ready for new audit.")
        self.update_status("Ready", 'green')
    
    def export_results(self):
        """Export results to a text file."""
        if not self.credentials:
            messagebox.showwarning("No Results", "No credentials to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ],
            title="Export Credentials"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 100 + "\n")
                f.write("Browser Credential Audit Results\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 100 + "\n\n")
                
                f.write(f"{'URL':<50} | {'Username':<30} | {'Password':<25} | {'Last Used':<20} | {'Times Used':<10}\n")
                f.write("-" * 100 + "\n")
                
                for cred in self.credentials:
                    url = cred['url'] or '[No URL]'
                    username = cred['username'] or '[No Username]'
                    password = cred['password'] or '[No Password]'
                    
                    if cred['last_used']:
                        last_used = cred['last_used'].strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        last_used = 'Never'
                    
                    times_used = str(cred['times_used'] or 0)
                    
                    f.write(f"{url[:47]:<50} | {username[:27]:<30} | {password[:22]:<25} | {last_used:<20} | {times_used:<10}\n")
                
                f.write("\n" + "=" * 100 + "\n")
                f.write(f"Total Credentials: {len(self.credentials)}\n")
                f.write("=" * 100 + "\n")
                
                # Export history if available
                if self.history:
                    f.write("\n\n" + "=" * 100 + "\n")
                    f.write("BROWSER HISTORY\n")
                    f.write("=" * 100 + "\n\n")
                    
                    f.write(f"{'URL':<60} | {'Title':<40} | {'Visit Count':<12} | {'Last Visit':<20} | {'Type':<15}\n")
                    f.write("-" * 100 + "\n")
                    
                    for entry in self.history:
                        url = entry['url'] or '[No URL]'
                        title = entry['title'] or '[No Title]'
                        visit_count = str(entry['visit_count'] or 0)
                        
                        if entry['last_visit']:
                            last_visit = entry['last_visit'].strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            last_visit = 'Unknown'
                        
                        transition = entry.get('transition', 'Unknown')
                        
                        f.write(f"{url[:57]:<60} | {title[:37]:<40} | {visit_count:<12} | {last_visit:<20} | {transition:<15}\n")
                    
                    f.write("\n" + "=" * 100 + "\n")
                    f.write(f"Total History Entries: {len(self.history)}\n")
                    f.write("=" * 100 + "\n")
                
                # Export downloads if available
                if self.downloads:
                    f.write("\n\n" + "=" * 100 + "\n")
                    f.write("DOWNLOAD HISTORY\n")
                    f.write("=" * 100 + "\n\n")
                    
                    f.write(f"{'URL':<50} | {'Filename':<30} | {'Size':<12} | {'State':<15} | {'Danger':<15} | {'Start Time':<20} | {'Opened':<8}\n")
                    f.write("-" * 100 + "\n")
                    
                    for entry in self.downloads:
                        url = entry['url'] or '[No URL]'
                        filename = entry['filename'] or '[Unknown File]'
                        size = entry['size'] or 'Unknown'
                        state = entry['state'] or 'Unknown'
                        danger = entry['danger_type'] or 'Unknown'
                        
                        if entry['start_time']:
                            start_time = entry['start_time'].strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            start_time = 'Unknown'
                        
                        opened = 'Yes' if entry['opened'] else 'No'
                        
                        f.write(f"{url[:47]:<50} | {filename[:27]:<30} | {size:<12} | {state:<15} | {danger:<15} | {start_time:<20} | {opened:<8}\n")
                    
                    f.write("\n" + "=" * 100 + "\n")
                    f.write(f"Total Download Entries: {len(self.downloads)}\n")
                    f.write("=" * 100 + "\n")
                
                # Export cache files if available
                if self.cache_files:
                    f.write("\n\n" + "=" * 100 + "\n")
                    f.write("CACHE FILES (HTML/CSS/JavaScript)\n")
                    f.write("=" * 100 + "\n\n")
                    
                    f.write(f"{'Filename':<50} | {'Type':<12} | {'Size':<12} | {'Modified':<20}\n")
                    f.write("-" * 100 + "\n")
                    
                    for entry in self.cache_files:
                        filename = entry['filename'] or '[Unknown]'
                        file_type = entry['type'] or 'Unknown'
                        size = entry['size'] or 'Unknown'
                        modified = entry['modified'].strftime('%Y-%m-%d %H:%M:%S') if entry.get('modified') else 'Unknown'
                        
                        f.write(f"{filename[:47]:<50} | {file_type:<12} | {size:<12} | {modified:<20}\n")
                    
                    f.write("\n" + "=" * 100 + "\n")
                    f.write(f"Total Cache Files: {len(self.cache_files)}\n")
                    f.write("=" * 100 + "\n")
                
                # Export downloaded files if available
                if self.downloaded_files:
                    f.write("\n\n" + "=" * 100 + "\n")
                    f.write("DOWNLOADED FILES (Downloads Folder)\n")
                    f.write("=" * 100 + "\n\n")
                    
                    f.write(f"{'Filename':<50} | {'Type':<15} | {'Size':<12} | {'Suspicious':<12} | {'Modified':<20}\n")
                    f.write("-" * 100 + "\n")
                    
                    for entry in self.downloaded_files:
                        filename = entry['filename'] or '[Unknown]'
                        file_type = entry['type'] or 'Unknown'
                        size = entry['size'] or 'Unknown'
                        suspicious = 'YES' if entry.get('suspicious', False) else 'NO'
                        modified = entry['modified'].strftime('%Y-%m-%d %H:%M:%S') if entry.get('modified') else 'Unknown'
                        
                        f.write(f"{filename[:47]:<50} | {file_type:<15} | {size:<12} | {suspicious:<12} | {modified:<20}\n")
                        
                        if entry.get('suspicious', False) and entry.get('indicators'):
                            f.write(f"  Indicators: {', '.join(entry['indicators'])}\n")
                    
                    f.write("\n" + "=" * 100 + "\n")
                    f.write(f"Total Downloaded Files: {len(self.downloaded_files)}\n")
                    suspicious_count = sum(1 for f in self.downloaded_files if f.get('suspicious', False))
                    f.write(f"Suspicious Files: {suspicious_count}\n")
                    f.write("=" * 100 + "\n")
                
                # Export detection results if available
                if self.detections:
                    f.write("\n\n" + "=" * 100 + "\n")
                    f.write("UNAUTHORIZED ACCESS DETECTION\n")
                    f.write("=" * 100 + "\n\n")
                    
                    f.write(f"Risk Level: {self.detections.get('risk_level', 'UNKNOWN')}\n")
                    f.write(f"Timestamp: {self.detections.get('timestamp', 'Unknown')}\n\n")
                    
                    unauthorized = self.detections.get('unauthorized_access', [])
                    if unauthorized:
                        f.write(f"Unauthorized Access Patterns ({len(unauthorized)}):\n")
                        f.write("-" * 100 + "\n")
                        for access in unauthorized:
                            f.write(f"\nFile: {access['file']}\n")
                            f.write(f"  Type: {access['type']}\n")
                            f.write(f"  Risk: {access['risk']}\n")
                            f.write(f"  Description: {access['description']}\n")
                    
                    suspicious = self.detections.get('suspicious_files', [])
                    if suspicious:
                        f.write(f"\n\nSuspicious Files ({len(suspicious)}):\n")
                        f.write("-" * 100 + "\n")
                        for file in suspicious:
                            f.write(f"\n{file['filename']}\n")
                            f.write(f"  Indicators: {', '.join(file.get('indicators', []))}\n")
                    
                    f.write("\n" + "=" * 100 + "\n")
            
            self.log(f"Results exported to: {filename}", 'SUCCESS')
            messagebox.showinfo("Export Complete", f"Results exported to:\n{filename}")
            
        except Exception as e:
            error_msg = f"Failed to export: {str(e)}"
            self.log(error_msg, 'ERROR')
            messagebox.showerror("Export Failed", error_msg)


def main():
    """Main entry point for GUI application."""
    root = tk.Tk()
    app = CredentialAuditGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
