#!/usr/bin/env python3
"""
SecurePass Manager - Advanced Password Generator and Manager
==========================================================

A comprehensive command-line tool for generating secure passwords, evaluating password strength,
and managing encrypted password history with notes.

Features:
- Secure password generation with multiple options
- Comprehensive password strength analysis
- Encrypted storage with secure backup
- Password history management
- Secure notes with encryption
- QR code generation for passwords
- Interactive UI with real-time feedback
- Advanced security features

License: MIT
Repository: https://github.com/0xmezbah/guptodhon
"""

import argparse
import json
import os
import secrets
import string
import sys
import time
from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from getpass import getpass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from enum import Enum
import csv

# UI and formatting imports
import colorama
from colorama import Fore, Back, Style
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
from rich.layout import Layout
from rich.style import Style as RichStyle
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.live import Live
from rich.align import Align
from pyfiglet import Figlet
from yaspin import yaspin
from yaspin.spinners import Spinners
from alive_progress import alive_bar
import qrcode
from PIL import Image

# Cryptography imports
import pyperclip
import zxcvbn
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Initialize colorama for Windows support
colorama.init()

# ASCII Art Banner
BANNER = r"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  ____                           ____                 __  __                ║
║ |  _ \ __ _ ___ _____      __ / ___| ___ _ __     |  \/  | __ _ _ __    ║
║ | |_) / _` / __/ __\ \ /\ / // |  _ / _ \ '_ \    | |\/| |/ _` | '_ \   ║
║ |  __/ (_| \__ \__ \\ V  V / | |_| |  __/ | | |   | |  | | (_| | | | |  ║
║ |_|   \__,_|___/___/ \_/\_/   \____|\___|_| |_|   |_|  |_|\__,_|_| |_|  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

# Application Constants
APP_NAME = GuptoDhon"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Mezbah"
APP_GITHUB = "https://github.com/0xmezbah/GuptoDhon"
APP_LICENSE = "MIT"
APP_DESCRIPTION = """
🔐 Advanced Password Generator and Manager

Features:
• 🎲 Secure password generation with multiple options
• 🔍 Comprehensive password strength analysis
• 🔒 Encrypted storage with secure backup
• 📜 Password history management
• 📝 Secure notes with encryption
• 📱 QR code generation for passwords
• 💻 Interactive UI with real-time feedback
• 🛡️ Advanced security features
"""

# File and Path Constants
MIN_PASSWORD_LENGTH = 12
DEFAULT_PASSWORD_LENGTH = 16
MAX_PASSWORD_LENGTH = 128
DATA_FILE = "password_data.encrypted"
SALT_LENGTH = 32
KEY_LENGTH = 32
ITERATIONS = 480000
MAX_PASSWORDS_PER_REQUEST = 100
DEFAULT_DISPLAY_LIMIT = 50
BACKUP_EXTENSION = ".bak"
CONFIG_FILE = "config.json"

# UI Constants
TABLE_HEADERS = ["ID", "Password", "Created At", "Note"]
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# UI Theme
class Theme:
    """Application theme constants with extended styles"""
    PRIMARY = "cyan"
    SECONDARY = "magenta"
    SUCCESS = "green"
    ERROR = "red"
    WARNING = "yellow"
    INFO = "blue"
    
    # Extended styles
    HIGHLIGHT = RichStyle(color="cyan", bold=True)
    DIMMED = RichStyle(dim=True)
    CODE = RichStyle(color="green", bold=True)
    URL = RichStyle(color="blue", underline=True)
    CRITICAL = RichStyle(color="red", bold=True, blink=True)
    
    # Animation styles
    SPINNER = Spinners.dots12
    PROGRESS_BAR = "[progress.description]{task.description}"
    
    # Extended icons
    EXTENDED_ICONS = {
        'star': '⭐',
        'sparkles': '✨',
        'fire': '🔥',
        'zap': '⚡',
        'gem': '💎',
        'trophy': '🏆',
        'medal': '🏅',
        'crown': '👑',
        'shield': '🛡️',
        'check_mark': '✅',
        'cross_mark': '❌',
        'warning_sign': '⚠️',
        'info_sign': 'ℹ️',
        'question': '❓',
        'exclamation': '❗',
        'thinking': '🤔',
        'lightbulb': '💡',
        'key': '🔑',
        'lock': '🔒',
        'unlock': '🔓',
    }

class PasswordStrength(Enum):
    """Password strength levels with associated colors and emojis"""
    VERY_WEAK = (0, 20, Theme.ERROR, "🔴")
    WEAK = (20, 40, Theme.WARNING, "🟡")
    MEDIUM = (40, 60, Theme.INFO, "🟡")
    STRONG = (60, 80, Theme.SUCCESS, "🟢")
    VERY_STRONG = (80, 101, Theme.SUCCESS, "✨")

    @classmethod
    def get_strength(cls, score: float) -> 'PasswordStrength':
        for strength in cls:
            if strength.value[0] <= score < strength.value[1]:
                return strength
        return cls.VERY_WEAK

class ErrorCodes(Enum):
    """Error codes for better error handling"""
    SUCCESS = 0
    INVALID_INPUT = 1
    FILE_ERROR = 2
    ENCRYPTION_ERROR = 3
    DECRYPTION_ERROR = 4
    PERMISSION_ERROR = 5
    CONFIGURATION_ERROR = 6
    VALIDATION_ERROR = 7
    RUNTIME_ERROR = 8
    UNKNOWN_ERROR = 9

class ValidationError(Exception):
    """Custom exception for validation errors"""
    def __init__(self, message: str, error_code: ErrorCodes = ErrorCodes.VALIDATION_ERROR):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

class ConfigurationError(Exception):
    """Custom exception for configuration errors"""
    def __init__(self, message: str, error_code: ErrorCodes = ErrorCodes.CONFIGURATION_ERROR):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

class EncryptionError(Exception):
    """Custom exception for encryption/decryption errors"""
    def __init__(self, message: str, error_code: ErrorCodes = ErrorCodes.ENCRYPTION_ERROR):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

class UIHelper:
    """Enhanced helper class for UI formatting and display"""
    
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self.figlet = Figlet(font='slant')
        
    def display_welcome(self) -> None:
        """Display an enhanced welcome message with ASCII art"""
        # Display ASCII banner
        self.console.print(BANNER, style="cyan bold")
        
        # Display app info
        info_panel = Panel(
            Markdown(APP_DESCRIPTION),
            title=f"[cyan]{APP_NAME}[/cyan] [dim]v{APP_VERSION}[/dim]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(info_panel)
        
        # Display quick help
        help_text = """
        Quick Commands:
        • 🎲 Generate password:    -g [length]
        • 🔍 Check strength:       -s <password>
        • 📜 View history:         -vn
        • 📋 View all:             -vna
        • 💡 Help:                --help
        • 🔑 Set master pass:      -m <password>
        • 💾 Backup:              --backup
        • 📥 Restore:             --restore
        """
        help_panel = Panel(
            help_text,
            title="Quick Reference",
            border_style="blue",
            padding=(1, 2),
        )
        self.console.print(help_panel)

    def display_password(self, password: str, strength_info: Optional[Dict] = None) -> None:
        """Display a password with optional strength information"""
        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(password)
        qr.make(fit=True)
        
        # Save QR code temporarily
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_path = "temp_qr.png"
        qr_img.save(qr_path)
        
        # Display password in a fancy box
        password_panel = Panel(
            Text(password, style="bold green"),
            title="🔑 Generated Password",
            border_style="green",
            padding=(1, 2),
        )
        self.console.print(password_panel)
        
        if strength_info:
            strength = PasswordStrength.get_strength(strength_info['score'])
            strength_bar = "█" * int(strength_info['score'] / 10)
            strength_panel = Panel(
                f"Strength: {strength_bar} ({strength_info['score']}%)\n"
                f"Rating: {strength.name.replace('_', ' ')}\n"
                f"Entropy: {strength_info['entropy']:.1f} bits",
                title="💪 Password Strength",
                border_style=strength.value[2],
                padding=(1, 2),
            )
            self.console.print(strength_panel)
        
        # Display QR code location
        self.console.print(f"\n📱 QR Code saved as: {qr_path}")

    def animate_operation(self, message: str, duration: float = 1.0) -> None:
        """Show an animated spinner during an operation"""
        with yaspin(Theme.SPINNER, text=message) as spinner:
            time.sleep(duration)
            spinner.ok("✓")

    def print_success(self, message: str) -> None:
        """Print a success message"""
        self.console.print(f"✅ {message}", style="bold green")
        
    def print_error(self, message: str, error_code: Optional[ErrorCodes] = None) -> None:
        """Print an error message"""
        error_msg = f"❌ {message}"
        if error_code:
            error_msg += f" (Error code: {error_code.value})"
        self.console.print(error_msg, style="bold red")
        
    def print_warning(self, message: str) -> None:
        """Print a warning message"""
        self.console.print(f"⚠️ {message}", style="bold yellow")
        
    def print_info(self, message: str) -> None:
        """Print an info message"""
        self.console.print(f"ℹ️ {message}", style="bold blue")

    def confirm_action(self, message: str, default: bool = False) -> bool:
        """Get user confirmation with styled prompt"""
        return Confirm.ask(message, default=default)

    def get_secure_input(self, message: str, password: bool = True) -> str:
        """Get secure input from user"""
        return Prompt.ask(message, password=password)

    def display_password_table(self, passwords: List[Dict], notes: Dict[str, str],
                             limit: Optional[int] = None, show_all: bool = False) -> None:
        """Display passwords in a formatted table"""
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
            title="🔐 Password History",
            title_style="bold cyan"
        )
        
        # Add columns with icons
        table.add_column("🔢 ID", style="dim", width=4)
        table.add_column("🔑 Password", style="bold")
        table.add_column("📅 Created", style="dim")
        table.add_column("📝 Note", style="italic")

        passwords_to_show = passwords if show_all else passwords[:limit]
        
        for idx, entry in enumerate(passwords_to_show, 1):
            password = entry['password']
            created_at = datetime.fromisoformat(entry['created_at']).strftime('%Y-%m-%d %H:%M')
            note = notes.get(password, "")
            
            # Alternate row styles
            row_style = "dim" if idx % 2 == 0 else "bold"
            table.add_row(
                str(idx),
                password,
                created_at,
                note,
                style=row_style
            )

        self.console.print(table)
        
        if not show_all and len(passwords) > limit:
            self.print_info(f"📄 Showing {limit} of {len(passwords)} passwords. Use -vna to view all.")

    def display_strength_report(self, report: Dict) -> None:
        """Display password strength report with colors and emojis"""
        strength = PasswordStrength.get_strength(report['score'])
        
        # Main metrics table
        metrics_table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
            title="💪 Password Strength Analysis",
            title_style="bold cyan"
        )
        
        metrics_table.add_column("Metric", style="bold")
        metrics_table.add_column("Value")
        
        metrics_table.add_row(
            "Score",
            Text(f"{report['score']:.1f}/100 {strength.value[3]}", style=RichStyle(color=strength.value[2]))
        )
        
        metrics_table.add_row(
            "Rating",
            Text(strength.name.replace('_', ' '), style=RichStyle(color=strength.value[2]))
        )
        
        metrics_table.add_row(
            "Entropy",
            f"{report['entropy']:.1f} bits"
        )
        
        self.console.print(metrics_table)
        
        # Warnings table
        if report['warnings']:
            warning_table = Table(
                show_header=True,
                header_style="bold yellow",
                box=box.ROUNDED,
                title="⚠️ Warnings"
            )
            warning_table.add_column("Warning Message")
            for warning in report['warnings']:
                warning_table.add_row(warning)
            self.console.print(warning_table)
        
        # Suggestions table
        if report['suggestions']:
            suggestion_table = Table(
                show_header=True,
                header_style="bold green",
                box=box.ROUNDED,
                title="💡 Suggestions"
            )
            suggestion_table.add_column("Suggestion")
            for suggestion in report['suggestions']:
                suggestion_table.add_row(suggestion)
            self.console.print(suggestion_table)

    def display_progress(self, message: str) -> Progress:
        """Create and return a progress indicator"""
        progress = Progress(
            SpinnerColumn(),
            TextColumn(Theme.PROGRESS_BAR),
            BarColumn(),
            console=self.console
        )
        progress.add_task(message, total=None)
        return progress

class PasswordError(Exception):
    """Custom exception for password-related errors"""
    pass

class PasswordData:
    """Class to handle password data storage and encryption"""
    
    def __init__(self, master_password: str):
        if not master_password:
            raise PasswordError("Master password cannot be empty")
        self.master_password = master_password
        self.ph = PasswordHasher()
        self._load_or_initialize_data()

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=salt,
                iterations=ITERATIONS
            )
            return kdf.derive(self.master_password.encode())
        except Exception as e:
            raise PasswordError(f"Error deriving encryption key: {e}")

    def _load_or_initialize_data(self) -> None:
        """Load existing data or initialize new encrypted storage"""
        try:
            self.data_path = Path(DATA_FILE)
            if not self.data_path.exists():
                salt = secrets.token_bytes(SALT_LENGTH)
                key = self._derive_key(salt)
                self.fernet = Fernet(b64encode(key))
                self.data = {
                    'version': '2.0',
                    'salt': b64encode(salt).decode(),
                    'passwords': [],
                    'notes': {},
                    'categories': {},
                    'tags': {},
                    'favorites': set(),
                    'expiry_dates': {},
                    'update_history': {},
                    'strength_history': {},
                    'statistics': {
                        'total_generated': 0,
                        'total_custom': 0,
                        'avg_strength': 0,
                        'last_update': None
                    }
                }
                self._save_data()
            else:
                self._load_data()
        except Exception as e:
            raise PasswordError(f"Error initializing data: {e}")

    def _load_data(self) -> None:
        """Load and decrypt existing data"""
        try:
            encrypted_data = self.data_path.read_bytes()
            try:
                # First try to parse the entire file as JSON
                data_dict = json.loads(encrypted_data)
                if 'salt' not in data_dict:
                    raise PasswordError("Invalid data file format: missing salt")
                salt = b64decode(data_dict['salt'])
                key = self._derive_key(salt)
                self.fernet = Fernet(b64encode(key))
                
                # The actual data is stored in the 'encrypted_data' field
                if 'encrypted_data' not in data_dict:
                    raise PasswordError("Invalid data file format: missing encrypted data")
                
                decrypted_data = self.fernet.decrypt(data_dict['encrypted_data'].encode())
                self.data = json.loads(decrypted_data)
                self.data['salt'] = data_dict['salt']  # Keep the salt in the data
            except json.JSONDecodeError:
                raise PasswordError("Invalid data file format: corrupted JSON")
            except Exception as e:
                raise PasswordError(f"Error decrypting data: {e}")
        except Exception as e:
            raise PasswordError(f"Error loading data: {e}")

    def _save_data(self) -> None:
        """Encrypt and save data"""
        try:
            # Store salt separately from the encrypted data
            salt = self.data.pop('salt', None)
            if not salt:
                raise PasswordError("Missing salt in data")
            
            # Encrypt the actual data
            encrypted_data = self.fernet.encrypt(json.dumps(self.data).encode())
            
            # Create the final structure
            final_data = {
                'salt': salt,
                'encrypted_data': encrypted_data.decode()
            }
            
            # Put salt back in the data
            self.data['salt'] = salt
            
            # Atomic write using temporary file
            temp_path = self.data_path.with_suffix('.tmp')
            temp_path.write_bytes(json.dumps(final_data).encode())
            temp_path.replace(self.data_path)
        except Exception as e:
            raise PasswordError(f"Error saving data: {e}")

    def add_password(self, password: str, note: Optional[str] = None) -> None:
        """Add a password and optional note to storage"""
        if not password:
            raise PasswordError("Password cannot be empty")
        
        timestamp = datetime.now().isoformat()
        self.data['passwords'].append({
            'password': password,
            'created_at': timestamp
        })
        if note:
            self.data['notes'][password] = note
        self._save_data()

    def get_history(self) -> List[Dict]:
        """Retrieve password history"""
        return self.data['passwords']

    def clear_history(self) -> None:
        """Securely clear password history"""
        try:
            # Overwrite with random data before clearing
            self.data['passwords'] = [{'password': secrets.token_hex(32), 'created_at': datetime.now().isoformat()}
                                    for _ in range(len(self.data['passwords']))]
            self._save_data()  # Save the random overwrite
            # Now clear the data
            self.data['passwords'] = []
            self.data['notes'] = {}
            self._save_data()
        except Exception as e:
            raise PasswordError(f"Error clearing history: {e}")

    def add_note(self, password: str, note: str) -> None:
        """Add or update a note for a password"""
        if not password:
            raise PasswordError("Password cannot be empty")
        if not note:
            raise PasswordError("Note cannot be empty")
        self.data['notes'][password] = note
        self._save_data()

    def get_note(self, password: str) -> Optional[str]:
        """Retrieve note for a password"""
        return self.data['notes'].get(password)

    def delete_password_by_id(self, password_id: int) -> None:
        """Delete a password by its ID (1-based index)"""
        try:
            if not self.data['passwords']:
                raise PasswordError("No passwords in history")
            
            if password_id < 1 or password_id > len(self.data['passwords']):
                raise PasswordError(f"Invalid password ID. Must be between 1 and {len(self.data['passwords'])}")
            
            # Get the password to delete
            password = self.data['passwords'][password_id - 1]['password']
            
            # Delete password and its note
            self.data['passwords'].pop(password_id - 1)
            if password in self.data['notes']:
                del self.data['notes'][password]
            
            self._save_data()
        except Exception as e:
            raise PasswordError(f"Error deleting password: {e}")

    def edit_note_by_id(self, password_id: int, new_note: str) -> None:
        """Edit note for a password by its ID"""
        try:
            if not self.data['passwords']:
                raise PasswordError("No passwords in history")
            
            if password_id < 1 or password_id > len(self.data['passwords']):
                raise PasswordError(f"Invalid password ID. Must be between 1 and {len(self.data['passwords'])}")
            
            password = self.data['passwords'][password_id - 1]['password']
            self.data['notes'][password] = new_note
            self._save_data()
        except Exception as e:
            raise PasswordError(f"Error editing note: {e}")

    def get_password_by_id(self, password_id: int) -> str:
        """Get a password by its ID"""
        try:
            if not self.data['passwords']:
                raise PasswordError("No passwords in history")
            
            if password_id < 1 or password_id > len(self.data['passwords']):
                raise PasswordError(f"Invalid password ID. Must be between 1 and {len(self.data['passwords'])}")
            
            return self.data['passwords'][password_id - 1]['password']
        except Exception as e:
            raise PasswordError(f"Error retrieving password: {e}")

    def search_passwords(self, query: str) -> List[Dict]:
        """Search passwords and notes"""
        try:
            results = []
            query = query.lower()
            
            for idx, entry in enumerate(self.data['passwords'], 1):
                password = entry['password']
                note = self.data['notes'].get(password, "")
                
                if (query in password.lower() or 
                    query in note.lower() or 
                    query in entry['created_at'].lower()):
                    results.append({
                        'id': idx,
                        'password': password,
                        'created_at': entry['created_at'],
                        'note': note
                    })
            
            return results
        except Exception as e:
            raise PasswordError(f"Error searching passwords: {e}")

    def export_data(self, export_path: str, include_passwords: bool = False) -> None:
        """Export data to a JSON file"""
        try:
            export_data = {
                'version': self.data.get('version', '1.0'),
                'created_at': datetime.now().isoformat(),
                'notes': self.data['notes']
            }
            
            if include_passwords:
                export_data['passwords'] = self.data['passwords']
            else:
                # Export only metadata without actual passwords
                export_data['password_count'] = len(self.data['passwords'])
                export_data['password_metadata'] = [
                    {'id': idx, 'created_at': p['created_at']}
                    for idx, p in enumerate(self.data['passwords'], 1)
                ]
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
        except Exception as e:
            raise PasswordError(f"Error exporting data: {e}")

    def import_data(self, import_path: str) -> None:
        """Import data from a JSON file"""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            # Validate import data
            if 'version' not in import_data:
                raise PasswordError("Invalid import file format")
            
            # Merge notes
            self.data['notes'].update(import_data.get('notes', {}))
            
            # Import passwords if available
            if 'passwords' in import_data:
                existing_passwords = {p['password'] for p in self.data['passwords']}
                new_passwords = [
                    p for p in import_data['passwords']
                    if p['password'] not in existing_passwords
                ]
                self.data['passwords'].extend(new_passwords)
            
            self._save_data()
        except Exception as e:
            raise PasswordError(f"Error importing data: {e}")

    def add_custom_password(self, password: str, note: str = "", category: str = "", 
                          tags: List[str] = None, expiry_days: int = None, 
                          favorite: bool = False) -> None:
        """Add a custom password with metadata"""
        if not password:
            raise PasswordError("Password cannot be empty")
        
        timestamp = datetime.now().isoformat()
        password_id = len(self.data['passwords']) + 1
        
        # Check password strength
        checker = PasswordStrengthChecker()
        strength_info = checker.check_strength(password)
        
        password_entry = {
            'id': password_id,
            'password': password,
            'created_at': timestamp,
            'type': 'custom',
            'category': category,
            'tags': tags or [],
            'strength_score': strength_info['score']
        }
        
        self.data['passwords'].append(password_entry)
        if note:
            self.data['notes'][password] = note
            
        if category:
            if category not in self.data['categories']:
                self.data['categories'][category] = []
            self.data['categories'][category].append(password_id)
            
        if tags:
            for tag in tags:
                if tag not in self.data['tags']:
                    self.data['tags'][tag] = []
                self.data['tags'][tag].append(password_id)
                
        if favorite:
            self.data['favorites'].add(password_id)
            
        if expiry_days:
            expiry_date = datetime.now() + timedelta(days=expiry_days)
            self.data['expiry_dates'][password_id] = expiry_date.isoformat()
            
        # Update statistics
        self.data['statistics']['total_custom'] += 1
        self._update_statistics()
        
        self._save_data()

    def add_category(self, category: str, description: str = "") -> None:
        """Add a new password category"""
        if not category:
            raise PasswordError("Category name cannot be empty")
            
        if category not in self.data['categories']:
            self.data['categories'][category] = []
            self._save_data()

    def add_tags(self, password_id: int, tags: List[str]) -> None:
        """Add tags to a password"""
        if not self.data['passwords']:
            raise PasswordError("No passwords in history")
            
        if password_id < 1 or password_id > len(self.data['passwords']):
            raise PasswordError(f"Invalid password ID")
            
        for tag in tags:
            if tag not in self.data['tags']:
                self.data['tags'][tag] = []
            if password_id not in self.data['tags'][tag]:
                self.data['tags'][tag].append(password_id)
                
        self._save_data()

    def toggle_favorite(self, password_id: int) -> bool:
        """Toggle favorite status of a password"""
        if password_id in self.data['favorites']:
            self.data['favorites'].remove(password_id)
            is_favorite = False
        else:
            self.data['favorites'].add(password_id)
            is_favorite = True
            
        self._save_data()
        return is_favorite

    def set_expiry(self, password_id: int, days: int) -> None:
        """Set expiry date for a password"""
        if days < 0:
            raise PasswordError("Expiry days must be positive")
            
        expiry_date = datetime.now() + timedelta(days=days)
        self.data['expiry_dates'][password_id] = expiry_date.isoformat()
        self._save_data()

    def get_expired_passwords(self) -> List[Dict]:
        """Get list of expired passwords"""
        expired = []
        now = datetime.now()
        
        for password_id, expiry_date in self.data['expiry_dates'].items():
            if datetime.fromisoformat(expiry_date) < now:
                expired.append(self.data['passwords'][password_id - 1])
                
        return expired

    def get_password_statistics(self) -> Dict:
        """Get password statistics"""
        stats = self.data['statistics'].copy()
        stats.update({
            'total_passwords': len(self.data['passwords']),
            'total_categories': len(self.data['categories']),
            'total_tags': len(self.data['tags']),
            'total_favorites': len(self.data['favorites']),
            'expired_passwords': len(self.get_expired_passwords())
        })
        return stats

    def _update_statistics(self) -> None:
        """Update password statistics"""
        total_strength = sum(p['strength_score'] for p in self.data['passwords'])
        total_passwords = len(self.data['passwords'])
        
        self.data['statistics'].update({
            'avg_strength': total_strength / total_passwords if total_passwords > 0 else 0,
            'last_update': datetime.now().isoformat()
        })

    def advanced_search(self, query: str = "", category: str = "", tags: List[str] = None,
                       min_strength: float = None, max_strength: float = None,
                       created_after: str = None, created_before: str = None,
                       favorites_only: bool = False, expired_only: bool = False) -> List[Dict]:
        """Advanced search with multiple filters"""
        results = []
        
        for password in self.data['passwords']:
            # Apply filters
            if query and query.lower() not in password['password'].lower():
                continue
                
            if category and password.get('category') != category:
                continue
                
            if tags and not all(tag in password.get('tags', []) for tag in tags):
                continue
                
            if min_strength is not None and password['strength_score'] < min_strength:
                continue
                
            if max_strength is not None and password['strength_score'] > max_strength:
                continue
                
            if created_after:
                if datetime.fromisoformat(password['created_at']) < datetime.fromisoformat(created_after):
                    continue
                    
            if created_before:
                if datetime.fromisoformat(password['created_at']) > datetime.fromisoformat(created_before):
                    continue
                    
            if favorites_only and password['id'] not in self.data['favorites']:
                continue
                
            if expired_only:
                if password['id'] not in self.data['expiry_dates']:
                    continue
                if datetime.fromisoformat(self.data['expiry_dates'][password['id']]) > datetime.now():
                    continue
                    
            results.append(password)
            
        return results

    def bulk_delete(self, password_ids: List[int]) -> None:
        """Delete multiple passwords at once"""
        if not password_ids:
            raise PasswordError("No passwords specified for deletion")
            
        # Sort in reverse order to avoid index shifting
        for password_id in sorted(password_ids, reverse=True):
            self.delete_password_by_id(password_id)

    def bulk_tag(self, password_ids: List[int], tags: List[str]) -> None:
        """Add tags to multiple passwords"""
        if not password_ids or not tags:
            raise PasswordError("Both password IDs and tags must be specified")
            
        for password_id in password_ids:
            self.add_tags(password_id, tags)

    def import_from_csv(self, file_path: str) -> None:
        """Import passwords from CSV file"""
        try:
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.add_custom_password(
                        password=row['password'],
                        note=row.get('note', ''),
                        category=row.get('category', ''),
                        tags=row.get('tags', '').split(',') if row.get('tags') else None,
                        expiry_days=int(row['expiry_days']) if row.get('expiry_days') else None,
                        favorite=row.get('favorite', '').lower() == 'true'
                    )
        except Exception as e:
            raise PasswordError(f"Error importing from CSV: {e}")

class PasswordGenerator:
    """Class to generate secure passwords"""

    def __init__(self):
        self.uppercase = string.ascii_uppercase
        self.lowercase = string.ascii_lowercase
        self.digits = string.digits
        self.special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous = "1l0O"

    def generate(self, length: int = DEFAULT_PASSWORD_LENGTH,
                use_uppercase: bool = True,
                use_lowercase: bool = True,
                use_digits: bool = True,
                use_special: bool = True,
                exclude_ambiguous: bool = False,
                pronounceable: bool = False) -> str:
        """Generate a password based on specified criteria"""
        if length < MIN_PASSWORD_LENGTH:
            raise PasswordError(f"Password length must be at least {MIN_PASSWORD_LENGTH}")
        if length > MAX_PASSWORD_LENGTH:
            raise PasswordError(f"Password length must not exceed {MAX_PASSWORD_LENGTH}")

        if pronounceable:
            return self._generate_pronounceable(length)

        # Build character set
        charset = ""
        if use_uppercase:
            charset += self.uppercase
        if use_lowercase:
            charset += self.lowercase
        if use_digits:
            charset += self.digits
        if use_special:
            charset += self.special

        if exclude_ambiguous:
            charset = ''.join(c for c in charset if c not in self.ambiguous)

        if not charset:
            raise PasswordError("No character sets selected for password generation")

        # Ensure minimum requirements are met
        password = []
        if use_uppercase:
            password.append(secrets.choice(self.uppercase))
        if use_lowercase:
            password.append(secrets.choice(self.lowercase))
        if use_digits:
            password.append(secrets.choice(self.digits))
        if use_special:
            password.append(secrets.choice(self.special))

        # Fill remaining length with random characters
        remaining_length = length - len(password)
        if remaining_length < 0:
            raise PasswordError("Password length too short for required character types")
        
        password.extend(secrets.choice(charset) for _ in range(remaining_length))

        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)

    def _generate_pronounceable(self, length: int) -> str:
        """Generate a pronounceable password"""
        if length < 5:  # Minimum length for pronounceable passwords
            raise PasswordError("Pronounceable passwords must be at least 5 characters long")

        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        password = []
        
        # Generate base pronounceable part
        while len(password) < length - 2:  # Reserve space for numbers
            if len(password) % 2 == 0:
                password.append(secrets.choice(consonants))
            else:
                password.append(secrets.choice(vowels))

        # Add random numbers
        password.extend(str(secrets.randbelow(10)) for _ in range(2))

        # Capitalize first letter
        password[0] = password[0].upper()

        # Add a special character
        password.append(secrets.choice(self.special))

        return ''.join(password)

class PasswordStrengthChecker:
    """Class to evaluate password strength"""

    def __init__(self):
        self.common_passwords = self._load_common_passwords()

    def _load_common_passwords(self) -> set:
        """Load common passwords from a file"""
        # In a real implementation, load from a comprehensive file
        return {'password', 'admin', '123456', 'qwerty', 'letmein', 'monkey',
                'abc123', 'baseball', 'football', 'shadow', 'master', 'dragon'}

    def check_strength(self, password: str) -> Dict:
        """Evaluate password strength using multiple criteria"""
        if not password:
            raise PasswordError("Password cannot be empty")

        try:
            result = zxcvbn.zxcvbn(password)
        except Exception as e:
            raise PasswordError(f"Error checking password strength: {e}")
        
        # Calculate entropy
        charset_size = 0
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 32

        entropy = len(password) * (charset_size.bit_length() if charset_size else 0)

        # Prepare strength report
        strength_score = result['score']  # 0-4
        normalized_score = (strength_score / 4) * 100

        report = {
            'score': normalized_score,
            'entropy': entropy,
            'guesses': result['guesses'],
            'feedback': result['feedback'],
            'rating': self._get_rating(normalized_score),
            'warnings': [],
            'suggestions': result['feedback']['suggestions']
        }

        # Additional checks
        if password.lower() in self.common_passwords:
            report['warnings'].append("This is a commonly used password")
        if len(password) < MIN_PASSWORD_LENGTH:
            report['warnings'].append(f"Password should be at least {MIN_PASSWORD_LENGTH} characters long")
        if not any(c.isupper() for c in password):
            report['warnings'].append("Add uppercase letters")
        if not any(c.islower() for c in password):
            report['warnings'].append("Add lowercase letters")
        if not any(c.isdigit() for c in password):
            report['warnings'].append("Add numbers")
        if not any(not c.isalnum() for c in password):
            report['warnings'].append("Add special characters")

        return report

    def _get_rating(self, score: float) -> str:
        """Convert numerical score to text rating"""
        if score < 20:
            return "Very Weak"
        elif score < 40:
            return "Weak"
        elif score < 60:
            return "Medium"
        elif score < 80:
            return "Strong"
        return "Very Strong"

def create_backup(file_path: Path) -> None:
    """Create a backup of the password file"""
    if file_path.exists():
        backup_path = file_path.with_suffix(BACKUP_EXTENSION)
        file_path.rename(backup_path)

def restore_backup(file_path: Path) -> None:
    """Restore from backup if main file is corrupted"""
    backup_path = file_path.with_suffix(BACKUP_EXTENSION)
    if backup_path.exists():
        backup_path.rename(file_path)

class PasswordManager:
    """Main class for password management operations"""
    
    def __init__(self):
        self.ui = UIHelper()
        self.generator = PasswordGenerator()
        self.checker = PasswordStrengthChecker()
        self.data_manager = None
        self._master_password = None  # Store master password temporarily

    def initialize_data_manager(self, master_password: Optional[str] = None) -> None:
        """Initialize the data manager with master password"""
        try:
            # Use stored master password if available
            if self._master_password:
                master_password = self._master_password
            
            # Get master password if not provided
            if not master_password:
                master_password = getpass("Enter master password: ")
                
            if not master_password:
                raise PasswordError("Master password cannot be empty")
                
            # Store master password for reuse in the same session
            self._master_password = master_password
            self.data_manager = PasswordData(master_password)
        except Exception as e:
            raise PasswordError(f"Error initializing data manager: {str(e)}")

    def generate_passwords(self, args: argparse.Namespace) -> None:
        """Generate passwords based on provided arguments"""
        try:
            # Initialize data manager once if note is required
            if args.note and self.data_manager is None:
                self.initialize_data_manager()

            generated_passwords = []
            for i in range(args.generate):
                try:
                    password = self.generator.generate(
                        length=args.length,
                        use_uppercase=args.uppercase,
                        use_digits=args.digits,
                        use_special=bool(args.characters),
                        exclude_ambiguous=args.ambiguous,
                        pronounceable=args.pronounceable
                    )
                    generated_passwords.append(password)
                    self.ui.print_success(f"\nGenerated password {i+1}: {password}")
                    pyperclip.copy(password)
                    self.ui.print_info("Password copied to clipboard!")

                except Exception as e:
                    self.ui.print_error(f"Error generating password {i+1}: {e}")
                    continue

            # Save all passwords at once if note is provided
            if args.note and generated_passwords:
                try:
                    for password in generated_passwords:
                        self.data_manager.add_password(password, args.note)
                    self.ui.print_success("All passwords and notes saved securely")
                except Exception as e:
                    self.ui.print_error(f"Error saving passwords: {e}")

        except Exception as e:
            self.ui.print_error(f"Error in password generation: {e}")

    def view_passwords(self, show_all: bool = False) -> None:
        """View stored passwords"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
            
            history = self.data_manager.get_history()
            if not history:
                self.ui.print_info("No password history found")
                return
            
            limit = None if show_all else DEFAULT_DISPLAY_LIMIT
            self.ui.display_password_table(
                history,
                self.data_manager.data['notes'],
                limit=limit,
                show_all=show_all
            )
        except Exception as e:
            self.ui.print_error(f"Error viewing passwords: {e}")

    def check_password_strength(self, password: str) -> None:
        """Check and display password strength"""
        try:
            report = self.checker.check_strength(password)
            self.ui.display_strength_report(report)
        except Exception as e:
            self.ui.print_error(f"Error checking password strength: {e}")

    def delete_password(self, password_id: int) -> None:
        """Delete a password by ID"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
            
            # Get password info before deletion for confirmation
            password = self.data_manager.get_password_by_id(password_id)
            
            # Confirm deletion
            confirm = self.ui.confirm_action(
                f"⚠️  Are you sure you want to delete password {password_id}? This action cannot be undone.",
                default=False
            )
            
            if confirm:
                self.data_manager.delete_password_by_id(password_id)
                self.ui.print_success(f"🗑️ Password {password_id} deleted successfully")
            else:
                self.ui.print_info("ℹ️ Operation cancelled")
        except Exception as e:
            self.ui.print_error(f"Error deleting password: {e}")

    def edit_note(self, password_id: int, new_note: str) -> None:
        """Edit note for a password"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
            
            self.data_manager.edit_note_by_id(password_id, new_note)
            self.ui.print_success(f"📝 Note updated for password {password_id}")
        except Exception as e:
            self.ui.print_error(f"Error editing note: {e}")

    def copy_password(self, password_id: int) -> None:
        """Copy a password to clipboard"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
            
            password = self.data_manager.get_password_by_id(password_id)
            pyperclip.copy(password)
            self.ui.print_success(f"📋 Password {password_id} copied to clipboard")
        except Exception as e:
            self.ui.print_error(f"Error copying password: {e}")

    def search_passwords(self, query: str) -> None:
        """Search passwords and notes"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
            
            results = self.data_manager.search_passwords(query)
            
            if not results:
                self.ui.print_info("🔍 No matching passwords found")
                return
            
            self.ui.print_success(f"🔍 Found {len(results)} matching passwords:")
            self.ui.display_password_table(results, self.data_manager.data['notes'])
        except Exception as e:
            self.ui.print_error(f"Error searching passwords: {e}")

    def export_data(self, export_path: str, include_passwords: bool = False) -> None:
        """Export data to file"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
            
            self.data_manager.export_data(export_path, include_passwords)
            self.ui.print_success(f"📤 Data exported successfully to {export_path}")
        except Exception as e:
            self.ui.print_error(f"Error exporting data: {e}")

    def import_data(self, import_path: str) -> None:
        """Import data from file"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
            
            self.data_manager.import_data(import_path)
            self.ui.print_success("📥 Data imported successfully")
        except Exception as e:
            self.ui.print_error(f"Error importing data: {e}")

    def add_custom_password(self, password: str, note: str = "", category: str = "",
                          tags: List[str] = None, expiry_days: int = None,
                          favorite: bool = False) -> None:
        """Add a custom password with metadata"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
                
            self.data_manager.add_custom_password(
                password=password,
                note=note,
                category=category,
                tags=tags,
                expiry_days=expiry_days,
                favorite=favorite
            )
            self.ui.print_success("🔐 Custom password added successfully")
        except Exception as e:
            self.ui.print_error(f"Error adding custom password: {e}")

    def add_category(self, category: str, description: str = "") -> None:
        """Add a new password category"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
                
            self.data_manager.add_category(category, description)
            self.ui.print_success(f"📁 Category '{category}' added successfully")
        except Exception as e:
            self.ui.print_error(f"Error adding category: {e}")

    def toggle_favorite(self, password_id: int) -> None:
        """Toggle favorite status of a password"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
                
            is_favorite = self.data_manager.toggle_favorite(password_id)
            status = "added to" if is_favorite else "removed from"
            self.ui.print_success(f"⭐ Password {password_id} {status} favorites")
        except Exception as e:
            self.ui.print_error(f"Error toggling favorite: {e}")

    def set_expiry(self, password_id: int, days: int) -> None:
        """Set expiry date for a password"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
                
            self.data_manager.set_expiry(password_id, days)
            self.ui.print_success(f"⏰ Expiry set for password {password_id}")
        except Exception as e:
            self.ui.print_error(f"Error setting expiry: {e}")

    def show_statistics(self) -> None:
        """Display password statistics"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
                
            stats = self.data_manager.get_password_statistics()
            
            table = Table(
                show_header=True,
                header_style="bold magenta",
                box=box.ROUNDED,
                title="📊 Password Statistics",
                title_style="bold cyan"
            )
            
            table.add_column("Metric", style="bold")
            table.add_column("Value")
            
            for key, value in stats.items():
                if key == 'last_update' and value:
                    value = datetime.fromisoformat(value).strftime('%Y-%m-%d %H:%M:%S')
                table.add_row(key.replace('_', ' ').title(), str(value))
                
            self.ui.console.print(table)
        except Exception as e:
            self.ui.print_error(f"Error showing statistics: {e}")

    def advanced_search(self, args: argparse.Namespace) -> None:
        """Perform advanced search"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
                
            results = self.data_manager.advanced_search(
                query=args.search,
                category=args.category,
                tags=args.tags.split(',') if args.tags else None,
                min_strength=args.min_strength,
                max_strength=args.max_strength,
                created_after=args.created_after,
                created_before=args.created_before,
                favorites_only=args.favorites_only,
                expired_only=args.expired_only
            )
            
            if not results:
                self.ui.print_info("🔍 No matching passwords found")
                return
                
            self.ui.print_success(f"🔍 Found {len(results)} matching passwords:")
            self.ui.display_password_table(results, self.data_manager.data['notes'])
        except Exception as e:
            self.ui.print_error(f"Error performing advanced search: {e}")

    def bulk_operations(self, args: argparse.Namespace) -> None:
        """Perform bulk operations"""
        try:
            if self.data_manager is None:
                self.initialize_data_manager()
                
            if args.bulk_delete:
                password_ids = [int(pid) for pid in args.bulk_delete.split(',')]
                confirm = self.ui.confirm_action(
                    f"⚠️  Are you sure you want to delete {len(password_ids)} passwords? This action cannot be undone.",
                    default=False
                )
                if confirm:
                    self.data_manager.bulk_delete(password_ids)
                    self.ui.print_success(f"🗑️ {len(password_ids)} passwords deleted successfully")
                else:
                    self.ui.print_info("ℹ️ Operation cancelled")
                    
            elif args.bulk_tag and args.tags:
                password_ids = [int(pid) for pid in args.bulk_tag.split(',')]
                tags = args.tags.split(',')
                self.data_manager.bulk_tag(password_ids, tags)
                self.ui.print_success(f"🏷️ Tags added to {len(password_ids)} passwords")
        except Exception as e:
            self.ui.print_error(f"Error performing bulk operation: {e}")

# Error Messages
ERROR_MESSAGES = {
    ErrorCodes.INVALID_INPUT: "Invalid input provided: {}",
    ErrorCodes.FILE_ERROR: "File operation error: {}",
    ErrorCodes.ENCRYPTION_ERROR: "Encryption error: {}",
    ErrorCodes.DECRYPTION_ERROR: "Decryption error: {}",
    ErrorCodes.PERMISSION_ERROR: "Permission denied: {}",
    ErrorCodes.CONFIGURATION_ERROR: "Configuration error: {}",
    ErrorCodes.VALIDATION_ERROR: "Validation error: {}",
    ErrorCodes.RUNTIME_ERROR: "Runtime error: {}",
    ErrorCodes.UNKNOWN_ERROR: "Unknown error occurred: {}"
}

def handle_error(error: Exception, show_welcome: bool = False) -> None:
    """Centralized error handling function"""
    if not show_welcome:
        print("\n" + "="*80)  # Add some spacing for better readability
    
    ui = UIHelper()
    error_code = ErrorCodes.UNKNOWN_ERROR
    error_msg = str(error)

    if isinstance(error, ValidationError):
        error_code = error.error_code
    elif isinstance(error, ConfigurationError):
        error_code = error.error_code
    elif isinstance(error, EncryptionError):
        error_code = error.error_code
    elif isinstance(error, PasswordError):
        error_code = ErrorCodes.VALIDATION_ERROR
    elif isinstance(error, (FileNotFoundError, PermissionError)):
        error_code = ErrorCodes.FILE_ERROR
    elif isinstance(error, json.JSONDecodeError):
        error_code = ErrorCodes.FILE_ERROR
        error_msg = "Invalid data file format"
    elif isinstance(error, ValueError):
        error_code = ErrorCodes.INVALID_INPUT
    
    formatted_msg = ERROR_MESSAGES[error_code].format(error_msg)
    ui.print_error(formatted_msg, error_code)
    
    # Add helpful suggestions based on error type
    if error_code == ErrorCodes.FILE_ERROR:
        ui.print_info("💡 Try using --restore to restore from backup")
    elif error_code == ErrorCodes.VALIDATION_ERROR and "master password" in str(error).lower():
        ui.print_info("💡 Use -m to create a new master password")
    elif error_code == ErrorCodes.ENCRYPTION_ERROR:
        ui.print_info("💡 Make sure you're using the correct master password")
    
    sys.exit(error_code.value)

def main():
    """Enhanced main function with better UI"""
    try:
        manager = PasswordManager()
        
        # Only show welcome message for help or no arguments
        show_welcome = len(sys.argv) <= 1 or any(arg in ['--help', '-h'] for arg in sys.argv)
        if show_welcome:
            manager.ui.display_welcome()

        parser = argparse.ArgumentParser(
            description=f"{APP_NAME} v{APP_VERSION} - Advanced Password Generator and Manager",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""
Examples:
  Generate a password:
    %(prog)s -g -l 20
  
  Generate multiple passwords:
    %(prog)s -g 5 -l 16 -n "My note"  # All passwords will have the same note
  
  Generate pronounceable password:
    %(prog)s -g -p
  
  Check password strength:
    %(prog)s --check "YourPassword123!"
  
  View password history:
    %(prog)s -vn
  
  Add password with note:
    %(prog)s -g -n "My important password"

For more information and updates, visit: {APP_GITHUB}
"""
        )
        
        # Fix duplicate arguments
        parser.add_argument("-l", "--length", type=int, default=DEFAULT_PASSWORD_LENGTH,
                          help=f"Password length (default: {DEFAULT_PASSWORD_LENGTH}, min: {MIN_PASSWORD_LENGTH})")
        parser.add_argument("-g", "--generate", nargs="?", const=1, type=int,
                          help="Generate password(s) (specify number or omit for one)")
        parser.add_argument("-u", "--uppercase", action="store_true", default=True,
                          help="Include uppercase letters (default: True)")
        parser.add_argument("-c", "--characters", type=str,
                          help="Custom special characters to use")
        parser.add_argument("-d", "--digits", action="store_true", default=True,
                          help="Include digits (default: True)")
        parser.add_argument("-a", "--ambiguous", action="store_true",
                          help="Exclude ambiguous characters")
        parser.add_argument("-p", "--pronounceable", action="store_true",
                          help="Generate pronounceable password")
        parser.add_argument("--check", type=str,
                          help="Check password strength")
        parser.add_argument("--history", action="store_true",
                          help="View password history")
        parser.add_argument("--clear-history", action="store_true",
                          help="Clear password history")
        parser.add_argument("-n", "--note", type=str,
                          help="Add note to generated password")
        parser.add_argument("-vn", "--view-notes", action="store_true",
                          help=f"View passwords and notes (limited to {DEFAULT_DISPLAY_LIMIT} entries)")
        parser.add_argument("-vna", "--view-notes-all", action="store_true",
                          help="View all passwords and notes")
        parser.add_argument("-m", "--master-password", type=str,
                          help="Create a new master password")
        parser.add_argument("--reset-master", type=str,
                          help="Reset master password (WARNING: this will delete all stored data)")
        parser.add_argument("--backup", action="store_true",
                          help="Create a backup of the password file")
        parser.add_argument("--restore", action="store_true",
                          help="Restore from backup")
        parser.add_argument("--delete", type=int,
                          help="Delete password by ID")
        parser.add_argument("--edit-note", type=int,
                          help="Edit note for password by ID")
        parser.add_argument("--note-text", type=str,
                          help="New note text for --edit-note")
        parser.add_argument("--copy", type=int,
                          help="Copy password by ID to clipboard")
        parser.add_argument("--search", type=str,
                          help="Search passwords and notes")
        parser.add_argument("--export", type=str,
                          help="Export data to file")
        parser.add_argument("--export-passwords", action="store_true",
                          help="Include passwords in export (use with caution)")
        parser.add_argument("--import", type=str, dest="import_file",
                          help="Import data from file")
        parser.add_argument("--add-custom", type=str,
                          help="Add custom password")
        parser.add_argument("--category", type=str,
                          help="Specify category for password")
        parser.add_argument("--tags", type=str,
                          help="Comma-separated tags")
        parser.add_argument("--expiry", type=int,
                          help="Set password expiry in days")
        parser.add_argument("--favorite", action="store_true",
                          help="Mark password as favorite")
        parser.add_argument("--toggle-favorite", type=int,
                          help="Toggle favorite status for password ID")
        parser.add_argument("--min-strength", type=float,
                          help="Minimum password strength for search")
        parser.add_argument("--max-strength", type=float,
                          help="Maximum password strength for search")
        parser.add_argument("--created-after", type=str,
                          help="Search passwords created after date (YYYY-MM-DD)")
        parser.add_argument("--created-before", type=str,
                          help="Search passwords created before date (YYYY-MM-DD)")
        parser.add_argument("--favorites-only", action="store_true",
                          help="Show only favorite passwords")
        parser.add_argument("--expired-only", action="store_true",
                          help="Show only expired passwords")
        parser.add_argument("--bulk-delete", type=str,
                          help="Comma-separated password IDs to delete")
        parser.add_argument("--bulk-tag", type=str,
                          help="Comma-separated password IDs to tag")
        parser.add_argument("--stats", action="store_true",
                          help="Show password statistics")
        parser.add_argument("--import-csv", type=str,
                          help="Import passwords from CSV file")

        args = parser.parse_args()

        # Handle backup operations
        if args.backup:
            create_backup(Path(DATA_FILE))
            manager.ui.print_success("💾 Backup created successfully")
            return
            
        if args.restore:
            restore_backup(Path(DATA_FILE))
            manager.ui.print_success("📥 Backup restored successfully")
            return

        # Handle master password operations
        if args.master_password:
            try:
                PasswordData.create_master_password(args.master_password)
                manager.ui.print_success("🔑 Master password created successfully!")
                return
            except Exception as e:
                manager.ui.print_error(f"❌ Error creating master password: {e}")
                sys.exit(1)

        # Handle password generation
        if args.generate:
            manager.generate_passwords(args)
            return

        # Handle password strength check
        if args.check:
            manager.check_password_strength(args.check)
            return

        # Handle view operations
        if args.view_notes or args.view_notes_all:
            manager.view_passwords(show_all=args.view_notes_all)
            return

        # Handle clear history
        if args.clear_history:
            confirm = manager.ui.confirm_action(
                "⚠️  Are you sure you want to clear all history? This action cannot be undone.",
                default=False
            )
            if confirm:
                manager.data_manager.clear_history()
                manager.ui.print_success("🗑️ History cleared successfully")
            else:
                manager.ui.print_info("ℹ️ Operation cancelled")
            return

        # Handle delete operation
        if args.delete:
            manager.delete_password(args.delete)
            return

        # Handle edit note operation
        if args.edit_note:
            if not args.note_text:
                args.note_text = manager.ui.get_secure_input("Enter new note: ", password=False)
            manager.edit_note(args.edit_note, args.note_text)
            return

        # Handle copy operation
        if args.copy:
            manager.copy_password(args.copy)
            return

        # Handle search operation
        if args.search:
            manager.search_passwords(args.search)
            return

        # Handle export operation
        if args.export:
            manager.export_data(args.export, args.export_passwords)
            return

        # Handle import operations
        if args.import_file:
            manager.import_data(args.import_file)
            return

        if args.import_csv:
            manager.import_from_csv(args.import_csv)
            return

        # Handle custom password addition
        if args.add_custom:
            manager.add_custom_password(
                password=args.add_custom,
                note=args.note,
                category=args.category,
                tags=args.tags.split(',') if args.tags else None,
                expiry_days=args.expiry,
                favorite=args.favorite
            )
            return

        # Handle favorite toggle
        if args.toggle_favorite:
            manager.toggle_favorite(args.toggle_favorite)
            return

        # Handle statistics display
        if args.stats:
            manager.show_statistics()
            return

        # Handle advanced search
        if args.category or args.tags or args.min_strength or \
           args.max_strength or args.created_after or args.created_before or \
           args.favorites_only or args.expired_only:
            manager.advanced_search(args)
            return

        # Handle bulk operations
        if args.bulk_delete or (args.bulk_tag and args.tags):
            manager.bulk_operations(args)
            return

        # If no arguments provided, show help
        if len(sys.argv) == 1:
            parser.print_help()
            return

    except Exception as e:
        handle_error(e, show_welcome)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Critical error: {str(e)}")
        sys.exit(1) 