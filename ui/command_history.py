import os
import json
from typing import List, Optional
from pathlib import Path
from config import Config


class CommandHistory:
    
    def __init__(self, max_size: int = 100, history_file: Optional[str] = None):
        self.max_size = max_size
        self.history_file = history_file or os.path.join(os.path.expanduser("~"), ".evil_lock_history.json")
        self._history: List[str] = []
        self._load_from_file()
    
    def add_command(self, command: str) -> None:
        if not command or not command.strip():
            return
        
        if command in self._history:
            self._history.remove(command)
        
        self._history.insert(0, command.strip())
        
        if len(self._history) > self.max_size:
            self._history = self._history[:self.max_size]
        
        self._save_to_file()
    
    def get_history(self, limit: Optional[int] = None) -> List[str]:
        if limit is None:
            return self._history.copy()
        return self._history[:limit]
    
    def clear_history(self) -> None:
        self._history = []
        self._save_to_file()
    
    def _save_to_file(self) -> None:
        try:
            history_dir = os.path.dirname(self.history_file)
            if history_dir and not os.path.exists(history_dir):
                os.makedirs(history_dir, exist_ok=True)
            
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self._history, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    
    def _load_from_file(self) -> None:
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self._history = json.load(f)
                    if not isinstance(self._history, list):
                        self._history = []
                    if len(self._history) > self.max_size:
                        self._history = self._history[:self.max_size]
        except Exception:
            self._history = []
    
    def save_to_file(self, file_path: str) -> bool:
        try:
            history_dir = os.path.dirname(file_path)
            if history_dir and not os.path.exists(history_dir):
                os.makedirs(history_dir, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self._history, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False
    
    def load_from_file(self, file_path: str) -> bool:
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    if isinstance(loaded, list):
                        self._history = loaded
                        if len(self._history) > self.max_size:
                            self._history = self._history[:self.max_size]
                        return True
        except Exception:
            pass
        return False


command_history = CommandHistory()
