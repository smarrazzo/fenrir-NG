# coding=utf-8
"""
Module de logging structuré pour FENRIR.

Ce module fournit un système de logging avancé avec :
- Support des niveaux de verbosité (0-3)
- Logging structuré avec métadonnées
- Handlers pour console (avec couleurs) et fichiers
- Format JSON optionnel pour l'analyse
- Compatibilité avec l'API existante de FenrirTail
"""

import logging
import sys
import json
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path


class ColoredFormatter(logging.Formatter):
    """Formatter avec support des couleurs ANSI pour la console."""
    
    # Codes de couleur ANSI
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Vert
        'WARNING': '\033[33m',    # Jaune
        'ERROR': '\033[31m',      # Rouge
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
    }
    
    def format(self, record):
        """Formate le message avec des couleurs."""
        # Ajouter la couleur selon le niveau
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        
        # Formater le message
        formatted = super().format(record)
        
        # Réinitialiser les couleurs à la fin
        return formatted


class StructuredFormatter(logging.Formatter):
    """Formatter pour le logging structuré (JSON)."""
    
    def format(self, record):
        """Formate le message en JSON structuré."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Ajouter les métadonnées supplémentaires si présentes
        if hasattr(record, 'metadata') and record.metadata:
            log_data['metadata'] = record.metadata
        
        # Ajouter l'exception si présente
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, ensure_ascii=False)


class FenrirLogger:
    """
    Logger principal pour FENRIR avec support de la verbosité.
    
    Niveaux de verbosité :
    - 0 : CRITICAL seulement
    - 1 : ERROR, WARNING, INFO (normal)
    - 2 : + DEBUG (information light)
    - 3 : + TRACE (verbose, tous les détails)
    """
    
    # Mapping verbosité -> niveau logging
    VERBOSITY_TO_LEVEL = {
        0: logging.CRITICAL,
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.DEBUG,  # TRACE sera géré différemment
    }
    
    def __init__(self, name: str = 'FENRIR', verbosity: int = 1, 
                 log_file: Optional[str] = None, 
                 json_log_file: Optional[str] = None):
        """
        Initialise le logger.
        
        Args:
            name: Nom du logger
            verbosity: Niveau de verbosité (0-3)
            log_file: Chemin vers le fichier de log texte (optionnel)
            json_log_file: Chemin vers le fichier de log JSON (optionnel)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # Accepter tous les niveaux
        self.verbosity = verbosity
        self.name = name
        
        # Éviter les handlers dupliqués
        if self.logger.handlers:
            return
        
        # Handler pour la console avec couleurs
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.VERBOSITY_TO_LEVEL.get(verbosity, logging.INFO))
        
        # Format pour la console
        if verbosity >= 2:
            console_format = '%(asctime)s [%(levelname)s] [%(name)s] %(message)s'
        else:
            console_format = '[%(levelname)s] %(message)s'
        
        console_formatter = ColoredFormatter(console_format, datefmt='%H:%M:%S')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Handler pour fichier texte
        if log_file:
            file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] [%(name)s] [%(module)s:%(funcName)s:%(lineno)d] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        
        # Handler pour fichier JSON (logging structuré)
        if json_log_file:
            json_handler = logging.FileHandler(json_log_file, mode='a', encoding='utf-8')
            json_handler.setLevel(logging.DEBUG)
            json_formatter = StructuredFormatter()
            json_handler.setFormatter(json_formatter)
            self.logger.addHandler(json_handler)
    
    def set_verbosity(self, verbosity: int):
        """Change le niveau de verbosité."""
        if verbosity < 0 or verbosity > 3:
            raise ValueError(f"Verbosity must be between 0 and 3, got {verbosity}")
        
        self.verbosity = verbosity
        level = self.VERBOSITY_TO_LEVEL.get(verbosity, logging.INFO)
        
        # Mettre à jour le niveau des handlers console
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stdout:
                handler.setLevel(level)
    
    def _should_log(self, verbosity_level: int) -> bool:
        """Vérifie si on doit logger selon le niveau de verbosité."""
        return self.verbosity >= verbosity_level
    
    def info(self, message: str, verbosity_level: int = 1, **kwargs):
        """Log un message d'information."""
        if self._should_log(verbosity_level):
            extra = {'metadata': kwargs} if kwargs else {}
            self.logger.info(message, extra=extra)
    
    def debug(self, message: str, verbosity_level: int = 2, **kwargs):
        """Log un message de debug."""
        if self._should_log(verbosity_level):
            extra = {'metadata': kwargs} if kwargs else {}
            self.logger.debug(message, extra=extra)
    
    def trace(self, message: str, **kwargs):
        """Log un message de trace (verbosité maximale)."""
        if self.verbosity >= 3:
            extra = {'metadata': kwargs} if kwargs else {}
            self.logger.debug(f"[TRACE] {message}", extra=extra)
    
    def warning(self, message: str, verbosity_level: int = 1, **kwargs):
        """Log un avertissement."""
        if self._should_log(verbosity_level):
            extra = {'metadata': kwargs} if kwargs else {}
            self.logger.warning(message, extra=extra)
    
    def error(self, message: str, exc_info: bool = False, **kwargs):
        """Log une erreur."""
        extra = {'metadata': kwargs} if kwargs else {}
        self.logger.error(message, exc_info=exc_info, extra=extra)
    
    def critical(self, message: str, exc_info: bool = False, **kwargs):
        """Log une erreur critique."""
        extra = {'metadata': kwargs} if kwargs else {}
        self.logger.critical(message, exc_info=exc_info, extra=extra)
    
    def success(self, message: str, verbosity_level: int = 1, **kwargs):
        """Log un message de succès (alias pour info avec formatage spécial)."""
        if self._should_log(verbosity_level):
            formatted_msg = f"\033[32m[*]\033[0m {message}"
            extra = {'metadata': kwargs} if kwargs else {}
            self.logger.info(formatted_msg, extra=extra)
    
    def packet_info(self, packet_number: int, **kwargs):
        """Log des informations sur un paquet traité."""
        if self.verbosity >= 2:
            message = f"Processing packet number {packet_number}"
            extra = {'metadata': {'packet_number': packet_number, **kwargs}}
            self.logger.debug(message, extra=extra)
    
    def packet_counter(self, packet_number: int):
        """Affiche un compteur de paquets (pour affichage en ligne)."""
        if self.verbosity >= 2:
            sys.stdout.write(f"\r\033[1m\033[32m[RAWR]\033[0m Processing packet number\033[1m \033[31m{packet_number}\033[0m")
            sys.stdout.flush()


# Instance globale du logger
_logger_instance: Optional[FenrirLogger] = None


def get_logger(name: str = 'FENRIR', verbosity: int = 1, 
               log_file: Optional[str] = None,
               json_log_file: Optional[str] = None) -> FenrirLogger:
    """
    Obtient ou crée une instance du logger.
    
    Args:
        name: Nom du logger
        verbosity: Niveau de verbosité (0-3)
        log_file: Chemin vers le fichier de log texte
        json_log_file: Chemin vers le fichier de log JSON
        
    Returns:
        Instance de FenrirLogger
    """
    global _logger_instance
    
    if _logger_instance is None:
        _logger_instance = FenrirLogger(name, verbosity, log_file, json_log_file)
    else:
        _logger_instance.set_verbosity(verbosity)
    
    return _logger_instance


def setup_logging(verbosity: int = 1, log_dir: Optional[str] = None) -> FenrirLogger:
    """
    Configure le système de logging pour FENRIR.
    
    Args:
        verbosity: Niveau de verbosité (0-3)
        log_dir: Répertoire pour les fichiers de log (optionnel)
        
    Returns:
        Instance du logger configuré
    """
    log_file = None
    json_log_file = None
    
    if log_dir:
        log_dir_path = Path(log_dir)
        log_dir_path.mkdir(parents=True, exist_ok=True)
        log_file = str(log_dir_path / 'fenrir.log')
        json_log_file = str(log_dir_path / 'fenrir.json')
    
    return get_logger('FENRIR', verbosity, log_file, json_log_file)

