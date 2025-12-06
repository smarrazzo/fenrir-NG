# coding=utf-8
"""
Module d'exceptions personnalisées pour FENRIR.

Ce module définit toutes les exceptions spécifiques à FENRIR
pour une meilleure gestion et traçabilité des erreurs.
"""


class FenrirError(Exception):
    """
    Classe de base pour toutes les exceptions FENRIR.
    
    Args:
        message: Message d'erreur descriptif
        details: Dictionnaire avec des détails supplémentaires (optionnel)
    """
    
    def __init__(self, message: str, details: dict = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}
    
    def __str__(self):
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} ({details_str})"
        return self.message


class FenrirSocketError(FenrirError):
    """Exception levée lors d'erreurs de socket."""
    pass


class FenrirNetworkError(FenrirError):
    """Exception levée lors d'erreurs réseau."""
    pass


class FenrirTAPError(FenrirError):
    """Exception levée lors d'erreurs avec l'interface TAP."""
    pass


class FenrirPacketError(FenrirError):
    """Exception levée lors d'erreurs de traitement de paquets."""
    pass


class FenrirMangleError(FenrirError):
    """Exception levée lors d'erreurs de mangle (transformation de paquets)."""
    pass


class FenrirThreadError(FenrirError):
    """Exception levée lors d'erreurs avec les threads de paquets."""
    pass


class FenrirInterfaceError(FenrirError):
    """Exception levée lors d'erreurs avec les interfaces réseau."""
    pass


class FenrirAutoconfError(FenrirError):
    """Exception levée lors d'erreurs d'auto-configuration."""
    pass


class FenrirConfigurationError(FenrirError):
    """Exception levée lors d'erreurs de configuration."""
    pass


class FenrirValidationError(FenrirError):
    """Exception levée lors d'erreurs de validation."""
    pass

