# Guide du système de logging structuré FENRIR

## 📋 Vue d'ensemble

Le système de logging structuré de FENRIR remplace les `print()` par un système de logging professionnel avec :
- ✅ Support des niveaux de verbosité (0-3)
- ✅ Logging structuré avec métadonnées
- ✅ Handlers pour console (avec couleurs) et fichiers
- ✅ Format JSON optionnel pour l'analyse
- ✅ Compatibilité avec l'API existante de FenrirTail

## 🎯 Niveaux de verbosité

| Niveau | Description | Niveau logging Python |
|--------|-------------|----------------------|
| 0 | Aucun message | CRITICAL seulement |
| 1 | Normal (erreurs, warnings, infos) | INFO |
| 2 | Information détaillée | DEBUG |
| 3 | Très verbeux (tous les détails) | DEBUG + TRACE |

## 📝 Utilisation

### Import du logger

```python
from logger import get_logger

# Créer un logger pour votre module
logger = get_logger('FENRIR.ModuleName', verbosity=1)
```

### Méthodes de logging

#### Messages d'information
```python
logger.info("Message d'information", verbosity_level=1)
logger.success("Opération réussie", verbosity_level=1)
```

#### Messages de debug
```python
logger.debug("Message de debug", verbosity_level=2)
logger.trace("Message très détaillé", verbosity_level=3)
```

#### Messages d'erreur
```python
logger.warning("Avertissement", verbosity_level=1)
logger.error("Erreur", exc_info=True)  # exc_info=True pour stack trace
logger.critical("Erreur critique", exc_info=True)
```

### Logging avec métadonnées structurées

```python
# Ajouter des métadonnées pour le logging structuré
logger.info("Paquet traité", 
            packet_type="TCP",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=443)
```

Ces métadonnées seront incluses dans les logs JSON pour faciliter l'analyse.

## 🔧 Configuration

### Configuration basique

```python
from logger import setup_logging

# Configuration avec répertoire de logs
logger = setup_logging(verbosity=2, log_dir='./logs')
```

### Configuration avancée

```python
from logger import get_logger

# Logger avec fichiers de log personnalisés
logger = get_logger(
    name='FENRIR.Custom',
    verbosity=2,
    log_file='./logs/fenrir.log',      # Log texte
    json_log_file='./logs/fenrir.json'  # Log JSON structuré
)
```

## 📂 Fichiers de log générés

### `fenrir.log` (format texte)
```
2024-01-15 10:30:45 [INFO] [FENRIR.Core] [FENRIR2.py:createTap:46] Creating TAP interface
2024-01-15 10:30:46 [DEBUG] [FENRIR.MANGLE] [MANGLE.py:Fenrir_Address_Translation:45] Processing packet
```

### `fenrir.json` (format JSON structuré)
```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "level": "INFO",
  "logger": "FENRIR.Core",
  "message": "Paquet traité",
  "module": "FENRIR2",
  "function": "process_packet",
  "line": 150,
  "metadata": {
    "packet_type": "TCP",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2"
  }
}
```

### `FENRIR.err` (exceptions de mangle)
Fichier texte pour les exceptions de mangle (compatibilité avec l'ancien système).

## 🎨 Couleurs dans la console

Le système utilise des couleurs ANSI pour améliorer la lisibilité :
- 🟢 **Vert** : Messages de succès (INFO)
- 🟡 **Jaune** : Avertissements (WARNING)
- 🔴 **Rouge** : Erreurs (ERROR)
- 🔵 **Cyan** : Debug (DEBUG)
- 🟣 **Magenta** : Critique (CRITICAL)

## 🔄 Migration depuis l'ancien système

### Avant (FenrirTail)
```python
self.FenrirTail.notify("Message", 1)
self.FenrirTail.notifyGood("Succès", 1)
self.FenrirTail.notifyWarn("Avertissement", 1)
self.FenrirTail.notifyBad("Erreur", 1)
```

### Après (Logger structuré)
```python
logger.info("Message", verbosity_level=1)
logger.success("Succès", verbosity_level=1)
logger.warning("Avertissement", verbosity_level=1)
logger.error("Erreur")
```

**Note** : L'ancien système FenrirTail reste compatible et utilise maintenant le logger en interne.

## 📊 Exemples d'utilisation

### Exemple 1 : Logging simple
```python
from logger import get_logger

logger = get_logger('FENRIR.Example', verbosity=1)
logger.info("Démarrage du module")
logger.success("Module initialisé avec succès")
```

### Exemple 2 : Logging avec métadonnées
```python
logger.debug("Paquet TCP reçu",
             verbosity_level=2,
             src_ip=pkt[IP].src,
             dst_ip=pkt[IP].dst,
             src_port=pkt[TCP].sport,
             dst_port=pkt[TCP].dport,
             seq=pkt[TCP].seq)
```

### Exemple 3 : Logging d'exceptions
```python
try:
    # Code qui peut échouer
    process_packet(pkt)
except Exception as e:
    logger.error("Erreur lors du traitement du paquet",
                 exc_info=True,
                 packet_type="TCP",
                 src_ip=pkt[IP].src)
```

### Exemple 4 : Compteur de paquets
```python
# Affiche un compteur en ligne (comme l'ancien packetCounter)
logger.packet_counter(packet_number)
```

## 🛠️ Bonnes pratiques

1. **Utiliser des métadonnées pertinentes** : Ajoutez des informations utiles pour le debugging
   ```python
   logger.info("Paquet traité", 
               packet_type="TCP",
               action="forwarded",
               interface="eth0")
   ```

2. **Choisir le bon niveau de verbosité** :
   - `verbosity_level=1` : Messages importants pour l'utilisateur
   - `verbosity_level=2` : Informations de debug
   - `verbosity_level=3` : Détails très verbeux

3. **Logger les exceptions avec `exc_info=True`** :
   ```python
   except Exception as e:
       logger.error("Erreur", exc_info=True)
   ```

4. **Utiliser des noms de logger descriptifs** :
   ```python
   logger = get_logger('FENRIR.MANGLE.ARP')  # Bon
   logger = get_logger('logger')              # Éviter
   ```

## 🔍 Analyse des logs

### Analyser les logs JSON avec jq
```bash
# Filtrer les erreurs
cat logs/fenrir.json | jq 'select(.level == "ERROR")'

# Compter les paquets par type
cat logs/fenrir.json | jq -r '.metadata.packet_type' | sort | uniq -c

# Extraire les IP sources
cat logs/fenrir.json | jq -r '.metadata.src_ip' | sort | uniq
```

### Analyser les logs texte avec grep
```bash
# Toutes les erreurs
grep "ERROR" logs/fenrir.log

# Paquets TCP
grep "packet_type.*TCP" logs/fenrir.json

# Erreurs d'un module spécifique
grep "\[FENRIR.MANGLE\]" logs/fenrir.log | grep "ERROR"
```

## 🚀 Améliorations futures

- [ ] Support de la rotation des logs
- [ ] Intégration avec des systèmes de monitoring (ELK, Splunk)
- [ ] Métriques de performance dans les logs
- [ ] Filtrage avancé des logs
- [ ] Compression automatique des anciens logs

