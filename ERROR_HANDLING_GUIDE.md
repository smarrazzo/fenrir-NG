# Guide de gestion d'erreurs FENRIR

## 📋 Vue d'ensemble

Le système de gestion d'erreurs de FENRIR utilise des exceptions personnalisées et un logging structuré pour une meilleure traçabilité et débogage.

## 🎯 Hiérarchie des exceptions

```
FenrirError (base)
├── FenrirSocketError
├── FenrirNetworkError
├── FenrirTAPError
├── FenrirPacketError
├── FenrirMangleError
├── FenrirThreadError
├── FenrirInterfaceError
├── FenrirAutoconfError
├── FenrirConfigurationError
└── FenrirValidationError
```

## 📝 Types d'exceptions

### FenrirSocketError
**Utilisation :** Erreurs liées aux sockets
```python
raise FenrirSocketError("Failed to create socket", 
                       details={'iface': 'eth0', 'error': str(e)})
```

### FenrirTAPError
**Utilisation :** Erreurs avec l'interface TAP
```python
raise FenrirTAPError("Failed to create TAP interface",
                     details={'tap_name': 'FENRIR', 'error': str(e)})
```

### FenrirPacketError
**Utilisation :** Erreurs de traitement de paquets
```python
raise FenrirPacketError("Failed to parse packet",
                       details={'packet_size': len(data), 'error': str(e)})
```

### FenrirMangleError
**Utilisation :** Erreurs lors de la transformation de paquets
```python
raise FenrirMangleError("Error during packet mangling",
                       details={'packet_type': 'TCP', 'error': str(e)})
```

### FenrirAutoconfError
**Utilisation :** Erreurs d'auto-configuration
```python
raise FenrirAutoconfError("Failed to detect host IP/MAC",
                         details={'timeout': 30})
```

## 🔧 Bonnes pratiques

### 1. Capturer des exceptions spécifiques

**❌ Mauvais :**
```python
try:
    socket.bind(...)
except:
    pass  # Ignore toutes les erreurs
```

**✅ Bon :**
```python
try:
    socket.bind(...)
except (OSError, socket.error) as e:
    logger.error("Failed to bind socket", exc_info=True, error=str(e))
    raise FenrirSocketError("Socket bind failed", details={'error': str(e)}) from e
```

### 2. Logger avec contexte

**✅ Bon :**
```python
try:
    process_packet(pkt)
except Exception as e:
    logger.error("Error processing packet",
                 exc_info=True,
                 packet_type="TCP",
                 src_ip=pkt[IP].src,
                 dst_ip=pkt[IP].dst,
                 error=str(e))
```

### 3. Utiliser des context managers

**❌ Mauvais :**
```python
logfd = open('file.log', 'a')
logfd.write(...)
logfd.close()  # Peut ne pas être appelé en cas d'exception
```

**✅ Bon :**
```python
with open('file.log', 'a') as logfd:
    logfd.write(...)
```

### 4. Gérer les erreurs de manière appropriée

**Pour les erreurs critiques :**
```python
try:
    critical_operation()
except FenrirError as e:
    logger.critical("Critical error", exc_info=True)
    raise  # Re-lever l'exception
```

**Pour les erreurs non-critiques :**
```python
try:
    optional_operation()
except (OSError, socket.error) as e:
    logger.warning("Operation failed, continuing", 
                  verbosity_level=2,
                  error=str(e))
    # Continuer le traitement
```

## 📊 Exemples d'utilisation

### Exemple 1 : Création de TAP
```python
def createTap(self):
    try:
        self.tap = TunTapDevice(flags=IFF_TAP|IFF_NO_PI, name='FENRIR')
        self.tap.up()
        logger.info("TAP created", tap_name="FENRIR")
    except OSError as e:
        error_msg = f"Failed to create TAP: {e}"
        logger.error(error_msg, exc_info=True)
        raise FenrirTAPError(error_msg, details={'error': str(e)}) from e
```

### Exemple 2 : Envoi de paquet
```python
def sendeth2(self, raw, interface):
    try:
        if not isinstance(raw, bytes):
            raw = bytes(raw)
        target_socket.send(raw)
    except (OSError, socket.error) as e:
        # Erreur non-critique, logger mais continuer
        logger.warning(f"Failed to send on {interface}",
                      verbosity_level=2,
                      interface=interface,
                      error=str(e))
    except (TypeError, ValueError) as e:
        # Erreur de conversion, plus critique
        error_msg = f"Invalid packet data: {e}"
        logger.error(error_msg, exc_info=True)
        raise FenrirPacketError(error_msg) from e
```

### Exemple 3 : Traitement de paquet
```python
def process_packet(self, pkt):
    try:
        pkt = Ether(raw_data)
    except Exception as e:
        logger.warning("Failed to parse as Ether",
                     verbosity_level=2,
                     error=str(e),
                     data_size=len(raw_data))
        return None  # Ignorer ce paquet
    
    try:
        return self.mangle_packet(pkt)
    except FenrirMangleError:
        raise  # Re-lever les erreurs de mangle
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        logger.critical(error_msg, exc_info=True)
        raise FenrirPacketError(error_msg) from e
```

## 🎨 Stratégies de gestion d'erreurs

### 1. Fail-fast (Échec rapide)
Pour les erreurs critiques qui empêchent le fonctionnement :
```python
if not self.tap:
    raise FenrirTAPError("TAP not initialized")
```

### 2. Continue on error (Continuer malgré l'erreur)
Pour les erreurs non-critiques :
```python
try:
    forward_packet(pkt)
except (OSError, socket.error) as e:
    logger.warning("Failed to forward, skipping", error=str(e))
    continue  # Passer au paquet suivant
```

### 3. Retry (Réessayer)
Pour les erreurs transitoires :
```python
max_retries = 3
for attempt in range(max_retries):
    try:
        send_packet(pkt)
        break
    except (OSError, socket.error) as e:
        if attempt == max_retries - 1:
            raise
        logger.debug(f"Retry {attempt+1}/{max_retries}", error=str(e))
        time.sleep(0.1)
```

## 🔍 Débogage

### Activer le logging détaillé
```python
logger = get_logger('FENRIR', verbosity=3)  # Niveau maximum
```

### Analyser les logs d'erreur
```bash
# Toutes les erreurs
grep "ERROR" logs/fenrir.log

# Erreurs de socket
grep "FenrirSocketError" logs/fenrir.log

# Erreurs avec stack trace
grep -A 20 "Traceback" logs/fenrir.log
```

### Analyser les logs JSON
```bash
# Erreurs uniquement
cat logs/fenrir.json | jq 'select(.level == "ERROR")'

# Erreurs avec métadonnées
cat logs/fenrir.json | jq 'select(.level == "ERROR") | .metadata'
```

## 📋 Checklist de gestion d'erreurs

- [ ] Tous les `except:` génériques remplacés par des exceptions spécifiques
- [ ] Toutes les exceptions loggées avec `exc_info=True` si nécessaire
- [ ] Métadonnées pertinentes ajoutées aux logs d'erreur
- [ ] Context managers utilisés pour les ressources (fichiers, sockets)
- [ ] Exceptions personnalisées utilisées pour les erreurs FENRIR
- [ ] Messages d'erreur descriptifs et actionnables
- [ ] Gestion appropriée des erreurs critiques vs non-critiques

## 🚀 Améliorations futures

- [ ] Système de retry automatique pour les erreurs transitoires
- [ ] Métriques d'erreurs (taux d'erreur, types d'erreurs)
- [ ] Alertes automatiques pour les erreurs critiques
- [ ] Tests unitaires pour chaque type d'exception
- [ ] Documentation des codes d'erreur

