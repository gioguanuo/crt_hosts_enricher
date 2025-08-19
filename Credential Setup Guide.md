# 🔧 Come Configurare le Credenziali - CRT Hosts Enricher

## 📋 Setup Rapido (3 passaggi)

### **Passo 1: Crea i file di configurazione di esempio**
```bash
python config.py --create-examples
```

Questo crea:
- `config.example.json` 
- `config.example.ini`

### **Passo 2: Copia e rinomina il file che preferisci**
```bash
# Opzione A: JSON (raccomandato)
cp config.example.json config.json

# Opzione B: INI (più familiare)
cp config.example.ini config.ini
```

### **Passo 3: Modifica con le tue credenziali**
```bash
# Apri il file con il tuo editor preferito
nano config.json
# oppure
notepad config.json
```

## 📝 Formato JSON (config.json)

```json
{
  "ipinfo_token": "f97aa0477bc627",
  "user_agent": "crt-hosts-enricher/2.1 (+https://github.com/yourusername/crt-hosts-enricher)",
  "default_sleep": 0.5,
  "http_timeout": 60.0,
  "http_retries": 3,
  "log_level": "INFO",
  "output_dir": "results",
  "only_resolvable": false,
  "public_only": false,
  "colored_output": true,
  "cache_enabled": true
}
```

**👆 Cambia solo la riga 2: inserisci il TUO token IPinfo!**

## 📝 Formato INI (config.ini)

```ini
[DEFAULT]
# IPinfo.io API token (required)
ipinfo_token = f97aa0477bc627

# User agent for HTTP requests
user_agent = crt-hosts-enricher/2.1 (+https://github.com/yourusername/crt-hosts-enricher)

# Rate limiting
default_sleep = 0.5
http_timeout = 60.0
http_retries = 3

# Logging
log_level = INFO
colored_output = true

# Output
output_dir = results
only_resolvable = false
public_only = false
```

**👆 Cambia solo la riga 3: inserisci il TUO token IPinfo!**

## 🌍 Alternative con Variabili d'Ambiente

Se preferisci non avere file di configurazione:

### **Linux/macOS:**
```bash
export CRT_IPINFO_TOKEN="f97aa0477bc627"
export CRT_LOG_LEVEL="INFO"
export CRT_OUTPUT_DIR="results"

# Poi esegui il tool
python crt-hosts-enricher.py --domain example.com -o analysis
```

### **Windows:**
```cmd
set CRT_IPINFO_TOKEN=f97aa0477bc627
set CRT_LOG_LEVEL=INFO
set CRT_OUTPUT_DIR=results

python crt-hosts-enricher.py --domain example.com -o analysis
```

### **Windows PowerShell:**
```powershell
$env:CRT_IPINFO_TOKEN="f97aa0477bc627"
$env:CRT_LOG_LEVEL="INFO"
$env:CRT_OUTPUT_DIR="results"

python crt-hosts-enricher.py --domain example.com -o analysis
```

## 🔍 Verifica Configurazione

### **Test se la configurazione funziona:**
```bash
python config.py
```

**Output atteso:**
```
[CONFIG] Configuration loaded successfully

=== Current Configuration ===
  cache_dir: .cache
  cache_enabled: True
  colored_output: True
  default_sleep: 0.5
  http_retries: 3
  http_timeout: 60.0
  ipinfo_token: ********
  log_level: INFO
  output_dir: results
  ...
```

### **Se vedi errori:**
```
[ERROR] Configuration failed: IPinfo token is required

To fix this:
1. Create a config file: python config.py --create-examples
2. Edit config.json with your IPinfo token
3. Or set environment variable: export CRT_IPINFO_TOKEN=your_token
```

## 🎯 Priorità di Configurazione

Il tool cerca le configurazioni in questo ordine:

1. **File specificato**: `--config myconfig.json`
2. **File locali**: `config.json` o `config.ini` nella directory corrente
3. **File utente**: `~/.crt-enricher.json` o `~/.crt-enricher.ini`
4. **Variabili ambiente**: `CRT_IPINFO_TOKEN`, `CRT_LOG_LEVEL`, etc.
5. **Default**: Valori predefiniti (fallback)

## 🔐 Token IPinfo.io

### **Come ottenere il token:**

1. **Vai su**: https://ipinfo.io/signup
2. **Registrati** (gratis)
3. **Dashboard**: Vai su https://ipinfo.io/account/token
4. **Copia il token**: Es. `f97aa0477bc627`

### **Limiti free tier:**
- ✅ **50.000 requests/mese** (più che sufficienti)
- ✅ **Tutti i dati**: ASN, paese, continente
- ✅ **No rate limit** estremi (usa default_sleep: 0.5)

## 🚀 Test Completo

### **Dopo aver configurato, testa:**
```bash
# Test veloce
python crt-hosts-enricher.py --domain google.com -o test --verbose

# Dovresti vedere:
[CONFIG] Configuration loaded successfully
[INFO] IPinfo token: ***configured***
[INFO] Starting hostname extraction from: google.com
```

## 🛡️ Security Best Practices

### **✅ Cosa FARE:**
- ✅ Usa file di configurazione locali
- ✅ Aggiungi `config.json` al `.gitignore`
- ✅ Usa variabili d'ambiente per CI/CD
- ✅ Ruota i token periodicamente

### **❌ Cosa NON fare:**
- ❌ Non committare mai `config.json` con token
- ❌ Non condividere token in chat/email
- ❌ Non usare token in URL/log files
- ❌ Non hardcodare token nel codice

## 🔧 Configurazioni Avanzate

### **Per uso intensivo:**
```json
{
  "ipinfo_token": "your_token_here",
  "default_sleep": 0.2,
  "http_timeout": 30.0,
  "http_retries": 5,
  "cache_enabled": true,
  "log_level": "DEBUG"
}
```

### **Per rate limiting conservativo:**
```json
{
  "ipinfo_token": "your_token_here", 
  "default_sleep": 1.0,
  "http_timeout": 90.0,
  "http_retries": 2,
  "log_level": "INFO"
}
```

## 🆘 Troubleshooting

### **Errore: "IPinfo token is required"**
```bash
# Verifica se il file config esiste:
ls -la config.json

# Verifica il contenuto:
cat config.json

# Verifica variabili ambiente:
echo $CRT_IPINFO_TOKEN
```

### **Errore: "Configuration validation failed"**
```bash
# Test configurazione:
python config.py

# Se necessario, ricrea i file esempio:
python config.py --create-examples
```

### **API rate limit errors**
```json
{
  "default_sleep": 1.0,
  "http_retries": 2
}
```

---

**🎉 Configurazione completata! Ora puoi usare il tool in sicurezza.**