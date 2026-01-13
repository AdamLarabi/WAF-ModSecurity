# Projet WAF - ModSecurity sur Kali Linux

![ModSecurity](https://img.shields.io/badge/ModSecurity-v3.0-blue)
![Apache](https://img.shields.io/badge/Apache-2.4-red)
![Security](https://img.shields.io/badge/Security-WAF-green)

## 📋 Description

Mise en place d'un **Web Application Firewall (WAF)** avec ModSecurity sur Apache pour détecter et bloquer les attaques web courantes (OWASP Top 10).

### Objectifs du projet

- Installation et configuration de ModSecurity
- Création de règles personnalisées de détection
- Tests d'intrusion (SQLi, XSS, LFI, Command Injection)
- Analyse des logs et gestion des faux positifs
- Taux de blocage : **100%**

---

## 🛠️ Technologies utilisées

- **OS** : Kali Linux
- **Serveur Web** : Apache 2.4
- **WAF** : ModSecurity 3.0
- **Application de test** : DVWA (Damn Vulnerable Web App)
- **Scripting** : Bash

---

## 🚀 Installation rapide

# Lancer l'installation

sudo ./setup.sh

```

---

## 📁 Architecture du projet

```

WAF-ModSecurity/
├── setup.sh # Installation complète automatisée (menu interactif)
├── test.sh # Tests d'attaques automatiques
├── analyze_logs.sh # Analyse des logs ModSecurity
└── README.md # Documentation du projet

````

---

## 🔧 Configuration

### Règles ModSecurity implémentées

| Règle   | Type d'attaque             | Action      | Sévérité |
| ------- | -------------------------- | ----------- | -------- |
| 1000001 | SQL Injection              | Block (403) | CRITICAL |
| 1000002 | Cross-Site Scripting (XSS) | Block (403) | CRITICAL |
| 1000003 | Scanner Detection          | Block (403) | WARNING  |
| 1000004 | Path Traversal / LFI       | Block (403) | CRITICAL |
| 1000005 | Command Injection          | Block (403) | CRITICAL |

### Fichiers de configuration

- **ModSecurity** : `/etc/modsecurity/modsecurity.conf`
- **Règles personnalisées** : `/etc/modsecurity/rules/custom-rules.conf`
- **Apache** : `/etc/apache2/mods-enabled/security2.conf`
- **Logs** : `/var/log/apache2/modsec_audit.log`

---

## 🧪 Tests et résultats

### Lancer les tests

```bash
# Tests complets
sudo ./test.sh

# Ou via le menu interactif
sudo ./setup.sh
# Puis choisir l'option 3 (Test WAF sans DVWA)

# Analyse des logs
sudo ./analyze_logs.sh
````

### Résultats obtenus

```
========================================
            RÉSUMÉ DES TESTS
========================================
Total de tests : 5
Attaques bloquées : 5
Attaques passées : 0
Taux de blocage : 100%
```

### Détail des tests

| Test | Type d'attaque    | Payload                        | Résultat        |
| ---- | ----------------- | ------------------------------ | --------------- |
| 1    | SQL Injection     | `?id=1' OR '1'='1`             | ✅ Bloqué (403) |
| 2    | XSS               | `?q=<script>alert(1)</script>` | ✅ Bloqué (403) |
| 3    | Path Traversal    | `?file=../../../../etc/passwd` | ✅ Bloqué (403) |
| 4    | Command Injection | `?cmd=ls;whoami`               | ✅ Bloqué (403) |
| 5    | Scanner Detection | User-Agent: Nikto              | ✅ Bloqué (403) |

---

## 📊 Analyse des logs

### Exemple de log ModSecurity

```
[Tue Jan 13 02:55:05 2026] [security2:error] [pid 36770]
ModSecurity: Access denied with code 403 (phase 2).
detected SQLi using libinjection with fingerprint 's&sos'
[file "/etc/modsecurity/rules/custom-rules.conf"] [line "10"]
[id "1000001"] [msg "SQL Injection détectée et bloquée"]
[severity "CRITICAL"]
```

### Statistiques

- **Total d'attaques détectées** : 5
- **Faux positifs** : 0
- **IP source** : ur ip
- **URIs ciblées** : /

---

## 🔍 Commandes utiles

```bash
# Vérifier le statut d'Apache
sudo systemctl status apache2

# Voir les logs en temps réel
sudo tail -f /var/log/apache2/modsec_audit.log

# Tester la configuration Apache
sudo apache2ctl configtest

# Redémarrer Apache
sudo service apache2 restart

# Compter les attaques bloquées aujourd'hui
grep "Access denied" /var/log/apache2/error.log | grep "$(date +%d/%b/%Y)" | wc -l
```

---

## 🛡️ Compétences démontrées

✅ Installation et configuration de ModSecurity  
✅ Création de règles WAF personnalisées (regex, libinjection)  
✅ Tests de sécurité applicative (OWASP Top 10)  
✅ Analyse de logs et détection d'intrusions  
✅ Gestion des faux positifs  
✅ Scripting Bash pour automatisation  
✅ Debugging de configuration Apache

---

## 📝 Améliorations possibles dans le futureee

- [ ] Intégration avec un SIEM (Wazuh, ELK)
- [ ] Ajout de règles OWASP CRS complètes
- [ ] Dashboard de visualisation (Kibana)
- [ ] Alerting automatique (email, Slack)
- [ ] Rate limiting et protection DDoS
- [ ] Géolocalisation des attaquants

---

## 📚 Ressources

- [Documentation ModSecurity](https://github.com/SpiderLabs/ModSecurity)
- [OWASP ModSecurity Core Rule Set](https://coreruleset.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Apache Module mod_security2](https://httpd.apache.org/docs/2.4/mod/mod_security2.html)

---

## 👤 Auteur

**R3D**  
adamlarabi10@gmail.com
