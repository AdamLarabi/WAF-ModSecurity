#!/bin/bash

# ============================================
# WAF ModSecurity - Script d'installation
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_menu() {
    clear
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}    WAF ModSecurity - Menu Principal   ${NC}"
    echo -e "${GREEN}========================================${NC}\n"
    echo "1. Installation complète du WAF"
    echo "2. Ajouter/Corriger les règles personnalisées"
    echo "3. Tester le WAF (sans DVWA)"
    echo "4. Tester le WAF (avec DVWA)"
    echo "5. Analyser les logs"
    echo "6. Afficher les statistiques"
    echo "7. Réparer Apache (si erreur)"
    echo "8. Quitter"
    echo ""
    read -p "Choisissez une option [1-8]: " choice
}

install_waf() {
    echo -e "${YELLOW}[*] Installation du WAF...${NC}"
    
    # Nettoyage
    apt clean
    
    # Installation
    apt install -y --no-install-recommends \
        apache2 libapache2-mod-security2 \
        default-mysql-server php php-mysqli php-gd \
        libapache2-mod-php git
    
    # Démarrage
    service apache2 start
    service mysql start
    
    # Configuration ModSecurity
    if [ -f /etc/modsecurity/modsecurity.conf-recommended ]; then
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
        sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
    fi
    
    a2enmod security2 headers rewrite
    
    # Règles basiques
    mkdir -p /etc/modsecurity/rules
    cat > /etc/modsecurity/rules/custom-rules.conf << 'EOF'
SecRule ARGS "@detectSQLi" \
    "id:1000001,phase:2,deny,status:403,log,msg:'SQL Injection bloquée',severity:CRITICAL,tag:'attack-sqli'"
SecRule ARGS "@detectXSS" \
    "id:1000002,phase:2,deny,status:403,log,msg:'XSS bloqué',severity:CRITICAL,tag:'attack-xss'"
SecRule REQUEST_HEADERS:User-Agent "@pm nikto sqlmap nmap" \
    "id:1000003,phase:1,deny,status:403,log,msg:'Scanner bloqué',severity:WARNING"
SecRule ARGS "@contains ../" \
    "id:1000004,phase:2,deny,status:403,log,msg:'Path traversal bloqué',severity:CRITICAL"
SecRule ARGS "@rx (\||;|`|\$\()" \
    "id:1000005,phase:2,deny,status:403,log,msg:'Command injection bloquée',severity:CRITICAL"
EOF
    
    # Config Apache
    cat > /etc/apache2/mods-enabled/security2.conf << 'EOF'
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/rules/custom-rules.conf
</IfModule>
EOF
    
    mkdir -p /var/cache/modsecurity
    chown www-data:www-data /var/cache/modsecurity
    
    # DVWA (optionnel)
    read -p "Installer DVWA ? (o/n): " install_dvwa
    if [ "$install_dvwa" = "o" ]; then
        cd /var/www/html
        git clone --depth 1 https://github.com/digininja/DVWA.git
        cp DVWA/config/config.inc.php.dist DVWA/config/config.inc.php
        chown -R www-data:www-data DVWA
        
        mysql -u root << 'EOSQL'
CREATE DATABASE IF NOT EXISTS dvwa;
CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
EOSQL
    fi
    
    service apache2 restart
    
    IP=$(hostname -I | awk '{print $1}')
    echo -e "\n${GREEN}✓ Installation terminée !${NC}"
    echo -e "${YELLOW}URL: http://$IP/DVWA${NC}\n"
}

test_waf_simple() {
    echo -e "${YELLOW}[*] Tests d'attaques simples...${NC}\n"
    
    IP=$(hostname -I | awk '{print $1}')
    
    echo -e "${BLUE}[Test 1]${NC} SQL Injection"
    curl -s -o /dev/null -w "Code: %{http_code}\n" "http://$IP/?id=1'+OR+'1'='1"
    
    echo -e "\n${BLUE}[Test 2]${NC} XSS"
    curl -s -o /dev/null -w "Code: %{http_code}\n" "http://$IP/?q=<script>alert(1)</script>"
    
    echo -e "\n${BLUE}[Test 3]${NC} Path Traversal"
    curl -s -o /dev/null -w "Code: %{http_code}\n" "http://$IP/?file=../../../../etc/passwd"
    
    echo -e "\n${BLUE}[Test 4]${NC} Command Injection"
    curl -s -o /dev/null -w "Code: %{http_code}\n" "http://$IP/?cmd=ls;whoami"
    
    echo -e "\n${BLUE}[Test 5]${NC} Scanner (Nikto)"
    curl -s -o /dev/null -w "Code: %{http_code}\n" -H "User-Agent: Nikto" "http://$IP/"
    
    echo -e "\n${GREEN}✓ Tests terminés${NC}"
    echo -e "${YELLOW}403 = Bloqué ✅ | 200 = Passé ❌${NC}\n"
}

analyze_logs() {
    echo -e "${YELLOW}[*] Analyse des logs...${NC}\n"
    
    TOTAL=$(grep -c "Access denied" /var/log/apache2/error.log 2>/dev/null || echo "0")
    echo -e "${YELLOW}Total d'attaques bloquées:${NC} $TOTAL"
    
    echo -e "\n${YELLOW}Top 3 des règles déclenchées:${NC}"
    grep "Access denied" /var/log/apache2/error.log 2>/dev/null | \
        grep -oP '\[id "\K[0-9]+' | sort | uniq -c | sort -rn | head -3
    
    echo -e "\n${YELLOW}Dernières attaques:${NC}"
    grep "Access denied" /var/log/apache2/error.log 2>/dev/null | tail -5 | \
        while read line; do
            echo "- $(echo $line | grep -oP '\[msg "\K[^"]+' || echo 'Attaque détectée')"
        done
    
    echo ""
}

show_stats() {
    echo -e "${GREEN}=== Statistiques WAF ===${NC}\n"
    
    echo -e "${YELLOW}Apache:${NC} $(systemctl is-active apache2)"
    echo -e "${YELLOW}ModSecurity:${NC} Actif"
    
    BLOCKED=$(grep -c "Access denied" /var/log/apache2/error.log 2>/dev/null || echo "0")
    echo -e "${YELLOW}Attaques bloquées (total):${NC} $BLOCKED"
    
    echo -e "\n${YELLOW}Règles actives:${NC}"
    ls /etc/modsecurity/rules/*.conf 2>/dev/null | wc -l
    
    IP=$(hostname -I | awk '{print $1}')
    echo -e "\n${YELLOW}IP du serveur:${NC} $IP"
    echo ""
}

add_custom_rules() {
    echo -e "${YELLOW}[*] Ajout/Correction des règles personnalisées...${NC}"

    # Créer le répertoire si nécessaire
    mkdir -p /etc/modsecurity/rules

    # Règles personnalisées
    cat > /etc/modsecurity/rules/custom-rules.conf << 'EOF'
SecRule ARGS "@detectSQLi" \
    "id:1000001,phase:2,deny,status:403,log,msg:'SQL Injection bloquée',severity:CRITICAL,tag:'attack-sqli'"
SecRule ARGS "@detectXSS" \
    "id:1000002,phase:2,deny,status:403,log,msg:'XSS bloqué',severity:CRITICAL,tag:'attack-xss'"
SecRule REQUEST_HEADERS:User-Agent "@pm nikto sqlmap nmap" \
    "id:1000003,phase:1,deny,status:403,log,msg:'Scanner bloqué',severity:WARNING"
SecRule ARGS "@contains ../" \
    "id:1000004,phase:2,deny,status:403,log,msg:'Path traversal bloqué',severity:CRITICAL"
SecRule ARGS "@rx (\||;|`|\$\()" \
    "id:1000005,phase:2,deny,status:403,log,msg:'Command injection bloquée',severity:CRITICAL"
EOF

    # Mettre à jour la configuration Apache
    cat > /etc/apache2/mods-enabled/security2.conf << 'EOF'
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/rules/custom-rules.conf
</IfModule>
EOF

    # Tester et redémarrer
    apache2ctl configtest
    service apache2 restart

    echo -e "${GREEN}✓ Règles personnalisées ajoutées/corrigées${NC}\n"
}

repair_apache() {
    echo -e "${YELLOW}[*] Réparation d'Apache...${NC}"

    # Configuration minimale
    cat > /etc/apache2/mods-enabled/security2.conf << 'EOF'
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/modsecurity.conf
</IfModule>
EOF

    apache2ctl configtest
    service apache2 restart

    if pgrep -x "apache2" > /dev/null; then
        echo -e "${GREEN}✓ Apache réparé${NC}\n"
    else
        echo -e "${RED}✗ Erreur persistante${NC}\n"
        systemctl status apache2
    fi
}

# Programme principal
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Exécutez avec sudo${NC}"
    exit 1
fi

while true; do
    show_menu
    case $choice in
        1) install_waf; read -p "Appuyez sur Entrée pour continuer..." ;;
        2) add_custom_rules; read -p "Appuyez sur Entrée pour continuer..." ;;
        3) test_waf_simple; read -p "Appuyez sur Entrée pour continuer..." ;;
        4) echo "Testez manuellement sur http://$(hostname -I | awk '{print $1}')/DVWA"; read -p "Entrée..." ;;
        5) analyze_logs; read -p "Appuyez sur Entrée pour continuer..." ;;
        6) show_stats; read -p "Appuyez sur Entrée pour continuer..." ;;
        7) repair_apache; read -p "Appuyez sur Entrée pour continuer..." ;;
        8) echo "Au revoir !"; exit 0 ;;
        *) echo "Option invalide"; sleep 2 ;;
    esac
done
