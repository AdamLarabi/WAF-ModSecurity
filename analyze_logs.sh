#!/bin/bash

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}    Analyse des logs ModSecurity       ${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Vérification des privilèges root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Ce script doit être exécuté en root (sudo)${NC}"
    exit 1
fi

LOG_FILE="/var/log/apache2/modsec_audit.log"
ERROR_LOG="/var/log/apache2/error.log"
REPORT_FILE=~/waf-lab/log_analysis_$(date +%Y%m%d_%H%M%S).txt

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}[!] Fichier de log introuvable : $LOG_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Analyse du fichier :${NC} $LOG_FILE" | tee $REPORT_FILE
echo -e "${YELLOW}[*] Rapport sauvegardé :${NC} $REPORT_FILE\n" | tee -a $REPORT_FILE

# Statistiques générales
echo -e "${CYAN}=== STATISTIQUES GÉNÉRALES ===${NC}\n" | tee -a $REPORT_FILE

TOTAL_ALERTS=$(grep -c "ModSecurity: Access denied" $ERROR_LOG 2>/dev/null || echo "0")
echo -e "${YELLOW}Total d'attaques détectées :${NC} $TOTAL_ALERTS" | tee -a $REPORT_FILE

# Top 5 des règles déclenchées
echo -e "\n${CYAN}=== TOP 5 DES RÈGLES DÉCLENCHÉES ===${NC}\n" | tee -a $REPORT_FILE
grep "ModSecurity: Access denied" $ERROR_LOG 2>/dev/null | \
    grep -oP '\[id "\K[0-9]+' | \
    sort | uniq -c | sort -rn | head -5 | \
    while read count id; do
        echo -e "${YELLOW}Règle $id :${NC} $count fois" | tee -a $REPORT_FILE
    done

# Types d'attaques détectées
echo -e "\n${CYAN}=== TYPES D'ATTAQUES DÉTECTÉES ===${NC}\n" | tee -a $REPORT_FILE

SQL_INJ=$(grep -c "SQL Injection" $ERROR_LOG 2>/dev/null || echo "0")
XSS=$(grep -c "XSS" $ERROR_LOG 2>/dev/null || echo "0")
LFI=$(grep -c "Local File" $ERROR_LOG 2>/dev/null || echo "0")
RCE=$(grep -c "Command" $ERROR_LOG 2>/dev/null || echo "0")

echo -e "${YELLOW}SQL Injection :${NC} $SQL_INJ tentatives" | tee -a $REPORT_FILE
echo -e "${YELLOW}XSS :${NC} $XSS tentatives" | tee -a $REPORT_FILE
echo -e "${YELLOW}Local File Inclusion :${NC} $LFI tentatives" | tee -a $REPORT_FILE
echo -e "${YELLOW}Command Injection :${NC} $RCE tentatives" | tee -a $REPORT_FILE

# IPs sources
echo -e "\n${CYAN}=== TOP 5 DES IPs SOURCES ===${NC}\n" | tee -a $REPORT_FILE
grep "ModSecurity: Access denied" $ERROR_LOG 2>/dev/null | \
    grep -oP '\[client \K[^\]]+' | \
    cut -d: -f1 | \
    sort | uniq -c | sort -rn | head -5 | \
    while read count ip; do
        echo -e "${YELLOW}$ip :${NC} $count attaques" | tee -a $REPORT_FILE
    done

# URIs les plus ciblées
echo -e "\n${CYAN}=== URIs LES PLUS CIBLÉES ===${NC}\n" | tee -a $REPORT_FILE
grep "ModSecurity: Access denied" $ERROR_LOG 2>/dev/null | \
    grep -oP '\[uri "\K[^"]+' | \
    sort | uniq -c | sort -rn | head -5 | \
    while read count uri; do
        echo -e "${YELLOW}$uri :${NC} $count fois" | tee -a $REPORT_FILE
    done

# Dernières attaques détectées
echo -e "\n${CYAN}=== 5 DERNIÈRES ATTAQUES DÉTECTÉES ===${NC}\n" | tee -a $REPORT_FILE
grep "ModSecurity: Access denied" $ERROR_LOG 2>/dev/null | \
    tail -5 | \
    while IFS= read -r line; do
        timestamp=$(echo "$line" | grep -oP '\[.*?\]' | head -1)
        rule_id=$(echo "$line" | grep -oP '\[id "\K[0-9]+')
        msg=$(echo "$line" | grep -oP '\[msg "\K[^"]+')
        echo -e "${YELLOW}$timestamp${NC}" | tee -a $REPORT_FILE
        echo -e "  Règle: $rule_id - $msg\n" | tee -a $REPORT_FILE
    done

# Faux positifs potentiels
echo -e "${CYAN}=== ANALYSE DES FAUX POSITIFS ===${NC}\n" | tee -a $REPORT_FILE

FP_COUNT=$(grep "ModSecurity: Access denied" $ERROR_LOG 2>/dev/null | \
    grep -i "GET /DVWA/login.php\|POST /DVWA/login.php\|GET /DVWA/setup.php" | wc -l)

if [ $FP_COUNT -gt 0 ]; then
    echo -e "${RED}[!] $FP_COUNT faux positifs potentiels détectés${NC}" | tee -a $REPORT_FILE
    echo -e "${YELLOW}    (Blocages sur pages de login/setup DVWA)${NC}\n" | tee -a $REPORT_FILE
else
    echo -e "${GREEN}[✓] Aucun faux positif évident détecté${NC}\n" | tee -a $REPORT_FILE
fi

# Recommandations
echo -e "${CYAN}=== RECOMMANDATIONS ===${NC}\n" | tee -a $REPORT_FILE

if [ $TOTAL_ALERTS -lt 5 ]; then
    echo -e "${YELLOW}[!] Peu d'attaques détectées. Lancez test_waf.sh pour générer du trafic${NC}" | tee -a $REPORT_FILE
elif [ $TOTAL_ALERTS -gt 50 ]; then
    echo -e "${RED}[!] Beaucoup d'alertes. Vérifiez les faux positifs${NC}" | tee -a $REPORT_FILE
    echo -e "${YELLOW}    Considérez de réduire le niveau de paranoïa${NC}" | tee -a $REPORT_FILE
else
    echo -e "${GREEN}[✓] Niveau d'alertes normal${NC}" | tee -a $REPORT_FILE
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}     Analyse terminée avec succès !    ${NC}"
echo -e "${GREEN}========================================${NC}\n"

echo -e "${YELLOW}[!] Rapport complet :${NC} $REPORT_FILE\n"
