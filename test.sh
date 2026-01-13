#!/bin/bash

echo "Test direct du WAF..."

# Détection automatique de l'IP
IP=$(hostname -I | awk '{print $1}')

if [ -z "$IP" ]; then
    echo "Erreur: Impossible de détecter l'IP du serveur"
    exit 1
fi

echo "IP du serveur: $IP"

# Test SQL Injection
echo -e "\n[Test 1] SQL Injection"
curl -s -o /dev/null -w "Code HTTP: %{http_code}\n" "http://$IP/?id=1'+OR+'1'='1"

# Test XSS
echo -e "\n[Test 2] XSS"
curl -s -o /dev/null -w "Code HTTP: %{http_code}\n" "http://$IP/?q=<script>alert(1)</script>"

# Test Path Traversal
echo -e "\n[Test 3] Path Traversal"
curl -s -o /dev/null -w "Code HTTP: %{http_code}\n" "http://$IP/?file=../../../../etc/passwd"

# Test Command Injection
echo -e "\n[Test 4] Command Injection"
curl -s -o /dev/null -w "Code HTTP: %{http_code}\n" "http://$IP/?cmd=ls;whoami"

# Test User-Agent
echo -e "\n[Test 5] User-Agent malveillant"
curl -s -o /dev/null -w "Code HTTP: %{http_code}\n" -H "User-Agent: Nikto" "http://$IP/"

# Vérifier les logs
echo -e "\n[Logs ModSecurity]"
sudo tail -10 /var/log/apache2/error.log | grep -i "ModSecurity"
