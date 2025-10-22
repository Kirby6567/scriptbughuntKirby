# 📖 Guia de Exemplos de Uso - Enterprise Bug Bounty Scanner

## Índice

1. [Casos de Uso Básicos](#casos-de-uso-básicos)
2. [Casos de Uso Avançados](#casos-de-uso-avançados)
3. [Workflows Específicos](#workflows-específicos)
4. [Integração com Outras Ferramentas](#integração-com-outras-ferramentas)
5. [Automação e CI/CD](#automação-e-cicd)
6. [Análise de Resultados](#análise-de-resultados)

---

## Casos de Uso Básicos

### 1. Primeiro Scan (Reconhecimento Passivo)

**Cenário**: Você acabou de receber um novo target e quer mapear a superfície de ataque sem fazer barulho.

```bash
# Criar scope file
echo "example.com" > scope.txt

# Executar em modo dry-run (apenas reconhecimento passivo)
./bugbounty-scanner-ULTIMATE-FIXED.sh --profile=balanced scope.txt
```

**O que acontece**:
- ✅ Enumeração de subdomínios (passive)
- ✅ Detecção de hosts vivos
- ✅ Coleta de URLs de archives
- ✅ Download de JS files
- ❌ NÃO executa: nuclei, sqlmap, dalfox, port scanning

**Duração estimada**: 15-30 minutos  
**Output**: `results_YYYYMMDD_HHMMSS/`

### 2. Scan Completo (Primeiro Target Autorizado)

**Cenário**: Você tem autorização e quer executar um scan completo do target.

```bash
# Scope com múltiplos domínios
cat > scope.txt <<EOF
example.com
*.example.com
api.example.com
EOF

# Executar scan completo
./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=balanced scope.txt
```

**O que acontece**:
- ✅ TUDO do dry-run
- ✅ Nuclei vulnerability scanning (4 modos)
- ✅ Port scanning (naabu + masscan)
- ✅ XSS testing (dalfox)
- ✅ SQLi validation (sqlmap)
- ✅ 40+ extra tools

**Duração estimada**: 2-4 horas  
**Output**: Report completo com vulnerabilidades

### 3. Scan Rápido (Apenas Critical)

**Cenário**: Você quer focar apenas em vulnerabilidades críticas para entrega rápida.

```bash
# Modificar temporariamente o script ou usar env vars
export NUCLEI_FLAGS_PRESET="-s critical -c 50 -rl 300"

./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=balanced scope.txt
```

**Duração estimada**: 30-60 minutos  
**Foco**: Apenas severidades critical no nuclei

---

## Casos de Uso Avançados

### 4. Scan Distribuído (Múltiplos VPS)

**Cenário**: Você tem múltiplos VPS e quer distribuir o trabalho.

#### VPS 1: Subdomain Enumeration + Live Detection
```bash
# vps1.sh
./bugbounty-scanner-ULTIMATE-FIXED.sh --profile=aggressive scope.txt

# Após conclusão, copiar resultados
scp -r results_*/subs/ results_*/alive/ user@vps2:/path/
```

#### VPS 2: Vulnerability Scanning
```bash
# vps2.sh - receber subs e alive do VPS1
mkdir -p subs alive
# Copiar arquivos recebidos

# Executar apenas vulnerability scanning
# (modificar script para pular fases 1-2)
./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=aggressive scope.txt
```

### 5. Continuous Monitoring (Monitoramento Contínuo)

**Cenário**: Você quer monitorar mudanças no target diariamente.

```bash
#!/bin/bash
# monitor.sh - Executar diariamente via cron

DOMAIN="example.com"
PREVIOUS_SCAN="results_previous"
CURRENT_SCAN="results_$(date +%Y%m%d)"

# Executar scan
./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=light scope.txt

# Comparar com scan anterior
if [[ -d "$PREVIOUS_SCAN" ]]; then
    # Novos subdomínios
    comm -13 <(sort "$PREVIOUS_SCAN/subs/all_subs.txt") \
             <(sort "$CURRENT_SCAN/subs/all_subs.txt") \
    > diff_new_subdomains.txt
    
    # Novas vulnerabilidades
    comm -13 <(sort "$PREVIOUS_SCAN/nuclei/nuclei_hosts_fast.txt") \
             <(sort "$CURRENT_SCAN/nuclei/nuclei_hosts_fast.txt") \
    > diff_new_vulns.txt
    
    # Enviar alerta se houver mudanças
    if [[ -s diff_new_subdomains.txt ]] || [[ -s diff_new_vulns.txt ]]; then
        # Enviar notificação
        curl -X POST "$DISCORD_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "{\"content\": \"🚨 New findings detected for $DOMAIN!\"}"
    fi
fi

# Atualizar referência
rm -rf "$PREVIOUS_SCAN"
cp -r "$CURRENT_SCAN" "$PREVIOUS_SCAN"
```

**Cron entry**:
```cron
0 2 * * * /path/to/monitor.sh >> /var/log/bugbounty_monitor.log 2>&1
```

### 6. Multi-Target Parallel Scanning

**Cenário**: Você tem múltiplos targets independentes e quer scannear todos em paralelo.

```bash
#!/bin/bash
# multi_scan.sh

TARGETS=("target1.com" "target2.com" "target3.com")
MAX_PARALLEL=3

scan_target() {
    local target="$1"
    echo "$target" > "scope_${target}.txt"
    
    ./bugbounty-scanner-ULTIMATE-FIXED.sh \
        --confirm \
        --yes \
        --profile=balanced \
        "scope_${target}.txt" \
        > "logs/${target}_scan.log" 2>&1
}

# Exportar função
export -f scan_target

# Executar em paralelo
printf '%s\n' "${TARGETS[@]}" | \
xargs -P "$MAX_PARALLEL" -I {} bash -c 'scan_target "$@"' _ {}

echo "✅ All scans completed!"
```

### 7. Scan Focado em API

**Cenário**: O target é principalmente uma API REST/GraphQL.

```bash
# scope_api.txt
api.example.com
graphql.example.com
v1.api.example.com
v2.api.example.com

# Executar scan com foco em APIs
./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=balanced scope_api.txt

# Após scan, análise manual de endpoints
cd results_*/apis/

# Testar GraphQL introspection
cat graphql/vulnerable.txt

# Analisar endpoints descobertos
jq '.' endpoints_from_js.txt

# Testar autenticação
for endpoint in $(cat endpoints_from_js.txt); do
    echo "Testing: $endpoint"
    
    # Sem auth
    curl -s "$endpoint" | jq '.'
    
    # Com token JWT fake
    curl -s "$endpoint" -H "Authorization: Bearer fake_token" | jq '.'
done
```

---

## Workflows Específicos

### 8. Workflow de Bug Bounty (HackerOne)

```bash
# Fase 1: Reconhecimento inicial (Dry-run)
./bugbounty-scanner-ULTIMATE-FIXED.sh --profile=balanced scope.txt

# Fase 2: Análise dos resultados do recon
cd results_*/
cat subs/all_subs.txt | wc -l  # Quantos subdomínios?
cat alive/hosts.txt | wc -l    # Quantos hosts vivos?
cat urls/with_params.txt | head -50  # URLs interessantes?

# Fase 3: Scan ativo (após aprovação)
cd ..
./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=balanced scope.txt

# Fase 4: Validação manual
cd results_*/nuclei/
# Revisar findings critical
grep -i "critical" nuclei_hosts_fast.txt

# Fase 5: Proof of Concept
mkdir -p ../poc
cd ../poc

# Replicar vulnerabilidade manualmente
curl -X POST "https://vulnerable-endpoint.example.com/api/users" \
     -d '{"id": "1 OR 1=1"}' \
     -H "Content-Type: application/json" \
     | tee sqli_poc.txt

# Fase 6: Gerar report para HackerOne
cd ..
cat reports/hackerone_report.md

# Fase 7: Submeter + anexar evidências
# - Upload report
# - Anexar screenshots
# - Incluir PoC
```

### 9. Workflow de Pentest (Cliente Enterprise)

```bash
# Pré-engagement
echo "client-domain.com" > scope.txt
echo "app.client-domain.com" >> scope.txt
echo "*.internal.client-domain.com" >> scope.txt

# Engagement Kick-off
./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=balanced scope.txt \
    > pentest_scan.log 2>&1 &

# Monitorar progresso
tail -f pentest_scan.log

# Durante scan, análise paralela
cd results_*/

# 1. Mapping de attack surface
cat subs/all_subs.txt | \
awk -F. '{print $(NF-1)"."$NF}' | \
sort | uniq -c | sort -rn > attack_surface_summary.txt

# 2. Análise de tecnologias
cat tech/technologies.txt | \
grep -oP '"\K[^"]+(?=")' | \
sort | uniq -c | sort -rn > tech_stack.txt

# 3. Identificar high-value targets
grep -iE '(admin|api|internal|dev|staging)' subs/all_subs.txt > high_value_targets.txt

# Após conclusão do scan
# 4. Criar relatório executivo
cat > executive_summary.md <<EOF
# Pentest Report - Client Domain

## Executive Summary
- **Scope**: $(wc -l < scope.txt) domains
- **Duration**: X hours
- **Critical Findings**: $(grep -c critical nuclei/nuclei_hosts_fast.txt)
- **High Findings**: $(grep -c high nuclei/nuclei_hosts_fast.txt)

## Risk Assessment
[Ver reports/vuln_summary.txt]

## Recommendations
1. Immediate: Patch critical SQLi in /api/users
2. Short-term: Implement WAF on exposed APIs
3. Long-term: Security training for developers
EOF

# 5. Preparar deliverables
mkdir -p deliverables
cp reports/vuln_summary.txt deliverables/
cp html/report.html deliverables/
cp executive_summary.md deliverables/
cp -r screenshots deliverables/

# 6. Comprimir para entrega
tar -czf pentest_deliverables_$(date +%Y%m%d).tar.gz deliverables/
```

### 10. Workflow de Retest (Após Remediação)

```bash
# Cliente corrigiu vulnerabilidades, você precisa revalidar

# 1. Carregar findings originais
ORIGINAL_SCAN="results_20250115_100000"
RETEST_SCOPE="retest_scope.txt"

# 2. Extrair apenas URLs vulneráveis
grep -oP 'https?://[^ ]+' "$ORIGINAL_SCAN/nuclei/nuclei_hosts_fast.txt" | \
sort -u > "$RETEST_SCOPE"

# 3. Retest focado
echo "example.com" > scope_base.txt
./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --profile=light scope_base.txt

# 4. Comparar resultados
cd results_*/
comm -12 <(sort "$ORIGINAL_SCAN/nuclei/nuclei_hosts_fast.txt") \
         <(sort "nuclei/nuclei_hosts_fast.txt") \
> still_vulnerable.txt

comm -23 <(sort "$ORIGINAL_SCAN/nuclei/nuclei_hosts_fast.txt") \
         <(sort "nuclei/nuclei_hosts_fast.txt") \
> fixed_vulnerabilities.txt

# 5. Gerar relatório de retest
cat > retest_report.md <<EOF
# Retest Report - $(date +%Y-%m-%d)

## Remediation Status
- **Total Original Findings**: $(wc -l < "$ORIGINAL_SCAN/nuclei/nuclei_hosts_fast.txt")
- **Still Vulnerable**: $(wc -l < still_vulnerable.txt)
- **Successfully Fixed**: $(wc -l < fixed_vulnerabilities.txt)
- **Fix Rate**: $(echo "scale=2; ($(wc -l < fixed_vulnerabilities.txt) * 100) / $(wc -l < "$ORIGINAL_SCAN/nuclei/nuclei_hosts_fast.txt")" | bc)%

## Remaining Issues
$(cat still_vulnerable.txt)
EOF
```

---

## Integração com Outras Ferramentas

### 11. Integração com Burp Suite

```bash
# Após scan, exportar URLs para Burp
cd results_*/

# URLs com parâmetros (alta prioridade)
cat urls/with_params.txt > burp_scope_high_priority.txt

# Todos os endpoints
cat urls/all_urls.txt > burp_scope_all.txt

# Importar no Burp:
# 1. Target → Site map
# 2. Right-click → Add to scope (from file)
# 3. Selecionar burp_scope_high_priority.txt

# Opcional: Gerar request files
while read url; do
    echo "GET $url HTTP/1.1" > "burp_requests/$(echo $url | md5sum | cut -c1-8).txt"
    echo "Host: $(echo $url | sed 's|http[s]*://||;s|/.*||')" >> "burp_requests/$(echo $url | md5sum | cut -c1-8).txt"
    echo "User-Agent: BurpSuite" >> "burp_requests/$(echo $url | md5sum | cut -c1-8).txt"
    echo "" >> "burp_requests/$(echo $url | md5sum | cut -c1-8).txt"
done < urls/with_params.txt
```

### 12. Integração com Metasploit

```bash
# Exportar hosts vivos para Metasploit
cd results_*/

# Criar arquivo de hosts para Metasploit
cat alive/hosts.txt | \
sed 's|https*://||;s|/.*||' | \
sort -u > metasploit_hosts.txt

# Importar no Metasploit
msfconsole <<EOF
workspace -a bugbounty_example_com
db_import metasploit_hosts.txt
hosts
services
EOF

# Usar dados de port scanning
cat ports/open_ports.txt | while read line; do
    ip=$(echo "$line" | awk '{print $1}')
    port=$(echo "$line" | awk '{print $2}')
    service=$(echo "$line" | awk '{print $3}')
    
    msfconsole -x "
        workspace bugbounty_example_com;
        services -a -p $port -s $service $ip;
        exit
    "
done
```

### 13. Integração com OWASP ZAP

```bash
# Exportar para ZAP API
cd results_*/

# Gerar script de automação ZAP
cat > zap_scan.py <<'PYTHON'
#!/usr/bin/env python3
from zapv2 import ZAPv2
import time

zap = ZAPv2(apikey='YOUR_ZAP_API_KEY')

# Carregar URLs
with open('urls/with_params.txt', 'r') as f:
    urls = [line.strip() for line in f if line.strip()]

print(f"Scanning {len(urls)} URLs with ZAP...")

for url in urls[:100]:  # Limitar a 100 URLs
    print(f"Scanning: {url}")
    zap.urlopen(url)
    time.sleep(2)

# Spider
print("Starting spider...")
zap.spider.scan(urls[0])
while int(zap.spider.status()) < 100:
    print(f"Spider progress: {zap.spider.status()}%")
    time.sleep(5)

# Active Scan
print("Starting active scan...")
zap.ascan.scan(urls[0])
while int(zap.ascan.status()) < 100:
    print(f"Scan progress: {zap.ascan.status()}%")
    time.sleep(5)

# Export results
print("Exporting results...")
with open('zap_report.html', 'w') as f:
    f.write(zap.core.htmlreport())

print("ZAP scan complete!")
PYTHON

chmod +x zap_scan.py
python3 zap_scan.py
```

---

## Automação e CI/CD

### 14. GitHub Actions Workflow

```yaml
# .github/workflows/security-scan.yml
name: Bug Bounty Scan

on:
  schedule:
    - cron: '0 2 * * 0'  # Toda semana domingo às 2am
  workflow_dispatch:  # Manual trigger

jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: kalilinux/kali-rolling
    
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Install tools
        run: |
          apt-get update
          apt-get install -y golang-go python3-pip
          go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
          go install github.com/projectdiscovery/httpx/cmd/httpx@latest
          go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
      
      - name: Run scan
        env:
          DISCORD_WEBHOOK: ${{ secrets.DISCORD_WEBHOOK }}
        run: |
          echo "${{ secrets.SCAN_SCOPE }}" > scope.txt
          ./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --yes --profile=light scope.txt
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: results_*/
      
      - name: Notify on findings
        if: success()
        run: |
          CRITICAL_COUNT=$(grep -c "critical" results_*/nuclei/nuclei_hosts_fast.txt || echo 0)
          if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
            curl -X POST "${{ secrets.DISCORD_WEBHOOK }}" \
                 -H "Content-Type: application/json" \
                 -d "{\"content\": \"🚨 $CRITICAL_COUNT critical findings detected!\"}"
          fi
```

### 15. Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent {
        docker {
            image 'kalilinux/kali-rolling'
        }
    }
    
    parameters {
        choice(name: 'PROFILE', choices: ['light', 'balanced', 'aggressive'], description: 'Scan profile')
        string(name: 'TARGET', defaultValue: 'example.com', description: 'Target domain')
    }
    
    stages {
        stage('Setup') {
            steps {
                sh '''
                    apt-get update && apt-get install -y golang-go
                    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
                    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
                '''
            }
        }
        
        stage('Scan') {
            steps {
                sh """
                    echo '${params.TARGET}' > scope.txt
                    ./bugbounty-scanner-ULTIMATE-FIXED.sh --confirm --yes --profile=${params.PROFILE} scope.txt
                """
            }
        }
        
        stage('Report') {
            steps {
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'results_*/html',
                    reportFiles: 'report.html',
                    reportName: 'Security Scan Report'
                ])
            }
        }
        
        stage('Alert') {
            when {
                expression {
                    def critical = sh(script: "grep -c critical results_*/nuclei/nuclei_hosts_fast.txt || echo 0", returnStdout: true).trim()
                    return critical.toInteger() > 0
                }
            }
            steps {
                emailext(
                    subject: "🚨 Critical Security Findings - ${params.TARGET}",
                    body: '''${FILE,path="results_*/reports/vuln_summary.txt"}''',
                    to: 'security@example.com'
                )
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'results_*/**', fingerprint: true
        }
    }
}
```

---

## Análise de Resultados

### 16. Análise Avançada com Scripts

```bash
#!/bin/bash
# analyze_results.sh

RESULTS_DIR="$1"

echo "========== ANÁLISE DE RESULTADOS =========="
echo ""

# 1. Top subdomínios por TLD
echo "Top 10 TLDs encontrados:"
cat "$RESULTS_DIR/subs/all_subs.txt" | \
awk -F. '{print $NF}' | \
sort | uniq -c | sort -rn | head -10

# 2. Tecnologias mais comuns
echo ""
echo "Top 10 tecnologias detectadas:"
cat "$RESULTS_DIR/tech/technologies.txt" | \
jq -r '.technologies[]' 2>/dev/null | \
sort | uniq -c | sort -rn | head -10

# 3. Portas mais abertas
echo ""
echo "Top 10 portas abertas:"
cat "$RESULTS_DIR/ports/open_ports.txt" | \
awk '{print $2}' | \
sort | uniq -c | sort -rn | head -10

# 4. Vulnerabilidades por severidade
echo ""
echo "Distribuição de severidades:"
for severity in critical high medium low info; do
    count=$(grep -ci "$severity" "$RESULTS_DIR/nuclei/nuclei_hosts_fast.txt" || echo 0)
    echo "  $severity: $count"
done

# 5. Endpoints de API mais interessantes
echo ""
echo "Top 10 endpoints de API:"
grep -oP '/api/[^?]+' "$RESULTS_DIR/urls/all_urls.txt" | \
sed 's|/[0-9]\+||g' | \
sort | uniq -c | sort -rn | head -10

# 6. Parâmetros mais comuns
echo ""
echo "Top 10 parâmetros mais usados:"
cat "$RESULTS_DIR/urls/with_params.txt" | \
grep -oP '\?[^=]+=' | \
sed 's/[?=]//g' | \
sort | uniq -c | sort -rn | head -10

# 7. Secrets encontrados (resumo)
echo ""
echo "Secrets detectados:"
echo "  AWS Keys: $(wc -l < "$RESULTS_DIR/secrets/tokens/aws_keys.txt" 2>/dev/null || echo 0)"
echo "  Google API: $(wc -l < "$RESULTS_DIR/secrets/tokens/google_api_keys.txt" 2>/dev/null || echo 0)"
echo "  Stripe Keys: $(wc -l < "$RESULTS_DIR/secrets/tokens/stripe_keys.txt" 2>/dev/null || echo 0)"
echo "  JWTs: $(wc -l < "$RESULTS_DIR/secrets/tokens/jwt_found.txt" 2>/dev/null || echo 0)"

# 8. WAF detection
echo ""
if [[ -f "$RESULTS_DIR/tech/waf_summary.txt" ]]; then
    echo "WAFs detectados:"
    cat "$RESULTS_DIR/tech/waf_summary.txt" | grep -oP 'behind \K[^()]+' | sort -u
else
    echo "Nenhum WAF detectado"
fi

# 9. Cloudflare bypass oportunidades
echo ""
echo "Cloudflare bypass candidates:"
wc -l "$RESULTS_DIR/reports/cloudflare_bypass/"*.txt 2>/dev/null || echo "0 candidates"

# 10. Métricas de tempo
echo ""
echo "Duração do scan:"
start_time=$(stat -c %Y "$RESULTS_DIR" 2>/dev/null || echo 0)
end_time=$(date +%s)
duration=$((end_time - start_time))
echo "  Total: $((duration / 60)) minutos"
```

### 17. Dashboard Interativo com Python

```python
#!/usr/bin/env python3
# dashboard.py - Visualização interativa dos resultados

import json
import sys
from pathlib import Path
import matplotlib.pyplot as plt
import seaborn as sns

def load_results(results_dir):
    """Carregar dados do scan"""
    data = {
        'subdomains': [],
        'vulnerabilities': [],
        'technologies': [],
        'ports': []
    }
    
    # Carregar subdomínios
    subs_file = Path(results_dir) / 'subs' / 'all_subs.txt'
    if subs_file.exists():
        data['subdomains'] = subs_file.read_text().strip().split('\n')
    
    # Carregar vulnerabilidades (parse nuclei output)
    vuln_file = Path(results_dir) / 'nuclei' / 'nuclei_hosts_fast.txt'
    if vuln_file.exists():
        for line in vuln_file.read_text().strip().split('\n'):
            if line:
                data['vulnerabilities'].append(line)
    
    return data

def plot_severity_distribution(vulns):
    """Gráfico de distribuição de severidades"""
    severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    
    for vuln in vulns:
        vuln_lower = vuln.lower()
        for sev in severities.keys():
            if sev in vuln_lower:
                severities[sev] += 1
                break
    
    plt.figure(figsize=(10, 6))
    colors = ['#d32f2f', '#ff6f00', '#fbc02d', '#388e3c', '#1976d2']
    plt.bar(severities.keys(), severities.values(), color=colors)
    plt.title('Vulnerability Severity Distribution')
    plt.xlabel('Severity')
    plt.ylabel('Count')
    plt.savefig('severity_distribution.png')
    print("✅ Gráfico salvo: severity_distribution.png")

def plot_subdomain_growth(subs):
    """Gráfico de crescimento de subdomínios"""
    # Simulação: agrupar por TLD
    tlds = {}
    for sub in subs:
        tld = sub.split('.')[-1]
        tlds[tld] = tlds.get(tld, 0) + 1
    
    plt.figure(figsize=(12, 6))
    plt.pie(tlds.values(), labels=tlds.keys(), autopct='%1.1f%%')
    plt.title('Subdomain Distribution by TLD')
    plt.savefig('subdomain_tld_distribution.png')
    print("✅ Gráfico salvo: subdomain_tld_distribution.png")

def generate_html_dashboard(data, results_dir):
    """Gerar dashboard HTML interativo"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bug Bounty Scan Dashboard</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .metric {{ display: inline-block; margin: 20px; padding: 20px; 
                      background: #f5f5f5; border-radius: 8px; }}
            .metric h2 {{ margin: 0; color: #333; }}
            .metric p {{ font-size: 32px; font-weight: bold; margin: 10px 0 0 0; }}
            canvas {{ max-width: 600px; margin: 20px; }}
        </style>
    </head>
    <body>
        <h1>🎯 Bug Bounty Scan Results Dashboard</h1>
        
        <div class="metrics">
            <div class="metric">
                <h2>Subdomains</h2>
                <p>{len(data['subdomains'])}</p>
            </div>
            <div class="metric">
                <h2>Vulnerabilities</h2>
                <p>{len(data['vulnerabilities'])}</p>
            </div>
            <div class="metric">
                <h2>Critical Findings</h2>
                <p>{sum(1 for v in data['vulnerabilities'] if 'critical' in v.lower())}</p>
            </div>
        </div>
        
        <h2>Visualizations</h2>
        <img src="severity_distribution.png" alt="Severity Distribution">
        <img src="subdomain_tld_distribution.png" alt="Subdomain TLD Distribution">
        
        <h2>Detailed Results</h2>
        <p>Full reports available in: <code>{results_dir}</code></p>
    </body>
    </html>
    """
    
    dashboard_file = Path(results_dir) / 'dashboard.html'
    dashboard_file.write_text(html)
    print(f"✅ Dashboard gerado: {dashboard_file}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 dashboard.py <results_directory>")
        sys.exit(1)
    
    results_dir = sys.argv[1]
    print(f"📊 Analisando resultados em: {results_dir}")
    
    data = load_results(results_dir)
    plot_severity_distribution(data['vulnerabilities'])
    plot_subdomain_growth(data['subdomains'])
    generate_html_dashboard(data, results_dir)
    
    print("\n✅ Análise completa!")
    print(f"   - Abra {results_dir}/dashboard.html no navegador")
```

**Uso**:
```bash
python3 dashboard.py results_20250120_150000/
```

---

**Documentação mantida por**: Kirby656 & AI Assistant  
**Última atualização**: 2025-01-20  
**Versão**: 1.0

Para mais exemplos e casos de uso, visite o [repositório no GitHub](https://github.com/seu-usuario/enterprise-bugbounty-scanner).
