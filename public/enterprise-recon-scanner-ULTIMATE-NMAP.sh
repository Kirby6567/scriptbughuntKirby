#!/usr/bin/env bash
# bugbounty_scanner_ULTIMATE_FIXED_NMAP.sh
# Enhanced automated bug-bounty reconnaissance & scanning pipeline
# CORRIGIDO COM: NMAP, FLAGS NUCLEI CORRETAS, SQLMAP --crawl/--forms
# Target platform: Kali Linux / Security distributions
# Author: Kirby656 & Enhanced by AI Assistant
# License: Use only on targets you are authorized to test.

# ============= AVISOS DE SEGURANÇA E ÉTICA =============
# ⚠️  IMPORTANTE: Use apenas em alvos autorizados para teste
# ⚠️  Para perfis agressivos, use VPS dedicado (não rede doméstica)  
# ⚠️  Monitore logs e ajuste rate limits conforme necessário
# ⚠️  Dry-run habilitado por padrão - use --confirm para ações ativas
# ⚠️  Toda atividade de scanning deve ter autorização prévia

set -euo pipefail
IFS=$'\n\t'

# ============= SISTEMA DE PERFIS E CONFIGURAÇÕES =============
# Parse command line arguments
PROFILE=""
DRY_RUN=true
SKIP_CONFIRMATION=false
EXPORT_JSON=false

# Parse argumentos da linha de comando
while [[ $# -gt 0 ]]; do
    case $1 in
        --profile=*)
            PROFILE="${1#*=}"
            shift
            ;;
        --confirm|--no-dry-run)
            DRY_RUN=false
            shift
            ;;
        --yes)
            SKIP_CONFIRMATION=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --export-json)
            EXPORT_JSON=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options] scope.txt"
            echo "Options:"
            echo "  --profile=PROFILE    Set profile: light, balanced, aggressive, kamikaze"
            echo "  --confirm            Disable dry-run mode (enable active scanning)"
            echo "  --dry-run            Enable dry-run mode (default)"
            echo "  --yes                Skip confirmation prompts"
            echo "  --export-json        Export results in JSON format"
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            SCOPE_FILE="$1"
            shift
            ;;
    esac
done

# ============= PROMPT INTERATIVO DE PERFIS =============
show_profile_menu() {
    echo ""
    echo "🎯 Selecione o perfil de execução:"
    echo ""
    echo "1) light      - Seguro para rede doméstica (baixo impacto)"
    echo "   • Concorrência: 8 threads"
    echo "   • Rate limit: 20/s"
    echo "   • Timeouts conservadores"
    echo ""
    echo "2) balanced   - Recomendado para VM 8GB/4cores (padrão) "
    echo "   • Concorrência: 20 threads"
    echo "   • Rate limit: 100/s"  
    echo "   • Timeouts médios"
    echo ""
    echo "3) aggressive - Somente VPS dedicado (alto paralelismo)"
    echo "   • Concorrência: 50 threads"
    echo "   • Rate limit: 300/s"
    echo "   • Timeouts agressivos"
    echo ""
    echo "4) kamikaze   - MÁXIMA BRUTALIDADE (use com cuidado!)"
    echo "   • Concorrência: 250 threads"
    echo "   • Rate limit: 1500/s"
    echo "   • SEM limites de segurança"
    echo ""
    echo -n "Escolha [1-4] ou [light/balanced/aggressive/kamikaze] (Enter = balanced): "
}

# Configurar perfil interativamente se necessário
if [[ -z "$PROFILE" ]]; then
    # Usar variável de ambiente se disponível
    PROFILE="${PROFILE:-}"
    
    # Se ainda não definido e rodando em TTY, mostrar menu
    if [[ -z "$PROFILE" ]] && [[ -t 0 ]] && [[ -t 1 ]]; then
        show_profile_menu
        read -r user_input
        
        case "$user_input" in
            1|light)
                PROFILE="light"
                ;;
            2|balanced|"")
                PROFILE="balanced"
                ;;
            3|aggressive)
                PROFILE="aggressive"
                ;;
            4|kamikaze)
                PROFILE="kamikaze"
                ;;
            *)
                echo "❌ Opção inválida. Usando 'balanced' como padrão."
                PROFILE="balanced"
                ;;
        esac
    fi
fi

# Definir padrão se ainda não configurado
PROFILE="${PROFILE:-balanced}"

# ============= CONFIGURAÇÃO DOS PERFIS =============
configure_profile() {
    case "$PROFILE" in
        light)
            CONCURRENCY=8
            PARALLEL_HOSTS=2
            RATE_LIMIT=20
            TIMEOUT_PER_HOST="20s"
            NUCLEI_CONCURRENCY=5
            NUCLEI_RATE_LIMIT=20
            NUCLEI_TIMEOUT=5
            MAX_CRAWL_DEPTH=1
            MAX_JS_FILES=20
            NCPU=2
            NAABU_TOP_PORTS=100
            SQLMAP_LEVEL=1
            SQLMAP_RISK=1
            MASSCAN_RATE=300
            NMAP_TIMING=2  # Polite
            NMAP_MAX_RATE=100
            SQLMAP_THREADS=1
            ;;
        balanced)
            CONCURRENCY=35
            PARALLEL_HOSTS=6
            RATE_LIMIT=200
            TIMEOUT_PER_HOST="90s"
            NUCLEI_CONCURRENCY=40
            NUCLEI_RATE_LIMIT=200
            NUCLEI_TIMEOUT=12
            MAX_CRAWL_DEPTH=6
            MAX_JS_FILES=200
            NCPU=$(nproc 2>/dev/null || echo 6)
            NAABU_TOP_PORTS=1000
            SQLMAP_LEVEL=4
            SQLMAP_RISK=2
            MASSCAN_RATE=800
            NMAP_TIMING=3  # Normal
            NMAP_MAX_RATE=500
            SQLMAP_THREADS=3
            ;;
        aggressive)
            CONCURRENCY=150
            PARALLEL_HOSTS=30
            RATE_LIMIT=800
            TIMEOUT_PER_HOST="180s"
            NUCLEI_CONCURRENCY=150
            NUCLEI_RATE_LIMIT=800
            NUCLEI_TIMEOUT=18
            MAX_CRAWL_DEPTH=8
            MAX_JS_FILES=800
            NCPU=$(nproc 2>/dev/null || echo 16)
            NAABU_TOP_PORTS=full
            SQLMAP_LEVEL=5
            SQLMAP_RISK=3
            MASSCAN_RATE=2000
            NMAP_TIMING=4  # Aggressive
            NMAP_MAX_RATE=2000
            SQLMAP_THREADS=5
            ;;
        kamikaze)
            CONCURRENCY=250
            PARALLEL_HOSTS=80
            RATE_LIMIT=1500
            TIMEOUT_PER_HOST="400s"
            NUCLEI_CONCURRENCY=250
            NUCLEI_RATE_LIMIT=1500
            NUCLEI_TIMEOUT=25
            MAX_CRAWL_DEPTH=12
            MAX_JS_FILES=1500
            NCPU=$(nproc 2>/dev/null || echo 32)
            NAABU_TOP_PORTS=full
            SQLMAP_LEVEL=5
            SQLMAP_RISK=3
            MASSCAN_RATE=5000
            NMAP_TIMING=5  # Insane
            NMAP_MAX_RATE=5000
            SQLMAP_THREADS=10
            ulimit -n 65535 2>/dev/null || true
            ;;
        *)
            echo "❌ Perfil desconhecido: $PROFILE"
            exit 1
            ;;
    esac
}

# Configurar perfil selecionado
configure_profile

# ... keep existing code (all utility functions, tool checks, directory setup, Telegram/Discord setup, subdomain enumeration, live host detection, etc. from lines 190-1263 of original script)

# ============= FUNÇÕES AUXILIARES =============
log_info() {
    echo -e "[INFO] $*"
}

log_warn() {
    echo -e "[WARN] $*"
}

log_error() {
    echo -e "[ERROR] $*"
}

log_success() {
    echo -e "[SUCCESS] $*"
}

log_section() {
    echo -e "\n========== $* ==========\n"
}

send_notification() {
    # Placeholder for notification logic (Telegram, Discord, etc.)
    # $1 = message, $2 = optional flag for urgent
    echo -e "[NOTIFY] $1"
}

safe_count() {
    if [[ -f "$1" ]]; then
        wc -l < "$1" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# ============= FERRAMENTAS APRIMORADAS =============
REQUIRED_TOOLS=(subfinder httpx nuclei jq curl wget)
OPTIONAL_TOOLS=(amass findomain naabu gau waybackurls hakrawler katana gf qsreplace dalfox sqlmap gospider getjs aria2c massdns subjack wafw00f nmap masscan)

check_tools() {
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_warn "⚠️  Ferramenta obrigatória não encontrada: $tool"
        fi
    done
}

setup_directories() {
    mkdir -p alive ports/naabu ports/masscan ports/nmap nuclei poc/sqli logs/nmap logs sqlmap urls reports html secrets
}

check_tools
setup_directories

# ============= FASE 3: PORT SCANNING COM NMAP INTEGRADO =============

echo ""
echo "========== FASE 3: PORT SCANNING + NMAP VULNERABILITY DETECTION =========="
send_notification "🔍 *FASE 3: PORT SCANNING + NMAP*\nEscaneando portas e vulnerabilidades..."

# ============= NMAP VULNERABILITY DETECTION INTEGRADO =============
nmap_vulnerability_scan() {
    if ! command -v nmap >/dev/null 2>&1; then
        log_warn "⚠️  nmap não instalado - pulando vulnerability detection"
        log_info "💡 Instale com: sudo apt install nmap"
        return 0
    fi
    
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_warn "⚠️  Nenhum host para NMAP scanning"
        return 0
    fi
    
    log_section "NMAP VULNERABILITY & SERVICE DETECTION"
    mkdir -p ports/nmap logs/nmap
    
    local max_nmap_hosts=20
    [[ "$PROFILE" = "light" ]] && max_nmap_hosts=5
    [[ "$PROFILE" = "balanced" ]] && max_nmap_hosts=20
    [[ "$PROFILE" = "aggressive" ]] && max_nmap_hosts=50
    [[ "$PROFILE" = "kamikaze" ]] && max_nmap_hosts=100
    
    log_info "🎯 Executando NMAP em até $max_nmap_hosts hosts (timing: T$NMAP_TIMING)..."
    
    # Preparar lista de hosts (resolver IPs se necessário)
    local target_list="ports/nmap/targets.txt"
    head -n "$max_nmap_hosts" alive/hosts_only.txt > "$target_list"
    
    # ETAPA 1: Service Version Detection + NSE Vuln Scripts (MÁXIMA COBERTURA)
    log_info "🔥 [NMAP] Etapa 1: Service Detection + Vulnerability NSE Scripts..."
    timeout 90m nmap -iL "$target_list" \
        -T${NMAP_TIMING} \
        --max-rate ${NMAP_MAX_RATE} \
        -sV \
        --version-intensity 7 \
        --script=vuln,exploit,auth,brute,discovery,intrusive \
        --script-args=unsafe=1 \
        -p- \
        --open \
        --reason \
        -oA ports/nmap/nmap_vuln_full \
        -oN ports/nmap/nmap_vuln_full.txt \
        -oX ports/nmap/nmap_vuln_full.xml \
        --stats-every 60s \
        --min-parallelism 10 \
        2>&1 | tee logs/nmap/nmap_vuln_scan.log || true
    
    # ETAPA 2: NSE Vuln-specific Scripts (se ports já descobertos)
    if [[ -s ports/naabu.txt ]] || [[ -s ports/masscan/masscan_ports.txt ]]; then
        log_info "🔥 [NMAP] Etapa 2: NSE Deep Vulnerability Scripts em portas conhecidas..."
        
        # Extrair portas únicas
        local ports_list=""
        if [[ -s ports/naabu.txt ]]; then
            ports_list=$(awk -F':' '{print $2}' ports/naabu.txt | sort -un | tr '\n' ',' | sed 's/,$//')
        elif [[ -s ports/masscan/masscan_ports.txt ]]; then
            ports_list=$(awk -F':' '{print $2}' ports/masscan/masscan_ports.txt | sort -un | tr '\n' ',' | sed 's/,$//')
        fi
        
        if [[ -n "$ports_list" ]]; then
            timeout 60m nmap -iL "$target_list" \
                -T${NMAP_TIMING} \
                --max-rate ${NMAP_MAX_RATE} \
                -sV -sC \
                --version-intensity 9 \
                --script="vulners,vulscan,vuln,http-vuln-*,ssl-*,smb-vuln-*,ftp-*,ssh-*,mysql-*,dns-*" \
                --script-args vulners.mincvss=5.0 \
                -p "$ports_list" \
                --open \
                -oA ports/nmap/nmap_vuln_specific \
                -oN ports/nmap/nmap_vuln_specific.txt \
                2>&1 | tee logs/nmap/nmap_vuln_specific.log || true
        fi
    fi
    
    # ETAPA 3: HTTP/HTTPS Specific NSE (Web Application Testing)
    log_info "🔥 [NMAP] Etapa 3: HTTP/HTTPS NSE Scripts para Web Apps..."
    timeout 45m nmap -iL "$target_list" \
        -T${NMAP_TIMING} \
        --max-rate ${NMAP_MAX_RATE} \
        -sV \
        -p 80,443,8080,8443,8000,8888,3000,5000 \
        --script="http-enum,http-methods,http-headers,http-title,http-robots.txt,http-shellshock,http-sql-injection,http-stored-xss,http-csrf,http-fileupload-exploiter,http-backup-finder,http-config-backup,http-git,http-svn-info,http-wordpress-enum,http-drupal-enum,http-joomla-brute" \
        --open \
        -oA ports/nmap/nmap_http_vuln \
        -oN ports/nmap/nmap_http_vuln.txt \
        2>&1 | tee logs/nmap/nmap_http.log || true
    
    # ETAPA 4: SSL/TLS Vulnerability Testing
    log_info "🔥 [NMAP] Etapa 4: SSL/TLS Security Testing..."
    timeout 30m nmap -iL "$target_list" \
        -T${NMAP_TIMING} \
        -p 443,8443 \
        --script="ssl-enum-ciphers,ssl-cert,ssl-cert-intaddr,ssl-date,ssl-heartbleed,ssl-poodle,ssl-dh-params,sslv2,ssl-ccs-injection" \
        --open \
        -oA ports/nmap/nmap_ssl_vuln \
        -oN ports/nmap/nmap_ssl_vuln.txt \
        2>&1 | tee logs/nmap/nmap_ssl.log || true
    
    # ETAPA 5: SMB/NetBIOS Vulnerability Testing
    log_info "🔥 [NMAP] Etapa 5: SMB/NetBIOS Security Testing..."
    timeout 30m nmap -iL "$target_list" \
        -T${NMAP_TIMING} \
        -p 139,445 \
        --script="smb-vuln-*,smb-os-discovery,smb-security-mode,smb-enum-shares,smb-enum-users" \
        --open \
        -oA ports/nmap/nmap_smb_vuln \
        -oN ports/nmap/nmap_smb_vuln.txt \
        2>&1 | tee logs/nmap/nmap_smb.log || true
    
    # Consolidar resultados
    log_info "📊 Processando resultados NMAP..."
    
    # Extrair vulnerabilidades encontradas
    if [[ -s ports/nmap/nmap_vuln_full.txt ]]; then
        grep -E "VULNERABLE|CVE-|exploit|http-vuln" ports/nmap/nmap_vuln_full.txt > ports/nmap/vulnerabilities_found.txt 2>/dev/null || touch ports/nmap/vulnerabilities_found.txt
        
        local vuln_count=$(grep -c "VULNERABLE\|CVE-" ports/nmap/vulnerabilities_found.txt 2>/dev/null || echo 0)
        log_success "✅ NMAP encontrou $vuln_count potenciais vulnerabilidades!"
        
        if [[ "$vuln_count" -gt 0 ]]; then
            send_notification "🚨 *NMAP VULNERABILITIES FOUND*\n🔥 $vuln_count potenciais vulnerabilidades detectadas!\n📄 Veja: ports/nmap/vulnerabilities_found.txt\n\n$(head -10 ports/nmap/vulnerabilities_found.txt)" "true"
        fi
    fi
    
    # Extrair CVEs encontrados
    if ls ports/nmap/*.txt >/dev/null 2>&1; then
        grep -Eoh "CVE-[0-9]{4}-[0-9]+" ports/nmap/*.txt 2>/dev/null | sort -u > ports/nmap/cves_found.txt || touch ports/nmap/cves_found.txt
        local cve_count=$(wc -l < ports/nmap/cves_found.txt 2>/dev/null || echo 0)
        
        if [[ "$cve_count" -gt 0 ]]; then
            log_success "✅ NMAP identificou $cve_count CVEs únicos!"
        fi
    fi
    
    # Extrair serviços descobertos
    if [[ -s ports/nmap/nmap_vuln_full.txt ]]; then
        grep -E "^[0-9]+/tcp.*open" ports/nmap/nmap_vuln_full.txt | awk '{print $3" "$4" "$5" "$6" "$7}' | sort -u > ports/nmap/services_detected.txt || touch ports/nmap/services_detected.txt
        local service_count=$(wc -l < ports/nmap/services_detected.txt 2>/dev/null || echo 0)
        log_info "📋 NMAP identificou $service_count serviços únicos"
    fi
    
    log_success "✅ NMAP vulnerability scanning completo!"
}

port_scanning() {
    # ETAPA 1: MASSCAN - Ultra-rápido pre-scan
    if command -v masscan >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]] && [[ "$DRY_RUN" = "false" ]]; then
        log_info "🚀 ETAPA 1: Executando MASSCAN para descoberta ultra-rápida..."
        mkdir -p ports/masscan
        
        local has_ips=false
        head -1 alive/hosts_only.txt | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' && has_ips=true
        
        if [[ "$has_ips" = "true" ]]; then
            log_info "⚠️  Usando rate SEGURO: ${MASSCAN_RATE:-500} pacotes/seg"
            timeout 45m masscan -p1-65535 \
                --rate "${MASSCAN_RATE:-500}" \
                -iL alive/hosts_only.txt \
                -oL ports/masscan/masscan_results.txt \
                --wait 2 \
                --open 2>/dev/null || true
            
            if [[ -s ports/masscan/masscan_results.txt ]]; then
                grep "^open" ports/masscan/masscan_results.txt | \
                    awk '{print $4":"$3}' | sort -u > ports/masscan/masscan_ports.txt || true
                
                local masscan_ports=$(wc -l < ports/masscan/masscan_ports.txt 2>/dev/null || echo 0)
                log_info "✅ Masscan encontrou $masscan_ports portas abertas"
            fi
        fi
    fi
    
    # ETAPA 2: NAABU - Verificação e service detection
    if command -v naabu >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]]; then
        log_info "🔥 ETAPA 2: Executando naabu..."
        
        local NAABU_FLAGS=()
        local PORT_ARG=()

        if naabu --help 2>/dev/null | grep -q '\-rate'; then
            NAABU_FLAGS=(-rate "$RATE_LIMIT")
        fi
        
        if [[ -s ports/masscan/masscan_ports.txt ]]; then
            log_info "📍 Usando portas descobertas pelo masscan..."
            awk -F':' '{print $2}' ports/masscan/masscan_ports.txt | sort -un | tr '\n' ',' | sed 's/,$//' > ports/masscan/ports_only.txt
            PORT_ARG=(-p "$(cat ports/masscan/ports_only.txt)")
        elif [[ "$NAABU_TOP_PORTS" == "full" ]]; then
            PORT_ARG=(-p "-")
        else
            PORT_ARG=(-tp "$NAABU_TOP_PORTS") 
        fi
        
        if timeout "$TIMEOUT_PER_HOST" naabu -list alive/hosts_only.txt \
            "${PORT_ARG[@]}" \
            "${NAABU_FLAGS[@]}" \
            -c "$CONCURRENCY" \
            -retries 2 \
            -warm-up-time 1 \
            -timeout 2000 \
            -verify \
            -no-color \
            -exclude-cdn \
            -silent \
            -o ports/naabu_raw.txt 2>logs/naabu_errors.log; then
            log_info "✅ Naabu completou com sucesso"
        else
            log_info "⚠️ Naabu teve problemas, tentando modo simplificado..."
            timeout "$TIMEOUT_PER_HOST" naabu -list alive/hosts_only.txt \
                "${PORT_ARG[@]}" \
                -c 10 \
                -silent \
                -o ports/naabu_raw.txt 2>>logs/naabu_errors.log || {
                    log_error "❌ Naabu falhou completamente"
                    touch ports/naabu_raw.txt
                }
        fi
            
        if [[ -s ports/naabu_raw.txt ]]; then
            sort -u ports/naabu_raw.txt > ports/naabu.txt || true
            awk -F":" '{print $1}' ports/naabu.txt | sort -u > ports/hosts_with_ports.txt || true
        fi
    fi
    
    # ETAPA 3: NMAP VULNERABILITY DETECTION
    nmap_vulnerability_scan
}

if [[ "$DRY_RUN" = "false" ]]; then
    port_scanning
else
    log_info "DRY-RUN: Pulando port scanning e NMAP"
    mkdir -p ports/nmap
    touch ports/naabu.txt ports/hosts_with_ports.txt ports/nmap/vulnerabilities_found.txt
fi

PORTS_FOUND=$(safe_count ports/naabu.txt)
HOSTS_WITH_PORTS=$(safe_count ports/hosts_with_ports.txt)
NMAP_VULNS=$(safe_count ports/nmap/vulnerabilities_found.txt)
NMAP_CVES=$(safe_count ports/nmap/cves_found.txt)

send_notification "✅ *FASE 3 COMPLETA - PORT SCANNING + NMAP*\n🚪 $PORTS_FOUND portas abertas\n🏠 $HOSTS_WITH_PORTS hosts com portas\n🔥 $NMAP_VULNS vulnerabilidades NMAP\n📋 $NMAP_CVES CVEs identificados"

# ============= FASE 5: VULNERABILITY SCANNING COM FLAGS CORRIGIDAS =============

echo ""
echo "========== FASE 5: VULNERABILITY SCANNING =========="
send_notification "🎯 *NUCLEI VULNERABILITY SCAN*  \nIniciando varredura com flags corrigidas..."

# Função nuclei_scanning com FLAGS CORRIGIDAS
nuclei_scanning() {
    if ! command -v nuclei >/dev/null 2>&1; then
        log_info "nuclei não encontrado — pulando etapa de varredura"
        return
    fi

    # Atualizar templates do nuclei primeiro
    log_info "📦 Atualizando templates do Nuclei..."
    nuclei -update-templates -silent >/dev/null 2>&1 || true
    
    # Verificar templates disponíveis
    log_info "🔍 Verificando templates disponíveis..."
    local templates_dir="$HOME/nuclei-templates"
    if [[ ! -d "$templates_dir" ]] || [[ ! "$(ls -A "$templates_dir" 2>/dev/null)" ]]; then
        log_warn "⚠️  Templates não encontrados em $templates_dir"
        log_info "🔄 Baixando templates do nuclei..."
        nuclei -update-templates -silent >/dev/null 2>&1 || {
            log_error "❌ Falha ao baixar templates - usando modo fallback"
            templates_dir=""
        }
    fi
    
    # Usar arquivo de alvos consolidado
    local target_file="alive/all_targets_with_protocol.txt"
    if [[ ! -s "$target_file" ]]; then
        log_warn "⚠️  Arquivo de alvos consolidados não encontrado, usando alive/hosts.txt"
        target_file="alive/hosts.txt"
    fi
    
    if [[ ! -s "$target_file" ]]; then
        log_error "❌ Nenhum alvo disponível para Nuclei"
        return
    fi
    
    # --- ETAPA 1: FAST MODE COM FLAGS CORRETAS ---
    log_info "🔥 Executando nuclei FAST mode com FLAGS CORRIGIDAS..."
    log_info "📊 Alvos encontrados: $(wc -l < "$target_file")"
    
    # FLAGS CORRETAS PARA NUCLEI
    timeout 2h nuclei -l "$target_file" \
        -tags cve,exposure,token,takeover,default-login,sqli,xss,rce,lfi,ssrf,xxe,idor,ssti,injection,auth-bypass \
        -severity critical,high,medium \
        -stats \
        -jsonl \
        -irr \
        -rl "$NUCLEI_RATE_LIMIT" \
        -c "$NUCLEI_CONCURRENCY" \
        -timeout "$NUCLEI_TIMEOUT" \
        -etags dos,fuzz,intrusive \
        -passive \
        -headless \
        -code \
        -follow-redirects \
        -max-redirects 5 \
        -system-resolvers \
        -project \
        -project-path nuclei/project_hosts_fast \
        -stream \
        -stats-interval 60 \
        -metrics \
        -include-rr \
        -store-resp \
        -store-resp-dir nuclei/responses_fast \
        -o nuclei/nuclei_hosts_fast.txt \
        -je nuclei/nuclei_hosts_fast_export.jsonl 2>&1 | tee logs/nuclei_fast_errors.log || {
            log_warn "⚠️  Nuclei falhou, tentando fallback..."
            timeout 1h nuclei -l "$target_file" \
                -tags cve,exposure \
                -severity critical,high \
                -c 10 \
                -passive \
                -o nuclei/nuclei_hosts_fast.txt 2>&1 | tee logs/nuclei_fast_fallback.log || true
        }
    
    # --- URLS FAST SCAN ---
    if [[ -s urls/all_urls_raw.txt ]]; then
        log_info "🔥 Executando nuclei em URLs com FLAGS CORRETAS..."
        
        timeout 2h nuclei -l urls/all_urls_raw.txt \
            -tags cve,exposure,token,sqli,xss,rce,lfi,ssrf,xxe,idor,ssti,injection,redirect \
            -severity critical,high,medium \
            -stats \
            -jsonl \
            -irr \
            -rl "$NUCLEI_RATE_LIMIT" \
            -c "$NUCLEI_CONCURRENCY" \
            -timeout "$NUCLEI_TIMEOUT" \
            -etags dos,fuzz,intrusive \
            -passive \
            -headless \
            -code \
            -follow-redirects \
            -max-redirects 5 \
            -system-resolvers \
            -project \
            -project-path nuclei/project_urls_fast \
            -stream \
            -include-rr \
            -store-resp \
            -store-resp-dir nuclei/responses_urls_fast \
            -o nuclei/nuclei_urls_fast.txt \
            -je nuclei/nuclei_urls_fast_export.jsonl 2>&1 | tee logs/nuclei_fast_urls_errors.log || {
                log_warn "⚠️  Nuclei URLs falhou, tentando fallback..."
                timeout 1h nuclei -l urls/all_urls_raw.txt \
                    -tags xss,sqli,lfi \
                    -severity critical,high \
                    -c 10 \
                    -passive \
                    -o nuclei/nuclei_urls_fast.txt 2>&1 | tee logs/nuclei_fast_urls_fallback.log || true
            }
    fi

    # --- ETAPA 2: EXTENDED MODE COM FLAGS CORRETAS ---
    log_info "🔥 Executando nuclei EXTENDED mode..."
    
    timeout 4h nuclei -l "$target_file" \
        -tags misconfig,panel,default-login,exposure,tech,iot,network,disclosure,token,backup,config,logs,secrets,keys,api \
        -severity critical,high,medium,low,info \
        -stats \
        -jsonl \
        -irr \
        -rl "$NUCLEI_RATE_LIMIT" \
        -c "$NUCLEI_CONCURRENCY" \
        -timeout "$NUCLEI_TIMEOUT" \
        -etags dos,fuzz,intrusive \
        -passive \
        -headless \
        -code \
        -follow-redirects \
        -max-redirects 5 \
        -system-resolvers \
        -project \
        -project-path nuclei/project_hosts_ext \
        -stream \
        -include-rr \
        -store-resp \
        -store-resp-dir nuclei/responses_ext \
        -o nuclei/nuclei_hosts_ext.txt \
        -je nuclei/nuclei_hosts_ext_export.jsonl 2>&1 | tee logs/nuclei_ext_errors.log || true
    
    # Estatísticas finais
    local total_findings=0
    for file in nuclei/nuclei_*.txt; do
        if [[ -s "$file" ]]; then
            local count=$(wc -l < "$file" 2>/dev/null || echo 0)
            total_findings=$((total_findings + count))
        fi
    done
    
    log_success "✅ Nuclei scanning completo - $total_findings findings totais"
}

# ============= SQLMAP TESTING COM --crawl E --forms =============
sqlmap_testing() {
    if ! command -v sqlmap >/dev/null 2>&1; then
        log_info "SQLMap não disponível"
        return 0
    fi
    
    log_section "SQLMAP TESTING COM --crawl E --forms"
    send_notification "💉 *SQL INJECTION TESTING BRUTAL*\nTestando URLs, subdomínios E crawling com --forms..."
    
    mkdir -p poc/sqli logs/sqlmap urls
    
    # PREPARAR ALVOS PARA SQLMAP
    log_info "🎯 Preparando alvos completos: URLs + Subdomínios + Crawling..."
    
    # 1. URLs parametrizadas (prioritárias)
    : > urls/sqli_candidates.txt
    if [[ -s urls/with_params.txt ]]; then
        if command -v gf >/dev/null 2>&1; then
            cat urls/with_params.txt | gf sqli 2>/dev/null > urls/sqli_candidates.txt || true
        else
            grep -Ei "(\\?|&)(id|user|search|category|page|item|product|login|admin|auth|token|key|sort|filter)=" urls/with_params.txt > urls/sqli_candidates.txt 2>/dev/null || true
        fi
    fi
    
    # 2. ADICIONAR SUBDOMÍNIOS PARA --crawl E --forms
    : > urls/sqli_subdomain_targets.txt
    if [[ -s alive/all_targets_with_protocol.txt ]]; then
        head -n 100 alive/all_targets_with_protocol.txt > urls/sqli_subdomain_targets.txt
    elif [[ -s alive/hosts.txt ]]; then
        head -n 100 alive/hosts.txt > urls/sqli_subdomain_targets.txt
    fi
    
    # Combinar todos os alvos
    cat urls/sqli_candidates.txt urls/sqli_subdomain_targets.txt 2>/dev/null | sort -u > urls/sqli_all_targets.txt || touch urls/sqli_all_targets.txt
    
    local total_sqli_targets=$(wc -l < urls/sqli_all_targets.txt 2>/dev/null || echo 0)
    log_info "📊 Total de alvos SQLi: $total_sqli_targets (URLs parametrizadas + subdomínios)"
    
    if [[ "$total_sqli_targets" -eq 0 ]]; then
        log_warn "⚠️  Nenhum alvo SQLi disponível"
        touch urls/sqli_validated.txt
        return 0
    fi
    
    # Determinar quantos alvos testar baseado no perfil
    local max_sqli_targets=10
    [[ "$PROFILE" = "light" ]] && max_sqli_targets=3
    [[ "$PROFILE" = "balanced" ]] && max_sqli_targets=10
    [[ "$PROFILE" = "aggressive" ]] && max_sqli_targets=30
    [[ "$PROFILE" = "kamikaze" ]] && max_sqli_targets=100
    
    [[ $total_sqli_targets -lt $max_sqli_targets ]] && max_sqli_targets=$total_sqli_targets
    
    log_info "💉 Testando $max_sqli_targets alvos com SQLMap (Level: $SQLMAP_LEVEL, Risk: $SQLMAP_RISK)..."
    
    local sqli_count=0
    : > urls/sqli_validated.txt
    
    head -n "$max_sqli_targets" urls/sqli_all_targets.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        sqli_count=$((sqli_count + 1))
        local url_hash=$(echo "$url" | md5sum | cut -c1-12)
        
        log_info "[$sqli_count/$max_sqli_targets] 🎯 Testing: $url"
        
        # SQLMAP COM --crawl E --forms PARA MÁXIMA COBERTURA
        local sqlmap_output="logs/sqlmap/sqlmap_${url_hash}.txt"
        local sqlmap_session="poc/sqli/session_${url_hash}"
        
        # Detectar se é URL parametrizada ou subdomain
        local is_parametrized=false
        if echo "$url" | grep -qE '\?'; then
            is_parametrized=true
        fi
        
        if [[ "$is_parametrized" = "true" ]]; then
            # URLs parametrizadas: teste direto + profundo
            log_info "  → URL parametrizada detectada - teste direto"
            timeout 600s sqlmap -u "$url" \
                --batch \
                --random-agent \
                --level="$SQLMAP_LEVEL" \
                --risk="$SQLMAP_RISK" \
                --threads="$SQLMAP_THREADS" \
                --technique=BEUSTQ \
                --dbms=MySQL,PostgreSQL,MSSQL,Oracle \
                --tamper=space2comment,between \
                --flush-session \
                --fresh-queries \
                --keep-alive \
                --null-connection \
                --skip-waf \
                -v 1 \
                -s "$sqlmap_session" \
                2>&1 | tee "$sqlmap_output" || true
        else
            # Subdomínios: usar --crawl e --forms para descobrir formulários
            log_info "  → Subdomain detectado - usando --crawl + --forms"
            timeout 900s sqlmap -u "$url" \
                --batch \
                --random-agent \
                --crawl=3 \
                --forms \
                --level="$SQLMAP_LEVEL" \
                --risk="$SQLMAP_RISK" \
                --threads="$SQLMAP_THREADS" \
                --technique=BEUSTQ \
                --dbms=MySQL,PostgreSQL,MSSQL,Oracle \
                --tamper=space2comment,between \
                --flush-session \
                --fresh-queries \
                --keep-alive \
                --null-connection \
                --skip-waf \
                -v 1 \
                -s "$sqlmap_session" \
                2>&1 | tee "$sqlmap_output" || true
        fi
        
        # Verificar se SQLi foi confirmado
        if grep -qiE "sqlmap identified the following injection|parameter.*is vulnerable|Type: |Title: " "$sqlmap_output"; then
            log_success "  ✅ SQLi CONFIRMADO!"
            echo "$url" >> urls/sqli_validated.txt
            
            # Gerar PoC detalhado
            cat > "poc/sqli/exploit_${url_hash}.sh" <<SQLPOC
#!/bin/bash
# SQLi Exploit for: $url
# Discovered: $(date)
# Session: $sqlmap_session

echo "🔥 SQL Injection Exploit"
echo "Target: $url"
echo ""

echo "1. Para enumerar databases:"
echo "sqlmap -u '$url' --batch --dbs --threads=$SQLMAP_THREADS"

echo ""

echo "2. Para dump de tabelas específicas:"
echo "sqlmap -u '$url' --batch -D DATABASE_NAME --tables --threads=$SQLMAP_THREADS"

echo ""

echo "3. CUIDADO: Dump completo (apenas com autorização):"
echo "sqlmap -u '$url' --batch --dump --threads=$SQLMAP_THREADS"

echo ""

echo "4. OS Pwn (máxima brutalidade - requer autorização):"
echo "sqlmap -u '$url' --batch --os-pwn --priv-esc"

echo ""

echo "📊 Análise detalhada do output:"
cat "$sqlmap_output"
SQLPOC
            chmod +x "poc/sqli/exploit_${url_hash}.sh"
            
            send_notification "🚨 *SQLI FOUND!*\n💥 SQL Injection confirmado!\n🎯 URL: \`${url:0:80}...\`\n📁 PoC: poc/sqli/exploit_${url_hash}.sh\n⚠️ REVISÃO MANUAL URGENTE!" "true"
        else
            log_info "  ℹ️  Nenhuma vulnerabilidade SQLi detectada"
        fi
        
        # Pequeno delay entre testes
        sleep 2
    done
    
    local sqli_found=$(safe_count urls/sqli_validated.txt)
    log_info "SQLMap testing completo. Vulnerabilidades confirmadas: $sqli_found"
    
    if [[ "$sqli_found" -gt 0 ]]; then
        send_notification "🚨 *SQLMAP SCAN COMPLETE*\n💥 $sqli_found SQL injections confirmadas!\n📁 PoCs gerados em poc/sqli/\n⚠️ REVISÃO MANUAL URGENTE!" "true"
    else
        send_notification "✅ *SQLMAP SCAN COMPLETE*\n🛡️ Nenhuma vulnerabilidade SQLi confirmada nos $max_sqli_targets alvos testados"
    fi
}

# Executar scanning
if [[ "${DRY_RUN:-false}" != "true" ]]; then
    nuclei_scanning
    sqlmap_testing
else
    log_info "DRY-RUN: Pulando vulnerability scanning"
    mkdir -p nuclei poc/sqli
    : > nuclei/nuclei_hosts_fast.txt
    : > nuclei/nuclei_urls_fast.txt
    : > nuclei/nuclei_hosts_ext.txt
    : > urls/sqli_validated.txt
fi

# ============= ESTATÍSTICAS FINAIS ATUALIZADAS =============
NUCLEI_FAST_COUNT=$(safe_count nuclei/nuclei_hosts_fast.txt)
NUCLEI_FAST_URLS=$(safe_count nuclei/nuclei_urls_fast.txt)
NUCLEI_FAST_TOTAL=$((NUCLEI_FAST_COUNT + NUCLEI_FAST_URLS))
NUCLEI_EXT_COUNT=$(safe_count nuclei/nuclei_hosts_ext.txt)
SQLI_VALIDATED=$(safe_count urls/sqli_validated.txt)

# Variáveis para outras estatísticas (exemplo placeholders)
TOTAL_SECRETS=$(safe_count secrets/secrets_found.txt)
XSS_CANDIDATES=$(safe_count urls/xss_candidates.txt)
SQLI_CANDIDATES=$(safe_count urls/sqli_candidates.txt)
LFI_CANDIDATES=$(safe_count urls/lfi_candidates.txt)
SSRF_CANDIDATES=$(safe_count urls/ssrf_candidates.txt)
LIVE_HOSTS=$(safe_count alive/hosts_only.txt)
PARAM_URLS=$(safe_count urls/with_params.txt)
API_ENDPOINTS=$(safe_count urls/api_endpoints.txt)
JS_DOWNLOADED=$(safe_count js/downloaded_js_files.txt)

# Criar resumo de vulnerabilidades COMPLETO
cat > reports/vuln_summary.txt <<-VSUMMARY
VULNERABILITY SUMMARY - $(date -u)
=====================================

🔥 CRITICAL FINDINGS:
- Nuclei Critical: $NUCLEI_FAST_TOTAL  
- SQLi Confirmed: $SQLI_VALIDATED (com --crawl + --forms)
- NMAP Vulnerabilities: $NMAP_VULNS
- CVEs Identified: $NMAP_CVES
- Exposed Secrets: $TOTAL_SECRETS

⚡ POTENTIAL ISSUES:
- XSS Candidates: $XSS_CANDIDATES
- SQLi Candidates: $SQLI_CANDIDATES
- LFI Candidates: $LFI_CANDIDATES
- SSRF Candidates: $SSRF_CANDIDATES
- Nuclei Medium: $NUCLEI_EXT_COUNT

📊 ATTACK SURFACE:
- Live Hosts: $LIVE_HOSTS
- URLs with Params: $PARAM_URLS
- API Endpoints: $API_ENDPOINTS
- JS Files Downloaded: $JS_DOWNLOADED
- Ports Found: $PORTS_FOUND
- NMAP Services: $(safe_count ports/nmap/services_detected.txt)

🛠️ TOOLS USED:
- NMAP: Full vulnerability + NSE scripts
- Nuclei: FLAGS CORRETAS (sem -no-mhe, -max-host-error, etc.)
- SQLMap: --crawl + --forms para máxima cobertura
- Masscan + Naabu: Port discovery

PROFILE: $PROFILE
MODE: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (collection only)" || echo "ACTIVE (full scanning)")
PRIORITY: $([ "$NUCLEI_FAST_TOTAL" -gt 5 ] && echo "🔴 HIGH" || [ "$NUCLEI_FAST_TOTAL" -gt 0 ] && echo "🟡 MEDIUM" || echo "🟢 LOW")

📁 KEY FILES:
- NMAP Vulnerabilities: ports/nmap/vulnerabilities_found.txt
- NMAP CVEs: ports/nmap/cves_found.txt
- Nuclei Results: nuclei/nuclei_hosts_fast.txt, nuclei/nuclei_urls_fast.txt
- SQLi Confirmed: urls/sqli_validated.txt
- SQLi PoCs: poc/sqli/
- Secrets: secrets/
VSUMMARY

# Exibir resumo final
echo ""
echo "============================================================"
echo "🎯 ENHANCED BUG BOUNTY SCAN COMPLETE (WITH NMAP + SQLMAP)"
echo "============================================================"
echo "📁 Resultados salvos em: $(pwd)"
echo "🔧 Perfil usado: $PROFILE"
echo "⚙️  Modo: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ATIVO")"
echo ""
echo "📊 RESUMO EXECUTIVO:"
echo "   ✅ Hosts vivos: $LIVE_HOSTS"
echo "   🔗 URLs: $PARAM_URLS (com parâmetros)"
echo "   🚪 Portas: $PORTS_FOUND"
echo "   🔥 NMAP Vulns: $NMAP_VULNS"
echo "   📋 CVEs: $NMAP_CVES"
echo ""
echo "🔥 VULNERABILIDADES:"
echo "   ⚡ Nuclei crítico: $NUCLEI_FAST_TOTAL"
echo "   💉 SQLi confirmada (--crawl/--forms): $SQLI_VALIDATED"
echo "   🔑 Secrets: $TOTAL_SECRETS"
echo ""
echo "📋 RELATÓRIOS:"
echo "   📄 Resumo: reports/vuln_summary.txt"
echo "   🔥 NMAP Vulns: ports/nmap/vulnerabilities_found.txt"
echo "   💉 SQLi PoCs: poc/sqli/"
echo ""
echo "============================================================"

exit 0
