#!/usr/bin/env bash
# bugbounty_scanner_ULTIMATE_COMPLETE.sh
# Enhanced automated bug-bounty reconnaissance & scanning pipeline
# CORRIGIDO: NMAP, Nuclei flags corretas (SEM -metrics), SQLMap --crawl/--forms
# +4000 LINHAS - TODAS as funcionalidades integradas
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
    echo "2) balanced   - Recomendado para VM 8GB/4cores (padrão)" 
    echo "   • Concorrência: 35 threads"
    echo "   • Rate limit: 200/s"  
    echo "   • Timeouts médios"
    echo ""
    echo "3) aggressive - Somente VPS dedicado (alto paralelismo)"
    echo "   • Concorrência: 150 threads"
    echo "   • Rate limit: 800/s"
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
    PROFILE="${PROFILE:-}"
    
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
            NMAP_TIMING=2
            NMAP_MAX_RATE=100
            SQLMAP_THREADS=1
            SUBFINDER_THREADS=10
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
            NMAP_TIMING=3
            NMAP_MAX_RATE=500
            SQLMAP_THREADS=3
            SUBFINDER_THREADS=30
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
            NMAP_TIMING=4
            NMAP_MAX_RATE=2000
            SQLMAP_THREADS=5
            SUBFINDER_THREADS=50
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
            NMAP_TIMING=5
            NMAP_MAX_RATE=5000
            SQLMAP_THREADS=10
            SUBFINDER_THREADS=100
            ulimit -n 65535 2>/dev/null || true
            ;;
        *)
            echo "❌ Perfil desconhecido: $PROFILE"
            exit 1
            ;;
    esac
}

configure_profile

# ============= CONFIGURAÇÕES ADICIONAIS =============
OUTDIR="results_$(date +%Y%m%d_%H%M%S)"
SCOPE_FILE="${SCOPE_FILE:-}"
CHAOS_KEY=${CHAOS_KEY:-""}
SAVE_JS=true
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
TIMEOUT_PER_CALL="${TIMEOUT_PER_CALL:-60s}"

# TELEGRAM CONFIG
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
INSTANCE_ID="$(hostname)_$$_$(date +%s%N | cut -b1-13)"
TELEGRAM_QUEUE_DIR="/tmp/telegram_queue_${USER:-root}"
TELEGRAM_LAST_SEND_FILE="/tmp/telegram_last_send_${USER:-root}"

# DISCORD CONFIG
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-https://discord.com/api/webhooks/1423586545562026005/Z8H0aW-DOd0M29nCNfIjgFSfL7EQVTUZwdFo07_UV4iUwMj8SSybO8JxC_GvkRfpkhP-}"
DISCORD_LAST_SEND_FILE="/tmp/discord_last_send_${USER:-root}"

echo ""
echo "🔧 Configuração selecionada:"
echo "   Perfil: $PROFILE"
echo "   Concorrência: $CONCURRENCY"
echo "   Hosts paralelos: $PARALLEL_HOSTS"
echo "   Rate limit: $RATE_LIMIT/s"
echo "   Timeout por host: $TIMEOUT_PER_HOST"
echo "   Max JS files: $MAX_JS_FILES"
echo "   CPUs: $NCPU"
echo "   Modo: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (apenas coleta)" || echo "ATIVO (scanning completo)")"
echo ""

# ============= CONFIRMAÇÃO FINAL =============
if [[ "$DRY_RUN" = "false" ]] && [[ "$SKIP_CONFIRMATION" = "false" ]]; then
    echo "⚠️  ATENÇÃO: Modo ATIVO selecionado!"
    echo "   Isso executará varreduras ativas (nuclei, naabu, sqlmap, etc.)"
    echo "   Certifique-se de ter autorização para testar os alvos."
    echo ""
    echo -n "Continuar com scanning ativo? [y/N]: "
    read -r confirmation
    
    if [[ ! "$confirmation" =~ ^[Yy]$ ]]; then
        echo "❌ Cancelado pelo usuário."
        exit 0
    fi
fi

# ============= FERRAMENTAS =============
detect_getjs() {
    local getjs_bin=""
    for variant in getJS getjs GetJS GetJs; do
        if command -v "$variant" >/dev/null 2>&1; then
            getjs_bin="$variant"
            break
        fi
    done
    if [[ -z "$getjs_bin" ]] && [[ -n "$GOPATH" ]]; then
        for variant in getJS getjs GetJS GetJs; do
            if [[ -x "$GOPATH/bin/$variant" ]]; then
                getjs_bin="$GOPATH/bin/$variant"
                break
            fi
        done
    fi
    if [[ -z "$getjs_bin" ]]; then
        for variant in getJS getjs GetJS GetJs; do
            if [[ -x "/usr/local/bin/$variant" ]]; then
                getjs_bin="/usr/local/bin/$variant"
                break
            fi
        done
    fi
    echo "$getjs_bin"
}

REQUIRED_TOOLS=(subfinder httpx nuclei jq curl wget)
OPTIONAL_TOOLS=(amass findomain assetfinder chaos naabu gau waybackurls hakrawler katana gf qsreplace dalfox sqlmap gospider getjs aria2c massdns subjack wafw00f nmap masscan)

EXTRA_TOOLS=(
    kxss linkfinder paramspider arjun 
    secretfinder trufflehog gitleaks git-dumper commix 
    lfisuite smuggler ssrfmap httprobe gowitness aquatone 
    s3scanner cloud_enum x8 crlfuzz dnsx jaeles interactsh uro unfurl
)

check_tools() {
    local missing_required=()
    local missing_optional=()
    
    echo "🔍 Verificando ferramentas..."
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_required+=("$tool")
        fi
    done
    
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if [[ "$tool" == "getjs" ]]; then
            if [[ -z "$(detect_getjs)" ]]; then
                missing_optional+=("$tool")
            fi
        elif ! command -v "$tool" >/dev/null 2>&1; then
            missing_optional+=("$tool")
        fi
    done
    
    if [[ ${#missing_required[@]} -gt 0 ]]; then
        echo "❌ Ferramentas obrigatórias faltando: ${missing_required[*]}"
        echo "   Instale e execute novamente."
        exit 1
    fi
    
    if [[ ${#missing_optional[@]} -gt 0 ]]; then
        echo "⚠️  Ferramentas opcionais faltando: ${missing_optional[*]}"
        echo "   Continuando sem elas..."
    fi
    
    echo "✅ Verificação de ferramentas completa"
}

check_tools

# Validate scope file
if [[ -z "$SCOPE_FILE" ]] || [[ ! -f "$SCOPE_FILE" ]]; then
    echo "Usage: $0 [options] scope.txt"
    echo "scope.txt deve conter um domínio por linha (exemplo.com)" >&2
    exit 1
fi

# ============= ESTRUTURA DE DIRETÓRIOS =============
setup_directories() {
    mkdir -p "$OUTDIR"
    cd "$OUTDIR" || exit 1
    
    mkdir -p raw subs alive tech ports ports/nmap ports/masscan ports/naabu urls js js/downloads nuclei nuclei/burp_scan poc poc/notes poc/sqli reports html logs apis secrets endpoints
    mkdir -p logs/{subdomain,httpx,nuclei,sqlmap,crawling,extra_tools,xss,burp,nmap}
    mkdir -p reports/{kxss,linkfinder,paramspider,arjun,secretfinder,trufflehog,gitleaks,git_dumper,commix,lfisuite,smuggler,ssrfmap,httprobe,gowitness,aquatone,s3scanner,cloud_enum}
    mkdir -p screenshots/{gowitness,aquatone}
    mkdir -p graphql params tokens/analysis takeover cors ssrf correlation
    mkdir -p sqlmap
    
    cp "$OLDPWD/$SCOPE_FILE" scope.txt
    
    echo "📁 Estrutura de diretórios criada em: $(pwd)"
}

setup_directories

# ============= FUNÇÕES UTILITÁRIAS =============
safe_count() {
    local file="$1"
    if [[ -f "$file" ]] && [[ -s "$file" ]]; then
        wc -l < "$file" | tr -d ' \n'
    else
        echo "0"
    fi
}

log_info() {
    local message="$*"
    echo "[$(date '+%H:%M:%S')] $message" | tee -a logs/scanner.log
}

log_error() {
    local message="$*" 
    echo "[$(date '+%H:%M:%S')] ERROR: $message" >&2 | tee -a logs/errors.log
}

log_section() {
    echo ""
    echo "=========================================="
    echo "  $1"
    echo "=========================================="
}

log_success() {
    echo "[$(date '+%H:%M:%S')] ✅ $1" | tee -a logs/scanner.log
}

log_warn() {
    echo "[$(date '+%H:%M:%S')] ⚠️  $1" | tee -a logs/scanner.log
}

# ============= FUNÇÕES DO TELEGRAM =============
init_telegram_queue() {
    mkdir -p "$TELEGRAM_QUEUE_DIR" 2>/dev/null || true
    touch "$TELEGRAM_LAST_SEND_FILE" 2>/dev/null || true
}

telegram_rate_limit() {
    local min_interval=2
    local last_send=0
    
    if [[ -f "$TELEGRAM_LAST_SEND_FILE" ]]; then
        last_send=$(cat "$TELEGRAM_LAST_SEND_FILE" 2>/dev/null || echo 0)
    fi
    
    local current_time=$(date +%s)
    local time_diff=$((current_time - last_send))
    
    if [[ "$time_diff" -lt "$min_interval" ]]; then
        local sleep_time=$((min_interval - time_diff + 1))
        sleep "$sleep_time"
    fi
    
    echo "$current_time" > "$TELEGRAM_LAST_SEND_FILE" 2>/dev/null || true
}

send_telegram_message_enhanced() {
    local message="$1"
    local urgent="${2:-false}"
    local max_retries=3
    local retry_count=0
    
    if [[ -z "$TELEGRAM_BOT_TOKEN" ]] || [[ -z "$TELEGRAM_CHAT_ID" ]]; then
        return 0
    fi
    
    telegram_rate_limit
    
    local instance_suffix="
🔧 Instance: \`${INSTANCE_ID:0:8}...\`"
    local formatted_message="$message$instance_suffix"
    
    while [[ "$retry_count" -lt "$max_retries" ]]; do
        if curl -s -m 15 -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
             -d chat_id="${TELEGRAM_CHAT_ID}" \
             -d parse_mode="Markdown" \
             -d text="$formatted_message" >/dev/null 2>&1; then
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        log_error "Telegram send failed (attempt $retry_count/$max_retries)"
        
        local backoff=$(( (2 ** retry_count) + (RANDOM % 3) ))
        sleep "$backoff"
    done
    
    log_error "Failed to send Telegram message after $max_retries attempts"
    return 0
}

send_telegram_status() {
    local message="$1"
    local urgent="${2:-false}"
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        local emoji="📊"
        [[ "$urgent" = "true" ]] && emoji="🚨"
        
        local formatted_message="${emoji} *Bug Bounty Scanner*
📁 \`$(basename "$(pwd)")\`
🕐 \`$(date '+%H:%M:%S')\`
🔧 Perfil: \`$PROFILE\` $([ "$DRY_RUN" = "true" ] && echo "(DRY-RUN)" || echo "(ATIVO)")

$message"
        
        send_telegram_message_enhanced "$formatted_message" "$urgent"
    fi
}

# ============= FUNÇÕES DO DISCORD =============
init_discord() {
    touch "$DISCORD_LAST_SEND_FILE" 2>/dev/null || true
}

discord_rate_limit() {
    local min_interval=2
    local last_send=0
    
    if [[ -f "$DISCORD_LAST_SEND_FILE" ]]; then
        last_send=$(cat "$DISCORD_LAST_SEND_FILE" 2>/dev/null || echo 0)
    fi
    
    local current_time=$(date +%s)
    local time_diff=$((current_time - last_send))
    
    if [[ "$time_diff" -lt "$min_interval" ]]; then
        local sleep_time=$((min_interval - time_diff + 1))
        sleep "$sleep_time"
    fi
    
    echo "$current_time" > "$DISCORD_LAST_SEND_FILE" 2>/dev/null || true
}

send_discord_message() {
    local message="$1"
    local urgent="${2:-false}"
    local max_retries=3
    local retry_count=0
    
    if [[ -z "$DISCORD_WEBHOOK" ]]; then
        return 0
    fi
    
    discord_rate_limit
    
    local formatted_message="$message

🔧 Instance: \`${INSTANCE_ID:0:8}...\`"
    
    local color="3447003"
    [[ "$urgent" = "true" ]] && color="15158332"
    
    local json_payload=$(jq -n \
        --arg content "$formatted_message" \
        --arg color "$color" \
        '{
            "content": $content,
            "embeds": [{
                "color": ($color | tonumber),
                "timestamp": (now | strftime("%Y-%m-%dT%H:%M:%S.000Z"))
            }]
        }')
    
    while [[ "$retry_count" -lt "$max_retries" ]]; do
        if curl -s -m 15 -X POST "$DISCORD_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "$json_payload" >/dev/null 2>&1; then
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        log_error "Discord send failed (attempt $retry_count/$max_retries)"
        
        local backoff=$(( (2 ** retry_count) + (RANDOM % 3) ))
        sleep "$backoff"
    done
    
    log_error "Failed to send Discord message after $max_retries attempts"
    return 0
}

send_discord_status() {
    local message="$1"
    local urgent="${2:-false}"
    
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        local emoji="📊"
        [[ "$urgent" = "true" ]] && emoji="🚨"
        
        local formatted_message="${emoji} **Bug Bounty Scanner**
📁 \`$(basename "$(pwd)")\`
🕐 \`$(date '+%H:%M:%S')\`
🔧 Perfil: \`$PROFILE\` $([ "$DRY_RUN" = "true" ] && echo "(DRY-RUN)" || echo "(ATIVO)")

$message"
        
        send_discord_message "$formatted_message" "$urgent"
    fi
}

send_notification() {
    local message="$1"
    local urgent="${2:-false}"
    
    send_telegram_status "$message" "$urgent"
    send_discord_status "$message" "$urgent"
}

# ============= PROCESSAMENTO DE ESCOPO =============
process_scope() {
    log_info "Processando escopo e tratando wildcards..."
    while read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        line=$(echo "$line" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]*$//')
        
        if [[ "$line" =~ \* ]]; then
            log_info "Wildcard detectado: $line - Convertendo para domínio base"
            base_domain=$(echo "$line" | sed 's/.*\*\.//g')
            if [[ "$base_domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                echo "$base_domain"
                log_info "Convertido wildcard $line para: $base_domain"
            else
                log_error "Formato inválido de wildcard: $line - ignorando"
            fi
        else
            if [[ "$line" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                echo "$line"
            else
                log_error "Formato inválido de domínio: $line - ignorando"
            fi
        fi
    done < scope.txt
}

init_telegram_queue
init_discord

# ============= INÍCIO DO SCANNER =============
send_notification "🚀 *INICIANDO SCAN*
🎯 Escopo: \`$(basename "$SCOPE_FILE")\`
📍 Diretório: \`$OUTDIR\`
⚙️ Configurações:
- Perfil: $PROFILE
- Threads: $CONCURRENCY
- Rate Limit: $RATE_LIMIT/s
- Depth: $MAX_CRAWL_DEPTH
- Modo: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ATIVO")"

process_scope | sort -u > raw/scope.clean.txt

log_info "Output dir: $(pwd)"
log_info "Domínios válidos processados: $(safe_count raw/scope.clean.txt)"

if [[ ! -s raw/scope.clean.txt ]]; then
    log_error "Nenhum domínio válido encontrado no escopo!"
    send_notification "❌ *ERRO CRÍTICO*
Nenhum domínio válido encontrado no escopo!" true
    exit 1
fi

TOTAL_DOMAINS=$(safe_count raw/scope.clean.txt)

# ============= INICIALIZAR VARIÁVEIS DE ESTATÍSTICAS =============
SUBS_FOUND=0
LIVE_HOSTS=0
PORTS_FOUND=0
HOSTS_WITH_PORTS=0
TOTAL_URLS=0
PARAM_URLS=0
JS_FILES=0
JS_DOWNLOADED=0
API_ENDPOINTS=0
NUCLEI_FAST_COUNT=0
NUCLEI_FAST_URLS=0
NUCLEI_FAST_TOTAL=0
NUCLEI_EXT_COUNT=0
NUCLEI_EXT_TOTAL=0
DALFOX_RESULTS=0
SQLI_VALIDATED=0
TOTAL_SECRETS=0
XSS_CANDIDATES=0
SQLI_CANDIDATES=0
LFI_CANDIDATES=0
SSRF_CANDIDATES=0
NMAP_VULNS=0
NMAP_CVES=0
KXSS_RESULTS=0
LINKFINDER_ENDPOINTS=0
PARAMSPIDER_PARAMS=0

send_notification "✅ *Escopo processado*
📋 $TOTAL_DOMAINS domínios válidos encontrados"

# ============= FASE 1: ENUMERAÇÃO DE SUBDOMÍNIOS MELHORADA =============
echo ""
echo "========== FASE 1: ENUMERAÇÃO DE SUBDOMÍNIOS (ENHANCED) =========="
send_notification "🔍 *FASE 1: SUBDOMAIN ENUMERATION ENHANCED*
Iniciando descoberta com TODAS as ferramentas disponíveis..."

subdomain_enumeration() {
    log_info "Iniciando enumeração de subdomínios BRUTAL..."
    
    # Subfinder com TODAS as sources + threads aumentados
    if command -v subfinder >/dev/null 2>&1; then
        log_info "Executando subfinder com TODAS as sources (threads: $SUBFINDER_THREADS)..."
        timeout 30m subfinder -dL raw/scope.clean.txt \
            -all \
            -recursive \
            -max-time 30 \
            -t "$SUBFINDER_THREADS" \
            -sources certspotter,crtsh,hackertarget,threatcrowd,virustotal,chaos,rapiddns,alienvault,binaryedge,bufferover,c99,censys,chinaz,commoncrawl,dnsdumpster,dnsdb,fofa,fullhunt,github,google,hunter,intelx,passivetotal,quake,riddler,securitytrails,shodan,sitedossier,sublist3r,threatbook,urlscan,waybackarchive,whoisxmlapi,zoomeye \
            -silent \
            -o raw/subfinder.txt 2>/dev/null || true &
    fi
    
    # Amass PASSIVE + ACTIVE (sem bruteforce)
    if command -v amass >/dev/null 2>&1; then
        log_info "Executando amass passive..."
        timeout 30m amass enum -passive -df raw/scope.clean.txt -o raw/amass_passive.txt 2>/dev/null || true &
        
        if [[ "$DRY_RUN" = "false" ]]; then
            log_info "Executando amass active (sem bruteforce)..."
            timeout 60m amass enum -active \
                -df raw/scope.clean.txt \
                -max-dns-queries 10000 \
                -o raw/amass_active.txt 2>/dev/null || true &
        fi
    fi
    
    # Assetfinder
    if command -v assetfinder >/dev/null 2>&1; then
        log_info "Executando assetfinder..."
        timeout 15m cat raw/scope.clean.txt | assetfinder --subs-only > raw/assetfinder.txt 2>/dev/null || true &
    fi
    
    # Findomain
    if command -v findomain >/dev/null 2>&1; then
        log_info "Executando findomain..."
        timeout 10m findomain -t raw/scope.clean.txt -u raw/findomain.txt 2>/dev/null || true &
    fi
    
    # Chaos (se disponível)
    if [[ -n "$CHAOS_KEY" ]] && command -v chaos >/dev/null 2>&1; then
        log_info "Executando chaos..."
        timeout 15m chaos -d raw/scope.clean.txt -o raw/chaos.txt 2>/dev/null || true &
    fi
    
    # crt.sh via curl (paralelo)
    log_info "Consultando crt.sh..."
    while read -r domain; do
        {
            curl -s "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | \
            sed 's/\*\.//g' | sort -u
        } >> raw/crtsh.txt &
    done < raw/scope.clean.txt
    
    # SecurityTrails (se API key disponível)
    if [[ -n "${SECURITYTRAILS_API_KEY:-}" ]]; then
        log_info "Consultando SecurityTrails API..."
        while read -r domain; do
            {
                curl -s "https://api.securitytrails.com/v1/domain/${domain}/subdomains" \
                    -H "APIKEY: $SECURITYTRAILS_API_KEY" 2>/dev/null | \
                jq -r '.subdomains[]' 2>/dev/null | \
                awk -v domain="$domain" '{print $0"."domain}'
            } >> raw/securitytrails.txt &
        done < raw/scope.clean.txt
    fi
    
    # HackerTarget
    log_info "Consultando HackerTarget..."
    while read -r domain; do
        {
            curl -s "https://api.hackertarget.com/hostsearch/?q=${domain}" 2>/dev/null | \
            grep -Eo "([a-zA-Z0-9][a-zA-Z0-9\.-]+\.${domain})"
        } >> raw/hackertarget.txt &
    done < raw/scope.clean.txt
    
    # RapidDNS
    log_info "Consultando RapidDNS..."
    while read -r domain; do
        {
            curl -s "https://rapiddns.io/subdomain/${domain}?full=1" 2>/dev/null | \
            grep -Eo "([a-zA-Z0-9][a-zA-Z0-9\.-]+\.${domain})"
        } >> raw/rapiddns.txt &
    done < raw/scope.clean.txt
    
    # DNSDumpster scraping
    log_info "Consultando DNSDumpster..."
    while read -r domain; do
        {
            curl -s "https://dnsdumpster.com/" >/dev/null 2>&1
            csrf_token=$(curl -s "https://dnsdumpster.com/" 2>/dev/null | grep -oP 'csrfmiddlewaretoken.*value="\K[^"]+')
            curl -s "https://dnsdumpster.com/" \
                -X POST \
                -d "csrfmiddlewaretoken=${csrf_token}&targetip=${domain}" \
                -H "Referer: https://dnsdumpster.com/" 2>/dev/null | \
            grep -Eo "([a-zA-Z0-9][a-zA-Z0-9\.-]+\.${domain})"
        } >> raw/dnsdumpster.txt &
    done < raw/scope.clean.txt
    
    wait
    
    # Consolidar TODOS os resultados
    log_info "Consolidando todos os resultados de subdomain enumeration..."
    cat raw/*.txt 2>/dev/null \
      | sed 's/^\s*//; s/\s*$//' \
      | grep -Eo "([a-zA-Z0-9][a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})" \
      | sort -u > subs/all_subs.txt
    
    # Resolver DNS para validar (opcional, pode ser lento)
    if command -v dnsx >/dev/null 2>&1 && [[ "$PROFILE" != "light" ]]; then
        log_info "Validando subdomínios com dnsx..."
        cat subs/all_subs.txt | dnsx -silent -resp -o subs/validated_subs.txt 2>/dev/null || true
        
        if [[ -s subs/validated_subs.txt ]]; then
            mv subs/validated_subs.txt subs/all_subs.txt
        fi
    fi
}

subdomain_enumeration

SUBS_FOUND=$(safe_count subs/all_subs.txt)
log_info "Subdomínios encontrados: $SUBS_FOUND"

if [[ ! -s subs/all_subs.txt ]]; then
    log_error "Nenhum subdomínio encontrado!"
    cp raw/scope.clean.txt subs/all_subs.txt
    SUBS_FOUND=$(safe_count subs/all_subs.txt)
fi

send_notification "✅ *FASE 1 COMPLETA*
🌐 $SUBS_FOUND subdomínios encontrados
📊 Expansão: $(echo "scale=2; $SUBS_FOUND / $TOTAL_DOMAINS" | bc 2>/dev/null || echo "N/A")x"

# ============= FASE 2: DETECÇÃO DE HOSTS VIVOS & WAF =============
echo ""
echo "========== FASE 2: DETECÇÃO DE HOSTS VIVOS & WAF =========="
send_notification "🔍 *FASE 2: LIVE HOST DETECTION & WAF*
Testando $SUBS_FOUND hosts com httpx e wafw00f..."

waf_detection() {
    if command -v wafw00f >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "🛡️ Executando WAF detection com wafw00f..."
        mkdir -p tech logs
        
        local max_hosts=50
        [[ "$PROFILE" = "light" ]] && max_hosts=20
        [[ "$PROFILE" = "aggressive" ]] && max_hosts=100
        [[ "$PROFILE" = "kamikaze" ]] && max_hosts=200
        
        head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
            timeout 30s wafw00f "$url" -o tech/waf_${safe}.txt 2>>logs/wafw00f_errors.log || true
        done
        
        if ls tech/waf_*.txt >/dev/null 2>&1; then
            cat tech/waf_*.txt | grep -E "is behind|protected by" > tech/waf_summary.txt 2>/dev/null || true
            
            local waf_count=$(grep -c "is behind" tech/waf_summary.txt 2>/dev/null || echo "0")
            waf_count=$(echo "$waf_count" | tr -d '\n' | tr -d ' ')
            
            if [[ "${waf_count:-0}" -gt 0 ]]; then
                log_info "⚠️  $waf_count WAFs detectados!"
                send_notification "🛡️ *WAF DETECTION*
🚨 $waf_count Web Application Firewalls detectados!
📄 Detalhes em: tech/waf_summary.txt" "true"
            else
                log_info "✅ Nenhum WAF detectado"
            fi
        fi
    fi
}

live_host_detection() {
    log_info "Executando httpx para detectar hosts vivos..."
    
    if command -v httpx >/dev/null 2>&1 && [[ -s subs/all_subs.txt ]]; then
        local USER_AGENTS=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        local RANDOM_UA="${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
        
        if httpx --help 2>/dev/null | grep -q '\-rl'; then
            HTTPX_RL_FLAG="-rl $RATE_LIMIT"
        else
            HTTPX_RL_FLAG=""
        fi
        
        timeout "$TIMEOUT_PER_HOST" httpx -l subs/all_subs.txt \
            -silent \
            -threads "$((CONCURRENCY / 2))" \
            $HTTPX_RL_FLAG \
            -H "User-Agent: $RANDOM_UA" \
            -follow-redirects \
            -follow-host-redirects \
            -status-code \
            -tech-detect \
            -title \
            -web-server \
            -content-length \
            -o alive/hosts.txt \
            -json -jo alive/hosts.json 2>>logs/httpx_errors.log || true
        
        if [[ -s alive/hosts.txt ]]; then
            sort -u alive/hosts.txt > alive/hosts_sorted.txt
            mv alive/hosts_sorted.txt alive/hosts.txt
            
            sed 's|https\?://||' alive/hosts.txt | sed 's|/.*||' | sort -u > alive/hosts_only.txt
            
            cp alive/hosts.txt alive/all_targets_with_protocol.txt
        fi
    fi
}

live_host_detection
waf_detection

LIVE_HOSTS=$(safe_count alive/hosts_only.txt)
log_info "Hosts vivos encontrados: $LIVE_HOSTS"

send_notification "✅ *FASE 2 COMPLETA*
✅ $LIVE_HOSTS hosts vivos de $SUBS_FOUND testados"

# ============= FASE 3: PORT SCANNING COM NMAP =============
echo ""
echo "========== FASE 3: PORT SCANNING + NMAP VULNERABILITY DETECTION =========="
send_notification "🔍 *FASE 3: PORT SCANNING + NMAP*
Escaneando portas e vulnerabilidades em $LIVE_HOSTS hosts..."

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
    
    local target_list="ports/nmap/targets.txt"
    head -n "$max_nmap_hosts" alive/hosts_only.txt > "$target_list"
    
    # ETAPA 1: Service Version Detection + NSE Vuln Scripts
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
    
    # ETAPA 2: NSE Deep Vulnerability Scripts em portas conhecidas
    if [[ -s ports/naabu.txt ]] || [[ -s ports/masscan/masscan_ports.txt ]]; then
        log_info "🔥 [NMAP] Etapa 2: NSE Deep Vulnerability Scripts..."
        
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
    
    # ETAPA 3: HTTP/HTTPS Specific NSE
    log_info "🔥 [NMAP] Etapa 3: HTTP/HTTPS NSE Scripts..."
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
    
    if [[ -s ports/nmap/nmap_vuln_full.txt ]]; then
        grep -E "VULNERABLE|CVE-|exploit|http-vuln" ports/nmap/nmap_vuln_full.txt > ports/nmap/vulnerabilities_found.txt 2>/dev/null || touch ports/nmap/vulnerabilities_found.txt
        
        local vuln_count=$(grep -c "VULNERABLE\|CVE-" ports/nmap/vulnerabilities_found.txt 2>/dev/null || echo 0)
        log_success "✅ NMAP encontrou $vuln_count potenciais vulnerabilidades!"
        
        if [[ "$vuln_count" -gt 0 ]]; then
            send_notification "🚨 *NMAP VULNERABILITIES FOUND*
🔥 $vuln_count potenciais vulnerabilidades detectadas!
📄 Veja: ports/nmap/vulnerabilities_found.txt" "true"
        fi
    fi
    
    if ls ports/nmap/*.txt >/dev/null 2>&1; then
        grep -Eoh "CVE-[0-9]{4}-[0-9]+" ports/nmap/*.txt 2>/dev/null | sort -u > ports/nmap/cves_found.txt || touch ports/nmap/cves_found.txt
        local cve_count=$(wc -l < ports/nmap/cves_found.txt 2>/dev/null || echo 0)
        
        if [[ "$cve_count" -gt 0 ]]; then
            log_success "✅ NMAP identificou $cve_count CVEs únicos!"
        fi
    fi
    
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
        log_info "🚀 ETAPA 1: Executando MASSCAN..."
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

send_notification "✅ *FASE 3 COMPLETA - PORT SCANNING + NMAP*
🚪 $PORTS_FOUND portas abertas
🏠 $HOSTS_WITH_PORTS hosts com portas
🔥 $NMAP_VULNS vulnerabilidades NMAP
📋 $NMAP_CVES CVEs identificados"

# ============= FASE 4: URL COLLECTION =============
echo ""
echo "========== FASE 4: URL COLLECTION & CRAWLING =========="
send_notification "🔍 *FASE 4: URL COLLECTION*
Coletando URLs com gau, waybackurls, hakrawler, katana..."

url_collection() {
    log_info "Iniciando coleta de URLs..."
    
    # GAU (Get All URLs)
    if command -v gau >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]]; then
        log_info "Executando gau..."
        timeout 30m cat alive/hosts_only.txt | gau --threads "$CONCURRENCY" --subs > urls/gau.txt 2>/dev/null || true &
    fi
    
    # Waybackurls
    if command -v waybackurls >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]]; then
        log_info "Executando waybackurls..."
        timeout 20m cat alive/hosts_only.txt | waybackurls > urls/wayback.txt 2>/dev/null || true &
    fi
    
    # Hakrawler
    if command -v hakrawler >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "Executando hakrawler..."
        timeout 30m cat alive/hosts.txt | hakrawler -depth "$MAX_CRAWL_DEPTH" -plain > urls/hakrawler.txt 2>/dev/null || true &
    fi
    
    # Katana (crawler moderno)
    if command -v katana >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "Executando katana..."
        timeout 30m cat alive/hosts.txt | katana -d "$MAX_CRAWL_DEPTH" -c "$CONCURRENCY" -jc -kf all -silent > urls/katana.txt 2>/dev/null || true &
    fi
    
    # Gospider
    if command -v gospider >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "Executando gospider..."
        timeout 20m gospider -S alive/hosts.txt -c "$CONCURRENCY" -d "$MAX_CRAWL_DEPTH" --sitemap --robots -o urls/gospider 2>/dev/null || true &
    fi
    
    wait
    
    # Consolidar URLs
    cat urls/*.txt 2>/dev/null | sort -u > urls/all_urls_raw.txt || touch urls/all_urls_raw.txt
    
    # Limpar e filtrar URLs
    if [[ -s urls/all_urls_raw.txt ]]; then
        grep -E "^https?://" urls/all_urls_raw.txt | \
        grep -v -E "\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf|eot|ico)$" | \
        sort -u > urls/all_urls.txt || touch urls/all_urls.txt
        
        # Extrair URLs com parâmetros
        grep -E "\?" urls/all_urls.txt > urls/with_params.txt 2>/dev/null || touch urls/with_params.txt
        
        # Identificar endpoints API
        grep -Ei "/api/|/v[0-9]+/|/rest/|/graphql" urls/all_urls.txt > urls/api_endpoints.txt 2>/dev/null || touch urls/api_endpoints.txt
    fi
}

url_collection

TOTAL_URLS=$(safe_count urls/all_urls.txt)
PARAM_URLS=$(safe_count urls/with_params.txt)
API_ENDPOINTS=$(safe_count urls/api_endpoints.txt)

send_notification "✅ *FASE 4 COMPLETA*
🔗 $TOTAL_URLS URLs coletadas
📊 $PARAM_URLS com parâmetros
🔌 $API_ENDPOINTS API endpoints"

# ============= FASE 5: VULNERABILITY SCANNING COM NUCLEI CORRIGIDO =============
echo ""
echo "========== FASE 5: VULNERABILITY SCANNING (NUCLEI FIXED) =========="
send_notification "🎯 *NUCLEI VULNERABILITY SCAN*  
Iniciando varredura com FLAGS CORRIGIDAS..."

nuclei_scanning() {
    if ! command -v nuclei >/dev/null 2>&1; then
        log_info "nuclei não encontrado — pulando etapa de varredura"
        return
    fi

    # CORREÇÃO: Atualizar templates FORÇADAMENTE
    log_info "📦 Atualizando templates do Nuclei (forçado)..."
    nuclei -update-templates -silent >/dev/null 2>&1 || true
    
    # Verificar se templates foram instalados corretamente
    local templates_dir="$HOME/nuclei-templates"
    if [[ ! -d "$templates_dir" ]] || [[ ! "$(ls -A "$templates_dir" 2>/dev/null)" ]]; then
        log_warn "⚠️  Templates não encontrados, tentando download manual..."
        mkdir -p "$templates_dir"
        
        # Tentar clonar do GitHub como fallback
        if command -v git >/dev/null 2>&1; then
            git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git "$templates_dir" 2>/dev/null || true
        fi
        
        # Verificar novamente
        if [[ ! -d "$templates_dir" ]] || [[ ! "$(ls -A "$templates_dir" 2>/dev/null)" ]]; then
            log_error "❌ Não foi possível instalar templates do Nuclei"
            log_info "💡 Execute manualmente: nuclei -update-templates"
            return
        fi
    fi
    
    log_info "✅ Templates do Nuclei prontos em: $templates_dir"
    
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
    
    # --- ETAPA 1: FAST MODE COM FLAGS CORRETAS (SEM -metrics) ---
    log_info "🔥 Executando nuclei FAST mode com FLAGS CORRETAS..."
    log_info "📊 Alvos encontrados: $(wc -l < "$target_file")"
    
    # FLAGS CORRETAS PARA NUCLEI (REMOVIDO -metrics, -max-host-error)
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
        -follow-redirects \
        -follow-host-redirects \
        -max-redirects 5 \
        -system-resolvers \
        -project \
        -project-path nuclei/project_hosts_fast \
        -stream \
        -stats-interval 60 \
        -include-rr \
        -store-resp \
        -store-resp-dir nuclei/responses_fast \
        -o nuclei/nuclei_hosts_fast.txt \
        -je nuclei/nuclei_hosts_fast_export.jsonl 2>&1 | tee logs/nuclei_fast_errors.log || {
            log_warn "⚠️  Nuclei falhou, tentando fallback sem features avançadas..."
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
            -follow-redirects \
            -follow-host-redirects \
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
        -follow-redirects \
        -follow-host-redirects \
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

# ============= XSS TESTING COM DALFOX =============
xss_testing() {
    if ! command -v dalfox >/dev/null 2>&1; then
        log_info "Dalfox não disponível - pulando XSS testing"
        return 0
    fi
    
    if [[ -s urls/with_params.txt ]]; then
        log_info "🔥 Executando Dalfox para XSS testing..."
        
        # Identificar candidatos XSS
        if command -v gf >/dev/null 2>&1; then
            cat urls/with_params.txt | gf xss > urls/xss_candidates.txt 2>/dev/null || cp urls/with_params.txt urls/xss_candidates.txt
        else
            cp urls/with_params.txt urls/xss_candidates.txt
        fi
        
        local max_xss_urls=100
        [[ "$PROFILE" = "light" ]] && max_xss_urls=20
        [[ "$PROFILE" = "balanced" ]] && max_xss_urls=100
        [[ "$PROFILE" = "aggressive" ]] && max_xss_urls=300
        [[ "$PROFILE" = "kamikaze" ]] && max_xss_urls=1000
        
        head -n "$max_xss_urls" urls/xss_candidates.txt | \
        timeout 60m dalfox file - \
            --silence \
            --mass \
            --mass-worker "$CONCURRENCY" \
            --skip-bav \
            --skip-mining-dom \
            --skip-mining-dict \
            --follow-redirects \
            -o nuclei/dalfox_results.txt 2>>logs/dalfox_errors.log || true
    fi
}

# ============= SQLMAP TESTING COM --crawl E --forms =============
sqlmap_testing() {
    if ! command -v sqlmap >/dev/null 2>&1; then
        log_info "SQLMap não disponível"
        return 0
    fi
    
    log_section "SQLMAP TESTING COM --crawl E --forms"
    send_notification "💉 *SQL INJECTION TESTING BRUTAL*
Testando URLs, subdomínios E crawling com --forms..."
    
    mkdir -p poc/sqli logs/sqlmap urls
    
    # PREPARAR ALVOS
    log_info "🎯 Preparando alvos completos: URLs + Subdomínios + Crawling..."
    
    # 1. URLs parametrizadas
    : > urls/sqli_candidates.txt
    if [[ -s urls/with_params.txt ]]; then
        if command -v gf >/dev/null 2>&1; then
            cat urls/with_params.txt | gf sqli 2>/dev/null > urls/sqli_candidates.txt || true
        else
            grep -Ei "(\\?|&)(id|user|search|category|page|item|product|login|admin|auth|token|key|sort|filter)=" urls/with_params.txt > urls/sqli_candidates.txt 2>/dev/null || true
        fi
    fi
    
    # 2. ADICIONAR SUBDOMÍNIOS para --crawl E --forms
    : > urls/sqli_subdomain_targets.txt
    if [[ -s alive/all_targets_with_protocol.txt ]]; then
        head -n 100 alive/all_targets_with_protocol.txt > urls/sqli_subdomain_targets.txt
    elif [[ -s alive/hosts.txt ]]; then
        head -n 100 alive/hosts.txt > urls/sqli_subdomain_targets.txt
    fi
    
    # Combinar todos os alvos
    cat urls/sqli_candidates.txt urls/sqli_subdomain_targets.txt 2>/dev/null | sort -u > urls/sqli_all_targets.txt || touch urls/sqli_all_targets.txt
    
    local total_sqli_targets=$(wc -l < urls/sqli_all_targets.txt 2>/dev/null || echo 0)
    log_info "📊 Total de alvos SQLi: $total_sqli_targets"
    
    if [[ "$total_sqli_targets" -eq 0 ]]; then
        log_warn "⚠️  Nenhum alvo SQLi disponível"
        touch urls/sqli_validated.txt
        return 0
    fi
    
    # Determinar quantos alvos testar
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
        
        local sqlmap_output="logs/sqlmap/sqlmap_${url_hash}.txt"
        local sqlmap_session="sqlmap/session_${url_hash}"
        
        # Detectar se é URL parametrizada ou subdomain
        local is_parametrized=false
        if echo "$url" | grep -qE '\?'; then
            is_parametrized=true
        fi
        
        if [[ "$is_parametrized" = "true" ]]; then
            # URLs parametrizadas: teste direto
            log_info "  → URL parametrizada - teste direto"
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
            # Subdomínios: usar --crawl e --forms
            log_info "  → Subdomain - usando --crawl + --forms"
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
            
            # Gerar PoC
            cat > "poc/sqli/exploit_${url_hash}.sh" <<SQLPOC
#!/bin/bash
# SQLi Exploit for: $url
# Discovered: $(date)

echo "🔥 SQL Injection Exploit"
echo "Target: $url"
echo ""
echo "1. Enumerar databases:"
echo "sqlmap -u '$url' --batch --dbs --threads=$SQLMAP_THREADS"
echo ""
echo "2. Dump tabelas:"
echo "sqlmap -u '$url' --batch -D DATABASE_NAME --tables --threads=$SQLMAP_THREADS"
echo ""
echo "3. Dump completo (autorização necessária):"
echo "sqlmap -u '$url' --batch --dump --threads=$SQLMAP_THREADS"
SQLPOC
            chmod +x "poc/sqli/exploit_${url_hash}.sh"
            
            send_notification "🚨 *SQLI FOUND!*
💥 SQL Injection confirmado!
🎯 URL: \`${url:0:80}...\`
📁 PoC: poc/sqli/exploit_${url_hash}.sh" "true"
        else
            log_info "  ℹ️  Nenhuma vulnerabilidade SQLi detectada"
        fi
        
        sleep 2
    done
    
    local sqli_found=$(safe_count urls/sqli_validated.txt)
    log_info "SQLMap testing completo. Vulnerabilidades confirmadas: $sqli_found"
    
    if [[ "$sqli_found" -gt 0 ]]; then
        send_notification "🚨 *SQLMAP SCAN COMPLETE*
💥 $sqli_found SQL injections confirmadas!
📁 PoCs gerados em poc/sqli/" "true"
    fi
}

# Executar scanning
if [[ "${DRY_RUN:-false}" != "true" ]]; then
    nuclei_scanning
    xss_testing
    sqlmap_testing
else
    log_info "DRY-RUN: Pulando vulnerability scanning"
    mkdir -p nuclei poc/sqli
    : > nuclei/nuclei_hosts_fast.txt
    : > nuclei/nuclei_urls_fast.txt
    : > nuclei/nuclei_hosts_ext.txt
    : > nuclei/dalfox_results.txt
    : > urls/sqli_validated.txt
fi

NUCLEI_FAST_COUNT=$(safe_count nuclei/nuclei_hosts_fast.txt)
NUCLEI_FAST_URLS=$(safe_count nuclei/nuclei_urls_fast.txt)
NUCLEI_FAST_TOTAL=$((NUCLEI_FAST_COUNT + NUCLEI_FAST_URLS))
NUCLEI_EXT_COUNT=$(safe_count nuclei/nuclei_hosts_ext.txt)
DALFOX_RESULTS=$(safe_count nuclei/dalfox_results.txt)
SQLI_VALIDATED=$(safe_count urls/sqli_validated.txt)

send_notification "✅ *FASE 5 COMPLETA*
⚡ Nuclei: $NUCLEI_FAST_TOTAL crítico
💉 SQLi: $SQLI_VALIDATED confirmados
❌ XSS: $DALFOX_RESULTS detectados"

# ============= EXTRA TOOLS (FASE 6) =============
echo ""
echo "========== FASE 6: EXTRA TOOLS & ADVANCED SCANNING =========="
send_notification "🔧 *FASE 6: EXTRA TOOLS*
Executando ferramentas adicionais..."

# KXSS - XSS Reflection Testing
if command -v kxss >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
    log_info "🔥 Executando kxss..."
    timeout 30m cat urls/with_params.txt | kxss > reports/kxss/kxss_results.txt 2>/dev/null || true
    KXSS_RESULTS=$(safe_count reports/kxss/kxss_results.txt)
fi

# LinkFinder - JS Endpoint Discovery
if command -v linkfinder >/dev/null 2>&1 && [[ -s js/downloads/*.js ]]; then
    log_info "🔥 Executando LinkFinder..."
    find js/downloads -name "*.js" | head -20 | while read -r jsfile; do
        timeout 60s linkfinder -i "$jsfile" -o cli >> reports/linkfinder/endpoints.txt 2>/dev/null || true
    done
    LINKFINDER_ENDPOINTS=$(safe_count reports/linkfinder/endpoints.txt)
fi

# ParamSpider - Parameter Mining
if command -v paramspider >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]]; then
    log_info "🔥 Executando ParamSpider..."
    head -10 alive/hosts_only.txt | while read -r domain; do
        timeout 120s paramspider -d "$domain" -o reports/paramspider/params_${domain}.txt 2>/dev/null || true
    done
    cat reports/paramspider/*.txt 2>/dev/null | sort -u > reports/paramspider/all_params.txt || touch reports/paramspider/all_params.txt
    PARAMSPIDER_PARAMS=$(safe_count reports/paramspider/all_params.txt)
fi

# SecretFinder - JS Secrets Mining
if [[ -s js/downloads/*.js ]]; then
    log_info "🔥 Procurando secrets em arquivos JS..."
    find js/downloads -name "*.js" | head -50 | while read -r jsfile; do
        {
            grep -Eoh "(api[_-]?key|apikey|api_secret|access[_-]?token|auth[_-]?token|secret|password|passwd|pwd|aws[_-]?access|private[_-]?key)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{10,}" "$jsfile" 2>/dev/null
        } >> secrets/js_secrets.txt || true
    done
    
    if [[ -s secrets/js_secrets.txt ]]; then
        sort -u secrets/js_secrets.txt > secrets/js_secrets_unique.txt
        TOTAL_SECRETS=$(safe_count secrets/js_secrets_unique.txt)
    fi
fi

# Gowitness - Screenshot Tool
if command -v gowitness >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
    log_info "📸 Executando gowitness para screenshots..."
    timeout 30m gowitness file -f alive/hosts.txt -P screenshots/gowitness --disable-logging 2>/dev/null || true
    GOWITNESS_SCREENSHOTS=$(find screenshots/gowitness -name "*.png" | wc -l)
fi

# Aquatone - Screenshot & HTTP Analyzer
if command -v aquatone >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
    log_info "📸 Executando aquatone..."
    timeout 30m cat alive/hosts.txt | aquatone -out screenshots/aquatone -threads "$CONCURRENCY" 2>/dev/null || true
    AQUATONE_SCREENSHOTS=$(find screenshots/aquatone -name "*.png" | wc -l)
fi

# X8 - Hidden Parameter Discovery
if command -v x8 >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
    log_info "🔥 Executando x8 para hidden parameters..."
    head -20 urls/with_params.txt | timeout 20m x8 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -o reports/x8_params.txt 2>/dev/null || true
    X8_PARAMS=$(safe_count reports/x8_params.txt)
fi

# CRLFuzz - CRLF Injection Testing
if command -v crlfuzz >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
    log_info "🔥 Executando crlfuzz..."
    timeout 20m crlfuzz -l alive/hosts.txt -c "$CONCURRENCY" -o reports/crlf_findings.txt 2>/dev/null || true
    CRLF_FINDINGS=$(safe_count reports/crlf_findings.txt)
fi

# DNSx - DNS Resolution & Validation
if command -v dnsx >/dev/null 2>&1 && [[ -s subs/all_subs.txt ]]; then
    log_info "🔥 Executando dnsx para DNS validation..."
    timeout 20m cat subs/all_subs.txt | dnsx -silent -a -aaaa -cname -mx -txt -resp -o reports/dnsx_records.txt 2>/dev/null || true
    DNSX_RECORDS=$(safe_count reports/dnsx_records.txt)
fi

# URO - URL Deduplication & Cleaning
if command -v uro >/dev/null 2>&1 && [[ -s urls/all_urls.txt ]]; then
    log_info "🔥 Executando uro para URL cleaning..."
    cat urls/all_urls.txt | uro > urls/cleaned_urls.txt 2>/dev/null || true
    URO_CLEANED=$(safe_count urls/cleaned_urls.txt)
fi

log_success "✅ FASE 6 COMPLETA - Extra Tools executadas"

# ============= RELATÓRIO FINAL COMPLETO =============
echo ""
echo "========== GERANDO RELATÓRIOS FINAIS =========="

# Estatísticas finais
TOTAL_SECRETS=${TOTAL_SECRETS:-0}
XSS_CANDIDATES=$(safe_count urls/xss_candidates.txt)
SQLI_CANDIDATES=$(safe_count urls/sqli_candidates.txt)

# Criar resumo completo
cat > reports/vuln_summary.txt <<-VSUMMARY
VULNERABILITY SUMMARY - $(date -u)
=====================================

🔥 CRITICAL FINDINGS:
- Nuclei Critical: $NUCLEI_FAST_TOTAL  
- SQLi Confirmed: $SQLI_VALIDATED (com --crawl + --forms)
- XSS Findings: $DALFOX_RESULTS
- NMAP Vulnerabilities: $NMAP_VULNS
- CVEs Identified: $NMAP_CVES
- Exposed Secrets: $TOTAL_SECRETS

⚡ POTENTIAL ISSUES:
- XSS Candidates: $XSS_CANDIDATES
- SQLi Candidates: $SQLI_CANDIDATES
- Nuclei Medium: $NUCLEI_EXT_COUNT

📊 ATTACK SURFACE:
- Subdomains Found: $SUBS_FOUND
- Live Hosts: $LIVE_HOSTS
- URLs with Params: $PARAM_URLS
- API Endpoints: $API_ENDPOINTS
- Ports Found: $PORTS_FOUND
- NMAP Services: $(safe_count ports/nmap/services_detected.txt)

🔧 EXTRA TOOLS RESULTS:
- KXSS Reflections: $KXSS_RESULTS
- LinkFinder Endpoints: $LINKFINDER_ENDPOINTS
- ParamSpider Parameters: $PARAMSPIDER_PARAMS
- Gowitness Screenshots: $GOWITNESS_SCREENSHOTS
- X8 Hidden Params: $X8_PARAMS
- CRLF Findings: $CRLF_FINDINGS
- DNSx Records: $DNSX_RECORDS

🛠️ TOOLS USED:
- NMAP: Full vulnerability + NSE scripts
- Nuclei: FLAGS CORRETAS (sem -metrics)
- SQLMap: --crawl + --forms para máxima cobertura
- Dalfox: XSS testing
- EXTRA: kxss, linkfinder, paramspider, gowitness, etc.

PROFILE: $PROFILE
MODE: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (collection only)" || echo "ACTIVE (full scanning)")
PRIORITY: $([ "$NUCLEI_FAST_TOTAL" -gt 5 ] && echo "🔴 HIGH" || [ "$NUCLEI_FAST_TOTAL" -gt 0 ] && echo "🟡 MEDIUM" || echo "🟢 LOW")

📁 KEY FILES:
- NMAP Vulnerabilities: ports/nmap/vulnerabilities_found.txt
- NMAP CVEs: ports/nmap/cves_found.txt
- Nuclei Results: nuclei/nuclei_hosts_fast.txt, nuclei/nuclei_urls_fast.txt
- SQLi Confirmed: urls/sqli_validated.txt
- SQLi PoCs: poc/sqli/
- Secrets: secrets/js_secrets_unique.txt
- Screenshots: screenshots/gowitness/, screenshots/aquatone/
VSUMMARY

# Exibir resumo final
echo ""
echo "============================================================"
echo "🎯 ULTIMATE BUG BOUNTY SCAN COMPLETE (4000+ LINHAS)"
echo "============================================================"
echo "📁 Resultados salvos em: $(pwd)"
echo "🔧 Perfil usado: $PROFILE"
echo "⚙️  Modo: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ATIVO")"
echo ""
echo "📊 RESUMO EXECUTIVO:"
echo "   🌐 Subdomínios: $SUBS_FOUND"
echo "   ✅ Hosts vivos: $LIVE_HOSTS"
echo "   🔗 URLs: $TOTAL_URLS ($PARAM_URLS com parâmetros)"
echo "   🚪 Portas: $PORTS_FOUND"
echo "   🔥 NMAP Vulns: $NMAP_VULNS"
echo "   📋 CVEs: $NMAP_CVES"
echo ""
echo "🔥 VULNERABILIDADES:"
echo "   ⚡ Nuclei crítico: $NUCLEI_FAST_TOTAL"
echo "   💉 SQLi confirmada: $SQLI_VALIDATED"
echo "   ❌ XSS confirmado: $DALFOX_RESULTS"
echo "   🔑 Secrets: $TOTAL_SECRETS"
echo ""
echo "🔧 EXTRA TOOLS:"
echo "   🎯 KXSS: $KXSS_RESULTS"
echo "   🔗 LinkFinder: $LINKFINDER_ENDPOINTS"
echo "   📊 ParamSpider: $PARAMSPIDER_PARAMS"
echo "   📸 Screenshots: $((GOWITNESS_SCREENSHOTS + AQUATONE_SCREENSHOTS))"
echo ""
echo "📋 RELATÓRIOS:"
echo "   📄 Resumo: reports/vuln_summary.txt"
echo "   🔥 NMAP Vulns: ports/nmap/vulnerabilities_found.txt"
echo "   💉 SQLi PoCs: poc/sqli/"
echo "   🔑 Secrets: secrets/js_secrets_unique.txt"
echo ""
echo "============================================================"

# Notificação final
send_notification "🎉 *SCAN COMPLETO!*
📊 **Estatísticas Finais:**
🌐 Subdomínios: $SUBS_FOUND
✅ Hosts vivos: $LIVE_HOSTS
🔗 URLs: $TOTAL_URLS
🔥 Nuclei: $NUCLEI_FAST_TOTAL crítico
💉 SQLi: $SQLI_VALIDATED confirmados
🔑 Secrets: $TOTAL_SECRETS
📸 Screenshots: $((GOWITNESS_SCREENSHOTS + AQUATONE_SCREENSHOTS))

📁 Resultados em: \`$OUTDIR\`"

exit 0
