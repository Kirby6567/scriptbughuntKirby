# 📘 Documentação Técnica - Enterprise Bug Bounty Scanner

## Índice

1. [Arquitetura do Sistema](#arquitetura-do-sistema)
2. [Componentes Principais](#componentes-principais)
3. [Fluxo de Execução](#fluxo-de-execução)
4. [Módulos e Funções](#módulos-e-funções)
5. [Configurações Avançadas](#configurações-avançadas)
6. [Integração de Ferramentas](#integração-de-ferramentas)
7. [Performance e Otimização](#performance-e-otimização)
8. [Segurança e Rate Limiting](#segurança-e-rate-limiting)

---

## Arquitetura do Sistema

### Visão Geral

O scanner é construído como um **pipeline sequencial** com **paralelização interna** em cada fase. A arquitetura é modular, permitindo fácil extensão e manutenção.

```
┌─────────────────────────────────────────────────────────────┐
│                    INITIALIZATION                           │
│  • Profile Selection  • Tool Validation  • Setup Dirs       │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                PHASE 1: SUBDOMAIN ENUMERATION               │
│  subfinder │ amass │ assetfinder │ findomain │ crt.sh       │
│  [PARALLEL EXECUTION] → Merge & Deduplicate                 │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│            PHASE 2: LIVE HOST DETECTION & WAF               │
│  httpx (tech detect) │ wafw00f │ CF Bypass                  │
│  [SEQUENTIAL WITH RETRY] → Filter & Validate                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                PHASE 3: PORT SCANNING                       │
│  masscan (discovery) → naabu (verification)                 │
│  [CONDITIONAL EXECUTION] → Service Detection                │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│          PHASE 4: URL & JAVASCRIPT COLLECTION               │
│  gau │ waybackurls │ katana │ gospider │ getJS              │
│  [PARALLEL WITH LIMITS] → Download & Parse                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│            PHASE 5: VULNERABILITY SCANNING                  │
│  nuclei (4 modes) │ dalfox │ sqlmap │ custom tests          │
│  [STAGED EXECUTION] → Validate & Correlate                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                PHASE 6: EXTRA TOOLS                         │
│  40+ specialized tools [GROUPED PARALLEL]                   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              PHASE 7: REPORT GENERATION                     │
│  HTML │ JSON │ Markdown │ Platform Exports                  │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
                [COMPLETE]
```

---

## Componentes Principais

### 1. Sistema de Perfis

```bash
# Estrutura de Dados do Perfil
PROFILE_CONFIG = {
    "concurrency": int,        # Threads paralelos
    "parallel_hosts": int,     # Hosts simultâneos
    "rate_limit": int,         # Requisições/segundo
    "timeout_per_host": str,   # Timeout por host
    "nuclei_flags": str,       # Flags do nuclei
    "max_crawl_depth": int,    # Profundidade de crawling
    "max_js_files": int,       # Limite de arquivos JS
    "ncpu": int,               # CPU cores
    "naabu_top_ports": int,    # Portas para scan
    "sqlmap_level": int,       # Nível de agressividade SQLmap
    "sqlmap_risk": int,        # Risco SQLmap
    "masscan_rate": int        # Rate do masscan
}
```

#### Função: `configure_profile()`

```bash
configure_profile() {
    case "$PROFILE" in
        light)
            CONCURRENCY=8
            RATE_LIMIT=20
            # ... configurações conservadoras
            ;;
        balanced)
            CONCURRENCY=35
            RATE_LIMIT=200
            # ... configurações moderadas
            ;;
        aggressive)
            CONCURRENCY=150
            RATE_LIMIT=800
            # ... configurações máximas
            ;;
    esac
}
```

### 2. Sistema de Logging

```bash
# Níveis de Log
log_info()    # Informação geral
log_error()   # Erros críticos
log_warn()    # Avisos importantes
log_success() # Operações bem-sucedidas

# Arquivos de Log
logs/scanner.log          # Log principal
logs/errors.log          # Apenas erros
logs/subdomain/*.log     # Logs por fase
logs/nuclei_fast.log     # Nuclei fast mode
logs/js_download_errors.log  # Erros de download
```

### 3. Sistema de Notificações

#### Discord Integration

```bash
send_discord_message() {
    local message="$1"
    local urgent="${2:-false}"
    
    # Rate limiting (2s entre mensagens)
    discord_rate_limit
    
    # JSON payload com embed colorido
    local json_payload=$(jq -n \
        --arg content "$message" \
        --arg color "$color" \
        '{
            "content": $content,
            "embeds": [{
                "color": ($color | tonumber),
                "timestamp": (now | strftime("%Y-%m-%dT%H:%M:%S.000Z"))
            }]
        }')
    
    # Retry logic (3 tentativas)
    curl -X POST "$DISCORD_WEBHOOK" \
         -H "Content-Type: application/json" \
         -d "$json_payload"
}
```

#### Telegram Integration

```bash
send_telegram_message_enhanced() {
    local message="$1"
    local urgent="${2:-false}"
    
    # Rate limiting
    telegram_rate_limit
    
    # Markdown formatting
    curl -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
         -d chat_id="${TELEGRAM_CHAT_ID}" \
         -d parse_mode="Markdown" \
         -d text="$formatted_message"
}
```

### 4. Sistema de Checkpointing

```bash
# Estrutura de Checkpoint
checkpoint_file="checkpoints/phase_${PHASE_NAME}.checkpoint"

save_checkpoint() {
    local phase="$1"
    local status="$2"
    echo "${phase}:${status}:$(date +%s)" > "checkpoints/${phase}.checkpoint"
}

load_checkpoint() {
    local phase="$1"
    if [[ -f "checkpoints/${phase}.checkpoint" ]]; then
        read phase status timestamp < "checkpoints/${phase}.checkpoint"
        return 0
    fi
    return 1
}
```

---

## Fluxo de Execução

### Inicialização

```bash
1. Parse command-line arguments
   ├─ --profile=PROFILE
   ├─ --confirm / --dry-run
   ├─ --yes
   └─ --export-json

2. Profile configuration
   ├─ Configure resources (CPU, RAM, threads)
   ├─ Set rate limits
   └─ Initialize timeouts

3. Tool validation
   ├─ Check required tools (subfinder, httpx, nuclei)
   ├─ Check optional tools (40+ ferramentas)
   └─ Report missing dependencies

4. Directory setup
   ├─ Create output directory structure
   ├─ Initialize log files
   └─ Copy scope file

5. Notification initialization
   ├─ Test Discord webhook
   ├─ Test Telegram bot
   └─ Send start notification
```

### Phase 1: Subdomain Enumeration

```bash
subdomain_enumeration() {
    # Execução paralela de múltiplas ferramentas
    subfinder -dL scope.txt -all -silent -o raw/subfinder.txt &
    amass enum -passive -df scope.txt -o raw/amass.txt &
    assetfinder < scope.txt > raw/assetfinder.txt &
    findomain -tL scope.txt -u raw/findomain.txt &
    
    # crt.sh via API
    while read domain; do
        curl -s "https://crt.sh/?q=%.${domain}&output=json" | \
        jq -r '.[].name_value' >> raw/crtsh.txt
    done < scope.txt &
    
    wait  # Aguardar conclusão de todos
    
    # Merge e deduplicação
    cat raw/*.txt | grep -Eo "([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})" | \
    sort -u > subs/all_subs.txt
}
```

**Otimizações**:
- Timeouts individuais (20m para subfinder, 40m para amass)
- Processamento paralelo de todas as ferramentas
- Deduplicação eficiente com `sort -u`
- Validação de formato de domínio com regex

### Phase 2: Live Host Detection

```bash
live_host_detection() {
    # User-Agent rotation
    local USER_AGENTS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605"
        # ... mais UAs
    )
    local RANDOM_UA="${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
    
    # httpx com anti-block headers
    httpx -l subs/all_subs.txt \
          -silent \
          -threads "$((CONCURRENCY / 2))" \
          -tech-detect \
          -status-code \
          -title \
          -ip \
          -H "User-Agent: $RANDOM_UA" \
          -H "X-Forwarded-For: 127.0.0.1" \
          -H "CF-Connecting-IP: 127.0.0.1" \
          -delay 2s \
          -o alive/httpx_results.txt
}
```

**Features**:
- User-Agent aleatório a cada execução
- Headers de bypass de Cloudflare
- Delay entre requisições (anti-rate-limit)
- Tech detection integrado
- Threads reduzidos (50% do total) para estabilidade

### Phase 3: Port Scanning

```bash
port_scanning() {
    # Stage 1: Masscan (ultra-fast discovery)
    masscan -iL ports/ips.txt \
            -p0-65535 \
            --rate "$MASSCAN_RATE" \
            -oG ports/masscan_raw.txt
    
    # Stage 2: Naabu (verification)
    naabu -list alive/hosts.txt \
          -c "$CONCURRENCY" \
          -rate "$RATE_LIMIT" \
          -top-ports "$NAABU_TOP_PORTS" \
          -o ports/naabu_ports.txt
    
    # Merge results
    cat ports/masscan_raw.txt ports/naabu_ports.txt | \
    sort -u > ports/open_ports.txt
}
```

**Estratégia em Duas Fases**:
1. **Masscan**: Discovery rápido de portas abertas
2. **Naabu**: Verificação e serviço detection

### Phase 4: URL Collection

```bash
url_collection() {
    # Archive-based discovery (paralelo)
    (gau --subs --blacklist png,jpg,gif,css < hosts.txt > urls/gau.txt) &
    (cat hosts.txt | waybackurls > urls/wayback.txt) &
    (hakrawler -d 2 < hosts.txt > urls/hakrawler.txt) &
    
    # Active crawling (sequencial para controlar carga)
    katana -list hosts.txt \
           -d "$MAX_CRAWL_DEPTH" \
           -c "$CONCURRENCY" \
           -jc \
           -o urls/katana.txt
    
    wait
    
    # Merge, filter e deduplicate
    cat urls/*.txt | \
    grep -E "https?://" | \
    uro | \
    sort -u > urls/all_urls.txt
}
```

### Phase 5: Vulnerability Scanning

#### Nuclei Multi-Stage

```bash
nuclei_scanning() {
    # Stage 1: Fast Mode (critical only)
    nuclei -l alive/hosts.txt \
           -t ~/nuclei-templates/ \
           -s critical,high \
           -c "$CONCURRENCY" \
           -rate-limit "$RATE_LIMIT" \
           -o nuclei/nuclei_hosts_fast.txt
    
    # Stage 2: Extended Mode (all severities)
    nuclei -l alive/hosts.txt \
           -t ~/nuclei-templates/ \
           -c "$CONCURRENCY" \
           -o nuclei/nuclei_hosts_ext.txt
    
    # Stage 3: Fuzzing Mode
    nuclei -l urls/with_params.txt \
           -t ~/nuclei-templates/fuzzing/ \
           -c "$((CONCURRENCY / 2))" \
           -o nuclei/nuclei_fuzzing.txt
    
    # Stage 4: DOM/JS Mode
    nuclei -l urls/all_urls.txt \
           -t ~/nuclei-templates/javascript/ \
           -headless \
           -c 20 \
           -o nuclei/nuclei_dom.txt
}
```

#### dalfox XSS Testing

```bash
dalfox_scanning() {
    # Custom payloads
    cat urls/gf_xss.txt | head -100 | \
    dalfox pipe \
           --skip-bav \
           --skip-mining-dom \
           --only-poc r \
           --ignore-return 404,403 \
           -w 20 \
           -H "X-Forwarded-For: 127.0.0.1" \
           --custom-payload payloads/xss_custom.txt \
           -o nuclei/dalfox_results.txt
}
```

#### SQLmap Validation

```bash
sqlmap_testing() {
    # Two-stage validation
    while IFS= read -r url; do
        # Stage 1: Quick scan
        sqlmap -u "$url" \
               --batch \
               --level "$SQLMAP_LEVEL" \
               --risk "$SQLMAP_RISK" \
               --threads 5 \
               --timeout 30 \
               --technique=BEUST \
               --random-agent \
               2>/dev/null | tee -a logs/sqlmap.log
        
        # Stage 2: Deep scan if positive
        if grep -q "vulnerable" logs/sqlmap.log; then
            echo "$url" >> urls/sqli_validated.txt
            
            # Extract data (careful!)
            sqlmap -u "$url" \
                   --batch \
                   --dbs \
                   --no-cast \
                   --dump-format=CSV \
                   -o poc/sqli/
        fi
    done < urls/gf_sqli.txt
}
```

### Phase 6: Extra Tools (Grouped Execution)

```bash
run_extra_tools() {
    # Grupo 1: XSS Tools
    (run_kxss) &
    wait
    
    # Grupo 2: Endpoint Discovery
    (run_linkfinder) &
    (run_paramspider) &
    wait
    
    # Grupo 3: Secret Scanners
    (run_secretfinder) &
    (run_trufflehog) &
    (run_gitleaks) &
    wait
    
    # Grupo 4: Exploitation (sequential - invasivo)
    run_git_dumper
    run_commix
    run_lfisuite
    
    # Grupo 5: Advanced Testing
    (run_smuggler) &
    (run_ssrfmap) &
    wait
    
    # Grupo 6: Screenshots
    (run_gowitness) &
    (run_aquatone) &
    wait
    
    # Grupo 7: Cloud
    (run_s3scanner) &
    (run_cloud_enum) &
    wait
}
```

**Estratégia de Agrupamento**:
- Ferramentas similares executam em paralelo
- Ferramentas invasivas executam sequencialmente
- Limites por grupo baseados no perfil

---

## Módulos e Funções

### Advanced Pentester Functions

#### 1. Advanced Parameter Discovery

```bash
advanced_parameter_discovery() {
    # Arjun - Deep mining
    arjun -u "$url" \
          --stable \
          -t $(($CONCURRENCY / 2)) \
          -d 5 \
          --passive
    
    # ParamSpider - Historical
    paramspider -d "$domain" \
                --exclude woff,css,png \
                --level high
    
    # JS Regex Mining
    find js/downloads -name "*.js" | while read jsfile; do
        # Query params: ?param=
        grep -oP '(?<=[\?&])[a-zA-Z0-9_-]+(?==)' "$jsfile"
        
        # JSON keys: "key": value
        grep -oP '"\K[a-zA-Z0-9_-]+(?=":\s*["\[\{])' "$jsfile"
        
        # FormData: formData.append('key', value)
        grep -oP 'FormData.*?\.append\(["\x27]([^"\x27]+)' "$jsfile"
    done | sort -u
}
```

#### 2. GraphQL Introspection

```bash
test_graphql_endpoints() {
    # Identificar endpoints
    grep -iE "graphql" urls/all_urls.txt > apis/graphql/potential.txt
    
    # Introspection query
    while read url; do
        curl -sk "$url" \
             -H "Content-Type: application/json" \
             -d '{"query": "{__schema{types{name,fields{name}}}}"}' \
             -o "apis/graphql/introspection_${safe}.json"
        
        # Validar se retornou schema
        if grep -q "__schema" "apis/graphql/introspection_${safe}.json"; then
            echo "$url - INTROSPECTION ENABLED" >> apis/graphql/vulnerable.txt
        fi
    done < apis/graphql/potential.txt
}
```

#### 3. JWT Token Analysis

```bash
analyze_tokens_advanced() {
    # Extrair JWTs de JS files
    find js/downloads -name "*.js" | while read jsfile; do
        grep -oP 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' "$jsfile"
    done | sort -u > secrets/tokens/jwt_found.txt
    
    # Decode e analisar
    while read token; do
        # Decode header e payload
        echo "$token" | cut -d. -f2 | base64 -d | jq '.' \
        >> secrets/tokens/analysis/jwt_decoded.txt
        
        # Verificar alg: none
        if echo "$token" | cut -d. -f1 | base64 -d | grep -q '"alg":"none"'; then
            echo "$token" >> secrets/tokens/analysis/CRITICAL_no_signature.txt
        fi
    done < secrets/tokens/jwt_found.txt
    
    # Extrair platform-specific tokens
    grep -rhoP 'sk_live_[a-zA-Z0-9]{24,}' js/downloads > secrets/tokens/stripe_keys.txt
    grep -rhoP 'AIza[a-zA-Z0-9_-]{35}' js/downloads > secrets/tokens/google_api_keys.txt
    grep -rhoP 'AKIA[A-Z0-9]{16}' js/downloads > secrets/tokens/aws_keys.txt
}
```

#### 4. CORS Misconfiguration Testing

```bash
test_cors_advanced() {
    local attack_origins=(
        "https://evil.com"
        "null"
        "http://localhost"
        "https://attacker.com"
    )
    
    while read url; do
        for origin in "${attack_origins[@]}"; do
            response=$(curl -sk "$url" \
                           -H "Origin: $origin" \
                           -i)
            
            acao=$(echo "$response" | grep -i "Access-Control-Allow-Origin:")
            acac=$(echo "$response" | grep -i "Access-Control-Allow-Credentials:")
            
            # CRITICAL: Origin reflection + credentials
            if echo "$acao" | grep -q "$origin" && \
               echo "$acac" | grep -qi "true"; then
                echo "CRITICAL: $url reflects origin '$origin' with credentials=true" \
                >> reports/cors/CRITICAL_findings.txt
            fi
        done
    done < alive/hosts.txt
}
```

#### 5. Cloudflare Bypass Techniques

```bash
cloudflare_bypass() {
    # 1. CloudFlair - DNS History Mining
    cloudflair "$domain" >> reports/cf_bypass/cloudflair.txt
    
    # 2. CrimeFlare Database
    curl -s "http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi" \
         -d "cfS=$domain" >> reports/cf_bypass/crimeflare.txt
    
    # 3. DNS History via ViewDNS
    curl -s "https://viewdns.info/iphistory/?domain=$domain" \
    >> reports/cf_bypass/dns_history.txt
    
    # 4. Subdomain bypass (direct access)
    for prefix in origin direct ftp admin dev; do
        dig +short "${prefix}.${domain}" >> reports/cf_bypass/unprotected_subs.txt
    done
    
    # 5. Shodan search
    shodan search "hostname:$domain" >> reports/cf_bypass/shodan.txt
    
    # 6. SSL Certificate lookup
    curl -s "https://crt.sh/?q=%.${domain}&output=json" | \
    jq -r '.[].name_value' >> reports/cf_bypass/ssl_certs.txt
    
    # 7. Wayback Machine CDN history
    curl -s "http://archive.org/wayback/available?url=$domain" | \
    jq -r '.archived_snapshots.closest.url' >> reports/cf_bypass/wayback.txt
}
```

---

## Configurações Avançadas

### Environment Variables

```bash
# Profile Override
export PROFILE="aggressive"

# Rate Limiting
export RATE_LIMIT=500
export CONCURRENCY=100

# Timeouts
export TIMEOUT_PER_HOST="120s"
export TIMEOUT_PER_CALL="90s"

# Nuclei Custom
export NUCLEI_FLAGS_PRESET="-c 150 -rl 800 -timeout 20"
export NUCLEI_FLAGS_EXT_PRESET="-c 80 -rl 400 -timeout 15"

# Notifications
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
export TELEGRAM_BOT_TOKEN="YOUR_TOKEN"
export TELEGRAM_CHAT_ID="YOUR_CHAT_ID"

# API Keys
export CHAOS_KEY="YOUR_CHAOS_API_KEY"

# Features Toggle
export SAVE_JS=true
export DRY_RUN=false
export EXPORT_JSON=true
```

### Profile Customization

Crie seu próprio perfil editando a função `configure_profile()`:

```bash
configure_profile() {
    case "$PROFILE" in
        # ... perfis existentes ...
        
        custom)
            CONCURRENCY=75
            PARALLEL_HOSTS=15
            RATE_LIMIT=400
            TIMEOUT_PER_HOST="120s"
            NUCLEI_FLAGS="-c 75 -rate-limit 400 -timeout 15"
            MAX_CRAWL_DEPTH=5
            MAX_JS_FILES=300
            NCPU=8
            NAABU_TOP_PORTS=500
            SQLMAP_LEVEL=3
            SQLMAP_RISK=2
            MASSCAN_RATE=1200
            ;;
    esac
}
```

---

## Performance e Otimização

### Resource Management

```bash
# Verificar recursos disponíveis
check_system_resources() {
    local mem_available=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    local cpu_count=$(nproc)
    local load_avg=$(uptime | awk -F'load average:' '{ print $2 }' | cut -d, -f1 | tr -d ' ')
    
    log_info "System Resources:"
    log_info "  - Memory Available: ${mem_available}MB"
    log_info "  - CPU Cores: $cpu_count"
    log_info "  - Load Average: $load_avg"
    
    # Ajustar concorrência se carga alta
    if (( $(echo "$load_avg > $cpu_count" | bc -l) )); then
        log_warn "High load detected! Reducing concurrency..."
        CONCURRENCY=$((CONCURRENCY / 2))
        RATE_LIMIT=$((RATE_LIMIT / 2))
    fi
}
```

### Disk I/O Optimization

```bash
# Use tmpfs para arquivos temporários (se disponível)
setup_tmpfs() {
    if [[ -d /dev/shm ]] && [[ $(df -h /dev/shm | tail -1 | awk '{print $4}' | sed 's/G//') -gt 2 ]]; then
        export TMPDIR="/dev/shm/bugbounty_tmp_$$"
        mkdir -p "$TMPDIR"
        log_info "Using tmpfs for temporary files: $TMPDIR"
    fi
}

cleanup_tmpfs() {
    [[ -n "$TMPDIR" ]] && rm -rf "$TMPDIR"
}

trap cleanup_tmpfs EXIT
```

### Network Optimization

```bash
# TCP tuning para high-throughput
optimize_network() {
    if [[ "$PROFILE" == "aggressive" ]]; then
        # Increase file descriptors
        ulimit -n 65535 2>/dev/null || true
        
        # TCP tuning (requires root)
        if [[ $EUID -eq 0 ]]; then
            sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null || true
            sysctl -w net.ipv4.ip_local_port_range="1024 65535" 2>/dev/null || true
            sysctl -w net.core.somaxconn=32768 2>/dev/null || true
        fi
    fi
}
```

---

## Segurança e Rate Limiting

### Adaptive Rate Limiting

```bash
detect_rate_limit_response() {
    local http_code="$1"
    local response_time="$2"
    
    # Rate limit indicators
    if [[ "$http_code" == "429" ]] || [[ "$http_code" == "503" ]]; then
        return 0
    fi
    
    # Slow response (possible throttling)
    if (( $(echo "$response_time > 5.0" | bc -l) )); then
        return 0
    fi
    
    return 1
}

auto_recover_rate_limit() {
    log_warn "Rate limit detected! Backing off..."
    
    # Reduce rate by 50%
    RATE_LIMIT=$((RATE_LIMIT / 2))
    CONCURRENCY=$((CONCURRENCY / 2))
    
    # Exponential backoff
    local backoff_time=$((2 ** retry_count))
    log_info "Sleeping for ${backoff_time}s before retry..."
    sleep "$backoff_time"
    
    # Retry with reduced rate
    retry_count=$((retry_count + 1))
}
```

### WAF Evasion

```bash
# Rotation de User-Agents
get_random_user_agent() {
    local agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    )
    echo "${agents[$RANDOM % ${#agents[@]}]}"
}

# Headers de bypass
get_bypass_headers() {
    cat <<EOF
-H "User-Agent: $(get_random_user_agent)"
-H "X-Forwarded-For: 127.0.0.1"
-H "X-Originating-IP: 127.0.0.1"
-H "X-Remote-IP: 127.0.0.1"
-H "X-Remote-Addr: 127.0.0.1"
-H "CF-Connecting-IP: 127.0.0.1"
-H "True-Client-IP: 127.0.0.1"
-H "X-Forwarded-Host: 127.0.0.1"
EOF
}
```

### Security Validations

```bash
# Validar scope antes de executar
validate_scope() {
    local scope_file="$1"
    
    # Check for private IPs
    if grep -qE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)' "$scope_file"; then
        log_error "Private IP ranges detected in scope!"
        return 1
    fi
    
    # Check for wildcards
    if grep -q '\*\.\*' "$scope_file"; then
        log_error "Overly broad wildcard detected!"
        return 1
    fi
    
    # Validate domain format
    while read domain; do
        if ! [[ "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            log_error "Invalid domain format: $domain"
            return 1
        fi
    done < "$scope_file"
    
    return 0
}

# Dry-run confirmation
confirm_active_scanning() {
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
}
```

---

## API Reference

### Funções Principais

#### `subdomain_enumeration()`
**Descrição**: Enumeração completa de subdomínios usando múltiplas ferramentas  
**Input**: Nenhum (lê de `raw/scope.clean.txt`)  
**Output**: `subs/all_subs.txt`  
**Duração**: 5-20 minutos

#### `live_host_detection()`
**Descrição**: Detecta hosts vivos e tecnologias  
**Input**: `subs/all_subs.txt`  
**Output**: `alive/hosts.txt`, `tech/technologies.txt`  
**Duração**: 2-10 minutos

#### `nuclei_scanning()`
**Descrição**: Scanning de vulnerabilidades com Nuclei  
**Input**: `alive/hosts.txt`, `urls/with_params.txt`  
**Output**: `nuclei/*.txt`  
**Duração**: 30-120 minutos

### Funções Utilitárias

#### `safe_count(file)`
**Descrição**: Conta linhas de arquivo com segurança  
**Returns**: Número de linhas ou "0" se arquivo não existir

#### `log_info(message)`
**Descrição**: Log com timestamp  
**Output**: Console e `logs/scanner.log`

#### `send_notification(message, [urgent])`
**Descrição**: Envia para Discord e Telegram  
**Parameters**: message (string), urgent (boolean)

---

## Exemplos de Customização

### Adicionar Nova Ferramenta

```bash
# 1. Criar função wrapper
run_my_tool() {
    if ! command -v mytool >/dev/null 2>&1; then
        log_warn "mytool não instalado - pulando"
        return 0
    fi
    
    log_info "▶️  Executando mytool..."
    mkdir -p reports/mytool
    
    timeout 300s mytool -i urls/all_urls.txt \
                        -o reports/mytool/results.txt \
                        2>/dev/null || true
    
    log_success "✅ mytool completo"
}

# 2. Adicionar ao pipeline
run_extra_tools() {
    # ... outras ferramentas ...
    
    # Adicionar mytool
    (run_my_tool) &
    wait
}

# 3. Adicionar contagem ao relatório
MYTOOL_RESULTS=$(safe_count reports/mytool/results.txt)
```

### Criar Template de Relatório Customizado

```bash
generate_custom_report() {
    cat > reports/custom_report.html <<-'REPORT'
<!DOCTYPE html>
<html>
<head>
    <title>Custom Scan Report</title>
    <style>
        body { font-family: Arial; }
        .critical { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Scan Results for TARGET_DOMAIN</h1>
    <h2>Critical Findings</h2>
    <ul>
        CRITICAL_FINDINGS_LIST
    </ul>
</body>
</html>
REPORT
    
    # Substituir placeholders
    sed -i "s/TARGET_DOMAIN/$(cat raw/scope.clean.txt | head -1)/g" reports/custom_report.html
    # ... mais substituições ...
}
```

---

## Troubleshooting Avançado

### Debug Mode

```bash
# Habilitar debug completo
set -x  # Ativa trace de comandos
export DEBUG=1

# Log verboso do nuclei
export NUCLEI_FLAGS_PRESET="-v -debug"

# Ver todas as chamadas de curl
alias curl='curl -v'
```

### Análise de Performance

```bash
# Profile de execução com time
time ./bugbounty-scanner-ULTIMATE-FIXED.sh --profile=balanced scope.txt

# Monitorar recursos em tempo real
watch -n 1 'ps aux | grep -E "(subfinder|httpx|nuclei)" | head -20'

# Disk I/O
iostat -x 1

# Network throughput
iftop -i eth0
```

---

**Documentação mantida por**: Kirby656 & AI Assistant  
**Última atualização**: 2025-01-20  
**Versão**: 3.0
