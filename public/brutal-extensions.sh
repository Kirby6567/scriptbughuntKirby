#!/usr/bin/env bash
# BRUTAL EXTENSIONS - Funcionalidades Adicionais Ultra-Agressivas
# Para integrar com bugbounty-scanner-ULTIMATE-BRUTAL.sh

# ============= FFUF PARAMETER FUZZING BRUTAL =============
run_ffuf_param_fuzz() {
    if [[ ! -s urls/with_params.txt ]]; then
        log_info "⚠️  Nenhuma URL parametrizada - pulando ffuf param fuzzing"
        return 0
    fi
    
    if ! command -v ffuf >/dev/null 2>&1; then
        log_info "⚠️  ffuf não instalado"
        log_info "💡 Instale com: go install github.com/ffuf/ffuf/v2@latest"
        return 0
    fi
    
    log_info "🔥 Executando FFUF Parameter Fuzzing BRUTAL..."
    mkdir -p reports/ffuf logs
    
    # Wordlist gigante de parâmetros
    local param_wordlist="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    if [[ ! -f "$param_wordlist" ]]; then
        param_wordlist="/usr/share/wordlists/dirb/common.txt"
    fi
    
    local max_urls=20
    [[ "$PROFILE" = "aggressive" ]] && max_urls=50
    [[ "$PROFILE" = "kamikaze" ]] && max_urls=100
    
    local count=0
    head -n "$max_urls" urls/with_params.txt | while read -r url; do
        count=$((count + 1))
        safe=$(echo "$url" | md5sum | cut -c1-10)
        log_info "[$count/$max_urls] FFUF Param Fuzzing: $url"
        
        # Testar parâmetros GET
        timeout 300s ffuf -u "${url}&FUZZ=test" \
            -w "$param_wordlist" \
            -mc 200,204,301,302,307,401,403,405,500 \
            -t 100 \
            -rate 500 \
            -timeout 30 \
            -ac \
            -v \
            -o "reports/ffuf/params_${safe}.json" \
            2>>logs/ffuf_errors.log || true
    done
    
    # Consolidar parâmetros encontrados
    if ls reports/ffuf/params_*.json >/dev/null 2>&1; then
        jq -r '.results[] | .input.FUZZ' reports/ffuf/params_*.json 2>/dev/null | \
            sort -u > reports/ffuf/all_hidden_params.txt || true
        local param_count=$(wc -l < reports/ffuf/all_hidden_params.txt 2>/dev/null || echo 0)
        log_success "✅ FFUF encontrou $param_count parâmetros ocultos"
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
    head -n "$max_hosts" alive/hosts.txt | while read -r url; do
        count=$((count + 1))
        safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
        log_info "[$count/$max_hosts] FFUF Directory: $url"
        
        timeout 600s ffuf -u "${url}/FUZZ" \
            -w "$wordlist" \
            -mc 200,204,301,302,307,401,403,405,500 \
            -t 100 \
            -rate 500 \
            -timeout 30 \
            -recursion \
            -recursion-depth 2 \
            -ac \
            -v \
            -o "reports/ffuf/directories/dir_${safe}.json" \
            2>>logs/ffuf_dir_errors.log || true
    done
    
    log_success "✅ FFUF directory bruteforce completo"
}

# ============= GRAPHQL INTROSPECTION =============
run_graphql_introspection() {
    if [[ ! -s apis/api_endpoints.txt ]]; then
        log_info "⚠️  Nenhum endpoint de API - pulando GraphQL introspection"
        return 0
    fi
    
    log_info "🔥 Executando GraphQL Introspection..."
    mkdir -p reports/graphql logs
    
    # Procurar por endpoints GraphQL
    grep -iE "graphql|gql" apis/api_endpoints.txt > reports/graphql/graphql_candidates.txt 2>/dev/null || true
    
    # Se não encontrou, testar endpoints comuns
    if [[ ! -s reports/graphql/graphql_candidates.txt ]]; then
        head -10 alive/hosts.txt | while read -r url; do
            for path in /graphql /api/graphql /v1/graphql /gql /api/gql; do
                echo "${url}${path}" >> reports/graphql/graphql_candidates.txt
            done
        done
    fi
    
    if [[ ! -s reports/graphql/graphql_candidates.txt ]]; then
        log_info "⚠️  Nenhum endpoint GraphQL encontrado"
        return 0
    fi
    
    # Query de introspection
    local introspection_query='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } }"}'
    
    cat reports/graphql/graphql_candidates.txt | while read -r endpoint; do
        safe=$(echo "$endpoint" | sed 's/[^a-zA-Z0-9]/_/g')
        log_info "Testing GraphQL: $endpoint"
        
        # Testar introspection
        timeout 30s curl -X POST "$endpoint" \
            -H "Content-Type: application/json" \
            -H "User-Agent: Mozilla/5.0" \
            -d "$introspection_query" \
            -s -o "reports/graphql/introspection_${safe}.json" 2>/dev/null || true
        
        # Verificar se introspection funcionou
        if [[ -s "reports/graphql/introspection_${safe}.json" ]]; then
            if grep -q "__schema" "reports/graphql/introspection_${safe}.json"; then
                log_success "✅ Introspection habilitado em: $endpoint"
                echo "$endpoint" >> reports/graphql/vulnerable_endpoints.txt
            fi
        fi
    done
    
    if [[ -s reports/graphql/vulnerable_endpoints.txt ]]; then
        local vuln_count=$(wc -l < reports/graphql/vulnerable_endpoints.txt)
        log_success "🎯 $vuln_count endpoints GraphQL com introspection habilitado"
        send_notification "🚨 *GRAPHQL VULNERABILITY*
🎯 $vuln_count endpoints com introspection habilitado!
📄 Veja: reports/graphql/vulnerable_endpoints.txt" "true"
    fi
}

# ============= CORS TESTING BRUTAL =============
run_cors_testing() {
    if [[ ! -s alive/hosts.txt ]]; then
        log_info "⚠️  Nenhum host - pulando CORS testing"
        return 0
    fi
    
    log_info "🔥 Executando CORS Testing BRUTAL..."
    mkdir -p reports/cors logs
    
    # Usar corsy se disponível
    if command -v corsy >/dev/null 2>&1; then
        log_info "▶️  Usando Corsy para testes avançados..."
        timeout 600s corsy -i alive/hosts.txt \
            -t 50 \
            -o reports/cors/corsy_results.json 2>>logs/cors_errors.log || true
    fi
    
    # Testes manuais de CORS
    log_info "▶️  Executando testes manuais de CORS..."
    
    local test_origins=(
        "null"
        "https://evil.com"
        "https://attacker.com"
        "http://localhost"
        "https://trusted-domain.evil.com"
    )
    
    head -20 alive/hosts.txt | while read -r url; do
        safe=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')
        
        for origin in "${test_origins[@]}"; do
            response=$(timeout 10s curl -s -I "$url" \
                -H "Origin: $origin" \
                -H "User-Agent: Mozilla/5.0" \
                2>/dev/null || true)
            
            if echo "$response" | grep -qi "access-control-allow-origin: $origin"; then
                echo "VULNERABLE: $url reflects origin: $origin" >> reports/cors/vulnerable_cors.txt
                log_warn "⚠️  CORS misconfiguration: $url reflects $origin"
            elif echo "$response" | grep -qi "access-control-allow-origin: \*"; then
                echo "VULNERABLE: $url allows wildcard origin" >> reports/cors/vulnerable_cors.txt
                log_warn "⚠️  CORS wildcard: $url allows any origin"
            fi
        done
    done
    
    if [[ -s reports/cors/vulnerable_cors.txt ]]; then
        local cors_count=$(wc -l < reports/cors/vulnerable_cors.txt)
        log_success "🎯 $cors_count CORS misconfigurations encontrados"
        send_notification "🚨 *CORS VULNERABILITY*
🎯 $cors_count CORS misconfigurations!
📄 Veja: reports/cors/vulnerable_cors.txt" "true"
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
    head -n "$max_urls" urls/with_params.txt | while read -r url; do
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
export -f run_jaeles
export -f run_arjun_brutal

log_info "✅ Brutal Extensions carregado - todas as funções disponíveis"
