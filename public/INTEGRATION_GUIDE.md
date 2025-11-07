# 🚀 Guia de Integração - Funcionalidades Brutais

## Integração Rápida

### 1. Adicionar ao script principal

No arquivo `bugbounty-scanner-ULTIMATE-BRUTAL.sh`, adicione após a linha de EXTRA_TOOLS:

```bash
# Carregar extensões brutais
source "$(dirname "$0")/brutal-extensions.sh" 2>/dev/null || true

# Executar após vulnerability scanning
if [[ "$DRY_RUN" = "false" ]]; then
    log_section "BRUTAL EXTENSIONS"
    
    # Parameter & Directory Fuzzing
    run_ffuf_param_fuzz &
    run_ffuf_dir_fuzz &
    wait
    
    # API Testing
    run_graphql_introspection &
    run_cors_testing &
    wait
    
    # Cloud Enumeration
    run_multicloud_enum
    
    # Additional Tools
    run_meg &
    run_jaeles &
    run_arjun_brutal &
    wait
    
    # Scoring
    run_cvss_scoring
fi
```

### 2. Uso Individual

```bash
# Carregar extensões
source brutal-extensions.sh

# Executar funções específicas
run_ffuf_param_fuzz
run_graphql_introspection
run_cors_testing
run_multicloud_enum
run_cvss_scoring
```

## Funcionalidades Implementadas

✅ Masscan otimizado (até 10k pps)
✅ Subfinder com 33 sources
✅ FFUF parameter & directory fuzzing
✅ GraphQL introspection
✅ CORS testing
✅ Multi-cloud enum (AWS/Azure/GCP)
✅ CVSS auto-scoring
✅ Arjun melhorado
✅ Meg path discovery
✅ Jaeles automated hacking

## Documentação

- `docs/BRUTAL_FEATURES.md` - Documentação completa
- `brutal-extensions.sh` - Código fonte das extensões

## Uso

```bash
./bugbounty-scanner-ULTIMATE-BRUTAL.sh --profile=kamikaze --confirm scope.txt
```
