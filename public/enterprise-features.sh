#!/usr/bin/env bash
# Enterprise Features Module - Complementary functions
# To be sourced by main scanner script

# ============= ENTERPRISE FEATURE #6: VULNERABILITY CORRELATION =============
correlate_vulnerabilities() {
    log_info "Correlating vulnerabilities across different tools..."
    
    mkdir -p correlation
    > correlation/chains.txt
    > correlation/high_confidence.txt
    
    # Correlacionar findings de XSS
    if [[ -s urls/gf_xss.txt ]] && [[ -s nuclei/dalfox_results.txt ]]; then
        comm -12 <(sort urls/gf_xss.txt) <(sort nuclei/dalfox_results.txt) > correlation/xss_confirmed_multi.txt
        local xss_correlated=$(wc -l < correlation/xss_confirmed_multi.txt)
        if [[ $xss_correlated -gt 0 ]]; then
            log_info "✅ Found $xss_correlated XSS vulnerabilities confirmed by multiple tools"
            echo "XSS: $xss_correlated confirmed by gf + dalfox" >> correlation/high_confidence.txt
        fi
    fi
    
    # Correlacionar findings de SQLi
    if [[ -s urls/gf_sqli.txt ]] && [[ -s urls/sqli_validated.txt ]]; then
        comm -12 <(sort urls/gf_sqli.txt) <(sort urls/sqli_validated.txt) > correlation/sqli_confirmed_multi.txt
        local sqli_correlated=$(wc -l < correlation/sqli_confirmed_multi.txt)
        if [[ $sqli_correlated -gt 0 ]]; then
            log_info "✅ Found $sqli_correlated SQLi vulnerabilities confirmed by multiple tools"
            echo "SQLi: $sqli_correlated confirmed by gf + sqlmap" >> correlation/high_confidence.txt
        fi
    fi
    
    # Identificar potential exploit chains
    while IFS= read -r url; do
        local has_xss=false
        local has_sqli=false
        local has_redirect=false
        
        grep -q "$url" urls/gf_xss.txt 2>/dev/null && has_xss=true
        grep -q "$url" urls/gf_sqli.txt 2>/dev/null && has_sqli=true
        grep -q "$url" urls/gf_redirect.txt 2>/dev/null && has_redirect=true
        
        if [[ "$has_xss" = "true" ]] && [[ "$has_sqli" = "true" ]]; then
            echo "CHAIN: XSS + SQLi on $url" >> correlation/chains.txt
        fi
        
        if [[ "$has_redirect" = "true" ]] && [[ "$has_xss" = "true" ]]; then
            echo "CHAIN: Open Redirect + XSS on $url" >> correlation/chains.txt
        fi
    done < <(cat urls/with_params.txt 2>/dev/null)
    
    local chains_found=$(wc -l < correlation/chains.txt 2>/dev/null || echo 0)
    if [[ $chains_found -gt 0 ]]; then
        log_info "⚠️  Found $chains_found potential exploit chains!"
        send_discord_notification "⚠️ Exploit Chains" "Found $chains_found potential exploit chains requiring investigation" 16776960 true
    fi
}

# ============= ENTERPRISE FEATURE #7: FALSE POSITIVE FILTERING =============
init_false_positive_patterns() {
    cat > "$FP_PATTERNS_FILE" <<'FPPATTERNS'
example\.com
test\.local
localhost
127\.0\.0\.1
\.css(\?|$)
\.js(\?|$)
\.jpg(\?|$)
\.png(\?|$)
\.gif(\?|$)
\.woff(\?|$)
/static/
/assets/
/_next/
FPPATTERNS
}

is_false_positive() {
    local finding="$1"
    
    if [[ ! -f "$FP_PATTERNS_FILE" ]]; then
        init_false_positive_patterns
    fi
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        if echo "$finding" | grep -qE "$pattern"; then
            return 0  # Is false positive
        fi
    done < "$FP_PATTERNS_FILE"
    
    return 1  # Not a false positive
}

filter_false_positives() {
    local input_file="$1"
    local output_file="$2"
    
    [[ ! -f "$input_file" ]] && touch "$output_file" && return
    
    > "$output_file"
    local filtered_count=0
    
    while IFS= read -r line; do
        if ! is_false_positive "$line"; then
            echo "$line" >> "$output_file"
        else
            ((filtered_count++))
        fi
    done < "$input_file"
    
    log_info "Filtered $filtered_count false positives from $(basename "$input_file")"
}

verify_vulnerability_double_check() {
    local vuln_type="$1"
    local target="$2"
    local confidence="low"
    
    # Verificação dupla para findings críticos
    case "$vuln_type" in
        sqli)
            if timeout 30s sqlmap -u "$target" --batch --level=1 --risk=1 --threads=1 2>&1 | grep -qi "vulnerable"; then
                confidence="high"
            fi
            ;;
        xss)
            if timeout 30s dalfox url "$target" --silence 2>&1 | grep -qi "POC\|VULN"; then
                confidence="high"
            fi
            ;;
    esac
    
    echo "$confidence"
}

# ============= ENTERPRISE FEATURE #8: CVSS SCORING & IMPACT ANALYSIS =============
calculate_cvss_score() {
    local vuln_type="$1"
    local context="$2"
    local score=0.0
    local severity="info"
    
    case "$vuln_type" in
        sqli)
            score=9.0
            severity="critical"
            ;;
        xss_reflected)
            score=6.5
            severity="medium"
            ;;
        xss_stored)
            score=8.0
            severity="high"
            ;;
        ssrf)
            score=7.5
            severity="high"
            ;;
        lfi)
            score=7.0
            severity="high"
            ;;
        secret_exposed)
            if echo "$context" | grep -qi "aws\|stripe\|private"; then
                score=9.5
                severity="critical"
            else
                score=7.0
                severity="high"
            fi
            ;;
        open_redirect)
            score=4.0
            severity="medium"
            ;;
        *)
            score=3.0
            severity="low"
            ;;
    esac
    
    echo "$score|$severity"
}

generate_cvss_report() {
    log_info "Generating CVSS scoring report..."
    
    > "$CVSS_SCORES_FILE"
    echo "[" >> "$CVSS_SCORES_FILE"
    
    # Score SQLi findings
    if [[ -f urls/sqli_validated.txt ]]; then
        while IFS= read -r url; do
            local cvss=$(calculate_cvss_score "sqli" "$url")
            cat >> "$CVSS_SCORES_FILE" <<EOF
  {
    "type": "SQL Injection",
    "target": "$url",
    "cvss_score": "$(echo $cvss | cut -d'|' -f1)",
    "severity": "$(echo $cvss | cut -d'|' -f2)",
    "impact": "Data breach, authentication bypass",
    "remediation": "Use parameterized queries"
  },
EOF
        done < urls/sqli_validated.txt
    fi
    
    # Score secrets
    if [[ -f secrets/aws_keys.txt ]] && [[ -s secrets/aws_keys.txt ]]; then
        local cvss=$(calculate_cvss_score "secret_exposed" "aws")
        cat >> "$CVSS_SCORES_FILE" <<EOF
  {
    "type": "AWS Keys Exposed",
    "count": "$(wc -l < secrets/aws_keys.txt)",
    "cvss_score": "$(echo $cvss | cut -d'|' -f1)",
    "severity": "$(echo $cvss | cut -d'|' -f2)",
    "impact": "Cloud infrastructure compromise",
    "remediation": "Rotate keys immediately, use IAM roles"
  },
EOF
    fi
    
    echo "  {}" >> "$CVSS_SCORES_FILE"
    echo "]" >> "$CVSS_SCORES_FILE"
    
    sed -i 's/},\s*{}/}/' "$CVSS_SCORES_FILE"
    
    log_info "CVSS report generated: $CVSS_SCORES_FILE"
}

# ============= ENTERPRISE FEATURE #10: BUG BOUNTY PLATFORM INTEGRATION =============
export_hackerone_format() {
    log_info "Exporting findings to HackerOne format..."
    
    local output="bugbounty_exports/hackerone_report.md"
    
    cat > "$output" <<'HONE'
# Vulnerability Report

## Summary
Multiple security vulnerabilities discovered during reconnaissance.

## Steps to Reproduce

### SQL Injection Vulnerabilities
HONE
    
    if [[ -f urls/sqli_validated.txt ]] && [[ -s urls/sqli_validated.txt ]]; then
        while IFS= read -r url; do
            cat >> "$output" <<EOF

**URL**: \`$url\`

1. Navigate to: $url
2. Parameter is vulnerable to SQL injection
3. Payload: \`' OR '1'='1\`
4. Impact: Database access, potential data breach

**CVSS Score**: 9.0 (Critical)

EOF
        done < urls/sqli_validated.txt
    fi
    
    cat >> "$output" <<'HONE2'

### Cross-Site Scripting (XSS)
HONE2
    
    if [[ -f nuclei/dalfox_results.txt ]] && [[ -s nuclei/dalfox_results.txt ]]; then
        head -10 nuclei/dalfox_results.txt | while IFS= read -r finding; do
            cat >> "$output" <<EOF

**Finding**: $finding

**CVSS Score**: 6.5 (Medium)

EOF
        done
    fi
    
    cat >> "$output" <<'HONE3'

## Impact
- **Confidentiality**: High
- **Integrity**: High  
- **Availability**: Medium

## Remediation
See individual vulnerability descriptions above.

## Supporting Material/References
- Nuclei scan results
- SQLMap validation logs
- Dalfox confirmation

HONE3
    
    log_info "HackerOne format report: $output"
}

export_bugcrowd_format() {
    log_info "Exporting findings to Bugcrowd format..."
    
    local output="bugbounty_exports/bugcrowd_report.json"
    
    cat > "$output" <<'BCROWD'
{
  "vulnerability_report": {
    "title": "Multiple Security Vulnerabilities",
    "severity": "P1",
    "vulnerability_types": ["SQL Injection", "XSS", "Information Disclosure"],
    "findings": [
BCROWD
    
    # Add SQLi findings
    if [[ -f urls/sqli_validated.txt ]] && [[ -s urls/sqli_validated.txt ]]; then
        local first=true
        while IFS= read -r url; do
            [[ "$first" = "false" ]] && echo "," >> "$output"
            cat >> "$output" <<EOF
      {
        "type": "SQL Injection",
        "url": "$url",
        "severity": "P1",
        "cvss": "9.0"
      }
EOF
            first=false
        done < urls/sqli_validated.txt
    fi
    
    cat >> "$output" <<'BCROWD2'
    ]
  }
}
BCROWD2
    
    log_info "Bugcrowd format report: $output"
}

# ============= ENTERPRISE FEATURE #11: STATISTICAL ATTACK SURFACE ANALYSIS =============
generate_statistics() {
    log_info "Generating statistical analysis..."
    
    local stats_file="reports/statistics.json"
    
    # Technology distribution
    local tech_dist=""
    if [[ -f alive/httpx_parsed.txt ]]; then
        tech_dist=$(grep -oE 'tech:\[.*?\]' alive/httpx_parsed.txt 2>/dev/null | sort | uniq -c | head -10 || echo "")
    fi
    
    # Parameter distribution
    local param_types=""
    if [[ -f urls/with_params.txt ]]; then
        param_types=$(grep -oE '\?[^=]+=' urls/with_params.txt | sort | uniq -c | sort -rn | head -10 || echo "")
    fi
    
    # Vulnerability timeline
    local vuln_timeline=$(find nuclei -type f -name "*.txt" -exec stat -c "%Y %n" {} \; 2>/dev/null | sort -n || echo "")
    
    cat > "$stats_file" <<EOF
{
  "scan_metadata": {
    "start_time": "$(stat -c %Y logs/scanner.log 2>/dev/null || date +%s)",
    "profile": "$PROFILE",
    "total_targets": $(wc -l < scope.txt 2>/dev/null || echo 0)
  },
  "discovery_stats": {
    "subdomains": $(wc -l < subs/all_subs.txt 2>/dev/null || echo 0),
    "live_hosts": $(wc -l < alive/hosts.txt 2>/dev/null || echo 0),
    "urls_collected": $(wc -l < urls/all_urls_raw.txt 2>/dev/null || echo 0),
    "unique_parameters": $(cat urls/with_params.txt 2>/dev/null | grep -oE '\?[^=]+=' | sort -u | wc -l || echo 0)
  },
  "vulnerability_stats": {
    "critical": $(wc -l < nuclei/nuclei_hosts_fast.txt 2>/dev/null || echo 0),
    "high": $(wc -l < nuclei/nuclei_hosts_ext.txt 2>/dev/null || echo 0),
    "sqli_confirmed": $(wc -l < urls/sqli_validated.txt 2>/dev/null || echo 0),
    "xss_confirmed": $(wc -l < nuclei/dalfox_results.txt 2>/dev/null || echo 0),
    "secrets_exposed": $TOTAL_SECRETS
  },
  "efficiency_metrics": {
    "subdomain_expansion_rate": $(echo "scale=2; $(wc -l < subs/all_subs.txt 2>/dev/null || echo 1) / $(wc -l < scope.txt 2>/dev/null || echo 1)" | bc),
    "live_host_rate": $(echo "scale=2; $(wc -l < alive/hosts.txt 2>/dev/null || echo 1) * 100 / $(wc -l < subs/all_subs.txt 2>/dev/null || echo 1)" | bc),
    "vuln_density": $(echo "scale=4; $(wc -l < nuclei/nuclei_hosts_fast.txt 2>/dev/null || echo 0) / $(wc -l < alive/hosts.txt 2>/dev/null || echo 1)" | bc)
  }
}
EOF
    
    log_info "Statistics generated: $stats_file"
}

# ============= ENTERPRISE FEATURE #12: AUTOMATED REVALIDATION =============
queue_for_revalidation() {
    local target="$1"
    local confidence="$2"
    
    if [[ "$confidence" = "low" ]]; then
        echo "$target" >> "$REVALIDATION_QUEUE"
        log_info "Queued for revalidation: $target"
    fi
}

run_revalidation() {
    [[ ! -f "$REVALIDATION_QUEUE" ]] && return
    [[ ! -s "$REVALIDATION_QUEUE" ]] && return
    
    log_info "Running revalidation on low-confidence findings..."
    
    mkdir -p revalidation
    > revalidation/confirmed.txt
    > revalidation/rejected.txt
    
    while IFS= read -r target; do
        log_info "Revalidating: $target"
        
        # Re-test with different approach
        local result=$(verify_vulnerability_double_check "sqli" "$target")
        
        if [[ "$result" = "high" ]]; then
            echo "$target" >> revalidation/confirmed.txt
            log_info "✅ Confirmed on revalidation: $target"
        else
            echo "$target" >> revalidation/rejected.txt
        fi
        
        sleep 2
    done < "$REVALIDATION_QUEUE"
    
    local confirmed=$(wc -l < revalidation/confirmed.txt 2>/dev/null || echo 0)
    log_info "Revalidation complete: $confirmed findings confirmed"
}

# ============= ENTERPRISE FEATURE #14: SCREENSHOT-BASED ANALYSIS =============
analyze_screenshots() {
    [[ ! -d "screenshots" ]] && return
    [[ -z "$(ls -A screenshots 2>/dev/null)" ]] && return
    
    log_info "Analyzing screenshots for vulnerabilities..."
    
    mkdir -p "$SCREENSHOT_ANALYSIS_DIR"
    > "$SCREENSHOT_ANALYSIS_DIR/findings.txt"
    
    if [[ "$OCR_ENABLED" = "true" ]]; then
        find screenshots -type f \( -name "*.png" -o -name "*.jpg" \) | while read -r img; do
            local text=$(tesseract "$img" stdout 2>/dev/null || echo "")
            
            # Detect error messages
            if echo "$text" | grep -qi "error\|exception\|traceback\|debug\|stack trace"; then
                echo "ERROR_DISCLOSURE: $img" >> "$SCREENSHOT_ANALYSIS_DIR/findings.txt"
                log_info "⚠️  Error disclosure detected in screenshot: $img"
            fi
            
            # Detect credentials
            if echo "$text" | grep -qi "password\|api.key\|secret\|token"; then
                echo "CREDENTIAL_EXPOSURE: $img" >> "$SCREENSHOT_ANALYSIS_DIR/findings.txt"
                log_info "⚠️  Potential credential exposure in screenshot: $img"
            fi
        done
        
        local findings=$(wc -l < "$SCREENSHOT_ANALYSIS_DIR/findings.txt" 2>/dev/null || echo 0)
        if [[ $findings -gt 0 ]]; then
            log_info "Screenshot analysis found $findings potential issues"
            send_discord_notification "📸 Screenshot Analysis" "Found $findings potential issues in screenshots" 16776960
        fi
    else
        log_info "OCR not available, skipping screenshot text analysis"
    fi
}

# ============= ENTERPRISE FEATURE #15: CI/CD INTEGRATION =============
export_ci_cd_format() {
    log_info "Generating CI/CD integration outputs..."
    
    # JUnit XML format for CI/CD
    cat > "reports/junit-results.xml" <<'JUNIT'
<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="Security Scan" tests="1" failures="0" errors="0">
JUNIT
    
    local failures=0
    if [[ $(wc -l < urls/sqli_validated.txt 2>/dev/null || echo 0) -gt 0 ]]; then
        ((failures++))
        cat >> "reports/junit-results.xml" <<EOF
    <testcase name="SQL Injection Check" classname="SecurityScan">
      <failure message="SQL Injection vulnerabilities found">
        $(wc -l < urls/sqli_validated.txt) SQL injection vulnerabilities detected
      </failure>
    </testcase>
EOF
    fi
    
    if [[ $TOTAL_SECRETS -gt 0 ]]; then
        ((failures++))
        cat >> "reports/junit-results.xml" <<EOF
    <testcase name="Secrets Check" classname="SecurityScan">
      <failure message="Exposed secrets found">
        $TOTAL_SECRETS exposed secrets detected
      </failure>
    </testcase>
EOF
    fi
    
    cat >> "reports/junit-results.xml" <<'JUNIT2'
  </testsuite>
</testsuites>
JUNIT2
    
    # SARIF format for GitHub Advanced Security
    cat > "reports/results.sarif" <<EOF
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Enterprise Bug Bounty Scanner",
        "version": "2.0"
      }
    },
    "results": []
  }]
}
EOF
    
    log_info "CI/CD outputs generated: junit-results.xml, results.sarif"
}
