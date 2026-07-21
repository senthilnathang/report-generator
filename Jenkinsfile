pipeline {
    agent {
        docker {
            image 'python:3.12-slim'
            args '-u root'
        }
    }

    tools {
        // Uses Jenkins system tools if configured, otherwise installs in sh blocks
    }

    environment {
        REPORTS_DIR = "reports/ci-${BUILD_NUMBER}"
        SCANNERS = params.SCANNERS
        FAIL_ON = params.FAIL_ON
    }

    parameters {
        string(name: 'SCANNERS', defaultValue: 'trivy,grype', description: 'Comma-separated scanners')
        string(name: 'FAIL_ON', defaultValue: 'high', description: 'Fail threshold: critical, high, medium, low')
        string(name: 'REPOLIST', defaultValue: '', description: 'Space-separated repo URLs (empty = use repolist.txt)')
        booleanParam(name: 'RUN_LICENSE_SCAN', defaultValue: false, description: 'Enable license scanning')
    }

    stages {
        stage('Setup') {
            steps {
                sh '''
                    apt-get update && apt-get install -y --no-install-recommends curl git ca-certificates
                    pip install --no-cache-dir -r requirements.txt
                '''
                sh 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin'
                sh 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin'
                sh '''
                    if [ -n "${SNYK_TOKEN}" ]; then
                        curl -L https://static.snyk.io/cli/latest/snyk-linux -o /usr/local/bin/snyk
                        chmod +x /usr/local/bin/snyk
                        snyk auth ${SNYK_TOKEN}
                    fi
                '''
            }
        }

        stage('Configure') {
            steps {
                sh '''
                    cat > config.yaml << 'CONFEOF'
                    git:
                      tokens:
                        github.com: ''
                        gitlab.com: ''
                    repositories:
                      - url: ${GIT_URL}
                        branch: ${BRANCH_NAME}
                        scan_mode: local
                    CONFEOF
                '''
                script {
                    if (params.REPOLIST?.trim()) {
                        sh "echo '${params.REPOLIST}' | tr ' ' '\\n' > repolist.txt"
                    }
                }
            }
        }

        stage('Vulnerability Scan') {
            steps {
                sh '''
                    SCANNERS_ARG=$(echo ${SCANNERS} | tr ',' ' ')
                    python main.py \
                        --local --sync --history \
                        -s ${SCANNERS_ARG} \
                        -f json html sarif \
                        --fail-on ${FAIL_ON} \
                        -o ${REPORTS_DIR}
                '''
            }
        }

        stage('License Scan') {
            when {
                expression { params.RUN_LICENSE_SCAN }
            }
            steps {
                sh '''
                    python main.py \
                        --local \
                        --license \
                        --license-policy "deny=GPL-3.0,AGPL-3.0" \
                        -o ${REPORTS_DIR}
                '''
            }
        }

        stage('Report') {
            steps {
                sh '''
                    echo "=== Vulnerability Summary ==="
                    python3 -c "
                    import json, glob
                    files = glob.glob('${REPORTS_DIR}/vulnerability_report.json')
                    if files:
                        with open(files[0]) as f:
                            data = json.load(f)
                        crit = sum(r.get('summary',{}).get('CRITICAL',0) for r in data)
                        high = sum(r.get('summary',{}).get('HIGH',0) for r in data)
                        med  = sum(r.get('summary',{}).get('MEDIUM',0) for r in data)
                        low  = sum(r.get('summary',{}).get('LOW',0) for r in data)
                        total = sum(len(r.get('vulnerabilities',[])) for r in data)
                        scanners = set(r.get('scanner','') for r in data)
                        print(f'Scanners: {chr(44).join(sorted(scanners))}')
                        print(f'Critical: {crit} | High: {high} | Medium: {med} | Low: {low} | Total: {total}')
                    else:
                        print('No report found')
                    "
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: "${REPORTS_DIR}/**", fingerprint: true
            junit testResults: "${REPORTS_DIR}/vulnerability_report.json", allowEmptyResults: true
        }
        failure {
            emailext(
                subject: "[FAILED] Vulnerability scan ${env.BUILD_NUMBER} - ${env.JOB_NAME}",
                body: """
                    <h2>Vulnerability scan failed</h2>
                    <p>Pipeline: ${env.BUILD_URL}</p>
                    <p>Branch: ${env.BRANCH_NAME}</p>
                    <p>Threshold: ${params.FAIL_ON}</p>
                    <p>Reports: ${env.BUILD_URL}artifact/${REPORTS_DIR}/</p>
                """,
                mimeType: 'text/html',
                recipientProviders: [requestor(), developers()]
            )
        }
    }
}
