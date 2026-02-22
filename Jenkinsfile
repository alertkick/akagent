pipeline {
    agent any

    environment {
        GOPATH = "${WORKSPACE}/go"
        PATH = "${GOPATH}/bin:${PATH}"
        GORELEASER_VERSION = '2.5.0'
    }

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                // Fetch all tags for goreleaser version detection
                sh 'git fetch --tags --force'
            }
        }

        stage('Setup Tools') {
            steps {
                sh '''
                    # Install GoReleaser if not present
                    if ! command -v goreleaser &> /dev/null; then
                        curl -sfL https://goreleaser.com/static/run | bash -s -- --version
                        go install github.com/goreleaser/goreleaser/v2@v${GORELEASER_VERSION}
                    fi
                '''
            }
        }

        stage('Test') {
            steps {
                sh 'go test -race ./...'
            }
        }

        stage('Generate eBPF') {
            when {
                changeset "ebpf/bpfgen/**"
            }
            steps {
                sh 'cd ebpf/bpfgen && go generate ./...'
            }
        }

        stage('Build & Package') {
            steps {
                sh 'goreleaser release --clean --skip=publish'
            }
        }

        stage('Upload') {
            when {
                anyOf {
                    branch 'main'
                    branch 'master'
                    buildingTag()
                }
            }
            steps {
                withCredentials([sshUserPrivateKey(credentialsId: 'deploy-ssh-key', keyFileVariable: 'SSH_KEY', usernameVariable: 'SSH_USER')]) {
                    sh '''
                        REMOTE_HOST="${DEPLOY_HOST:-deploy.alertpriority.com}"
                        REMOTE_PATH="${DEPLOY_PATH:-/var/www/repos/agent}"

                        # Upload all packages
                        scp -i $SSH_KEY -o StrictHostKeyChecking=no \
                            dist/*.deb \
                            dist/*.rpm \
                            dist/*.tar.gz \
                            dist/*.zip \
                            dist/checksums.txt \
                            ${SSH_USER}@${REMOTE_HOST}:${REMOTE_PATH}/
                    '''
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'dist/**/*', allowEmptyArchive: true
            cleanWs()
        }
        success {
            echo 'Build and packaging completed successfully!'
        }
        failure {
            echo 'Build failed!'
        }
    }
}
