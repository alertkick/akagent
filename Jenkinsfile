pipeline {
    agent any

    environment {
        GO_VERSION = '1.23.6'
        GORELEASER_VERSION = '2.5.0'
        GOROOT = "${WORKSPACE}/tools/go"
        GOPATH = "${WORKSPACE}/go"
        PATH = "${WORKSPACE}/tools/go/bin:${GOPATH}/bin:${WORKSPACE}/tools/bin:${PATH}"
    }

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout([
                    $class: 'GitSCM',
                    branches: scm.branches,
                    extensions: scm.extensions + [
                        [$class: 'CloneOption', noTags: false, shallow: false],
                        [$class: 'CleanBeforeCheckout']
                    ],
                    userRemoteConfigs: scm.userRemoteConfigs
                ])
            }
        }

        stage('Setup Tools') {
            steps {
                sh '''
                    mkdir -p ${WORKSPACE}/tools/bin

                    # Install Go
                    if [ ! -x "${GOROOT}/bin/go" ]; then
                        curl -sfL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
                        tar -C ${WORKSPACE}/tools -xzf /tmp/go.tar.gz
                        rm -f /tmp/go.tar.gz
                    fi
                    go version

                    # Install GoReleaser
                    if [ ! -x "${WORKSPACE}/tools/bin/goreleaser" ]; then
                        curl -sfL "https://github.com/goreleaser/goreleaser/releases/download/v${GORELEASER_VERSION}/goreleaser_Linux_x86_64.tar.gz" -o /tmp/goreleaser.tar.gz
                        tar -C ${WORKSPACE}/tools/bin -xzf /tmp/goreleaser.tar.gz goreleaser
                        rm -f /tmp/goreleaser.tar.gz
                    fi
                    goreleaser --version

                    # Install go-licenses
                    go install github.com/google/go-licenses@latest
                '''
            }
        }

        stage('License Check') {
            steps {
                sh 'go-licenses check ./... --disallowed_types=restricted'
            }
        }

        stage('License Collect') {
            steps {
                sh 'go-licenses save ./... --save_path=./third_party_licenses --force'
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
                        scp -i $SSH_KEY -o StrictHostKeyChecking=accept-new \
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
