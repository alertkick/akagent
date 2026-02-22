pipeline {
    agent {
        docker {
            image 'goreleaser/goreleaser:v2.5.0'
            args '--entrypoint=""'
        }
    }

    environment {
        GOPATH = "${WORKSPACE}/go"
        PATH = "${GOPATH}/bin:/usr/local/go/bin:${PATH}"
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
