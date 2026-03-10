pipeline {
    agent any

    environment {
        BUILD_IMAGE = 'apagent-build'
        BUILD_CONTAINER = 'apagent-builder'
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

        stage('Build Image') {
            steps {
                sh 'docker build -f Dockerfile.build -t ${BUILD_IMAGE} .'
            }
        }

        stage('Build & Test') {
            steps {
                writeFile file: 'ci-build.sh', text: '''\
#!/bin/sh
set -e

echo "=== Downloading modules ==="
go mod download

echo "=== License Check ==="
go-licenses check ./cmd/... --ignore apagent --disallowed_types=restricted

echo "=== License Collect ==="
go-licenses save ./cmd/... --ignore apagent --save_path=./third_party_licenses --force

echo "=== Test ==="
CGO_ENABLED=1 go test -race ./...

echo "=== Build & Package ==="
rm -f ci-build.sh
# Use --snapshot for non-tagged commits (e.g. develop branch)
if git describe --exact-match --tags HEAD >/dev/null 2>&1; then
    goreleaser release --clean --skip=publish
else
    goreleaser release --clean --snapshot
fi

echo "=== Generate Per-Package Checksums ==="
cd dist
for f in *.deb *.rpm *.tar.gz *.zip; do
    [ -f "$f" ] || continue
    sha256sum "$f" > "${f}.checksum"
    echo "  ${f}.checksum"
done
cd ..

echo "=== Dist Contents ==="
ls -lh dist/
'''
                sh 'chmod +x ci-build.sh'
                sh 'docker rm -f ${BUILD_CONTAINER} 2>/dev/null || true'
                sh 'docker create --name ${BUILD_CONTAINER} -w /build ${BUILD_IMAGE} /build/ci-build.sh'
                sh 'docker cp ${WORKSPACE}/. ${BUILD_CONTAINER}:/build/'
                sh 'docker start -a ${BUILD_CONTAINER}'
                sh 'docker cp ${BUILD_CONTAINER}:/build/dist/. ${WORKSPACE}/dist/'
                sh 'docker rm ${BUILD_CONTAINER}'
            }
        }

        stage('Upload') {
            when {
                anyOf {
                    branch 'main'
                    branch 'master'
                    branch 'develop'
                    buildingTag()
                }
            }
            steps {
                withCredentials([sshUserPrivateKey(credentialsId: 'endpoint1-ssh-key', keyFileVariable: 'SSH_KEY')]) {
                    sh '''
                        scp -i $SSH_KEY -o StrictHostKeyChecking=accept-new \
                            dist/*.deb \
                            dist/*.rpm \
                            dist/*.tar.gz \
                            dist/*.zip \
                            dist/*.checksum \
                            root@endpoint1.ssidhu.io:/data/containers/ak-wildcard-api/download-packages/
                    '''
                }
            }
        }
    }

    post {
        always {
            sh 'docker rm -f ${BUILD_CONTAINER} 2>/dev/null || true'
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
