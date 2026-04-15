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

        stage('Upload to S3') {
            when {
                buildingTag()
            }
            environment {
                TAG_VERSION = "${env.TAG_NAME?.replaceFirst('^v', '') ?: 'snapshot'}"
                S3_BUCKET = 'alertpriority-agent-packages'
                SUPERADMIN_URL = 'http://superadmin.ssidhu.io:3002'
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'aws-s3-packages', usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh '''
                        set -eu
                        AWS_DEFAULT_REGION=us-east-1

                        # Run aws CLI in a container so we don't depend on it being installed
                        # on the Jenkins agent. Bucket policy grants public read on packages/*,
                        # so no per-object ACL needed.
                        AWS_RUN="docker run --rm \
                            -e AWS_ACCESS_KEY_ID \
                            -e AWS_SECRET_ACCESS_KEY \
                            -e AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} \
                            -v ${WORKSPACE}/dist:/dist \
                            amazon/aws-cli"

                        echo "=== Uploading packages to S3 ==="
                        for f in dist/*.deb dist/*.rpm dist/*.tar.gz dist/*.zip dist/*.checksum; do
                            [ -f "$f" ] || continue
                            BASENAME=$(basename "$f")
                            echo "  uploading $BASENAME → s3://${S3_BUCKET}/packages/v${TAG_VERSION}/"
                            $AWS_RUN s3 cp "/dist/${BASENAME}" "s3://${S3_BUCKET}/packages/v${TAG_VERSION}/${BASENAME}"
                        done

                        echo "=== Registering with superadmin ==="
                        # Build JSON payload with file list
                        PACKAGES="["
                        FIRST=true
                        for f in dist/*.deb dist/*.rpm dist/*.tar.gz; do
                            [ -f "$f" ] || continue
                            BASENAME=$(basename "$f")
                            CHECKSUM=""
                            if [ -f "${f}.checksum" ]; then
                                CHECKSUM=$(cat "${f}.checksum" | awk '{print "sha256:"$1}')
                            fi
                            SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)

                            # Detect os/arch/format from filename
                            case "$BASENAME" in
                                *.deb)    FORMAT="deb" ;;
                                *.rpm)    FORMAT="rpm" ;;
                                *.tar.gz) FORMAT="tar.gz" ;;
                                *)        continue ;;
                            esac
                            case "$BASENAME" in
                                *amd64*|*x86_64*) ARCH="amd64" ;;
                                *arm64*|*aarch64*) ARCH="arm64" ;;
                                *) continue ;;
                            esac

                            if [ "$FIRST" = true ]; then FIRST=false; else PACKAGES="$PACKAGES,"; fi
                            PACKAGES="$PACKAGES{\"os\":\"linux\",\"arch\":\"$ARCH\",\"format\":\"$FORMAT\",\"filename\":\"$BASENAME\",\"checksum\":\"$CHECKSUM\",\"size\":$SIZE}"
                        done
                        PACKAGES="$PACKAGES]"

                        PAYLOAD=$(printf '{"version":"%s","tag":"%s","packages":%s}' "$TAG_VERSION" "$TAG_NAME" "$PACKAGES")
                        echo "Payload: $PAYLOAD"
                        curl --fail-with-body -sS --max-time 30 -X POST "${SUPERADMIN_URL}/fleet-api/agent-packages/register" \
                            -H "Content-Type: application/json" \
                            -d "$PAYLOAD"
                        echo
                        echo "=== Done ==="
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
