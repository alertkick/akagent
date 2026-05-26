pipeline {
    agent any

    environment {
        // Scope image and container names per-branch + per-build so concurrent
        // develop/main/PR builds don't collide on the host's Docker daemon.
        // disableConcurrentBuilds() below already prevents same-branch overlap.
        BUILD_IMAGE = "akagent-build-${env.BRANCH_NAME}"
        BUILD_CONTAINER = "akagent-builder-${env.BRANCH_NAME}-${env.BUILD_NUMBER}"
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
go-licenses check ./cmd/... --ignore akagent --disallowed_types=restricted

echo "=== License Collect ==="
go-licenses save ./cmd/... --ignore akagent --save_path=./third_party_licenses --force

echo "=== Test ==="
CGO_ENABLED=1 go test -race ./...

echo "=== Build & Package ==="
rm -f ci-build.sh
# Tag builds: goreleaser builds AND publishes a GitHub Release. The
# release: section in .goreleaser.yml points at alertkick/akagent and
# uses GITHUB_TOKEN (passed in via -e on docker create, sourced from
# the github-token-akagent Jenkins credential).
#
# Non-tag builds: --snapshot only, no publish, no token needed.
if git describe --exact-match --tags HEAD >/dev/null 2>&1; then
    goreleaser release --clean
else
    goreleaser release --clean --snapshot
fi

echo "=== Generate Per-Package Checksums ==="
# Used by the S3 + fleet-registration step downstream; GitHub Release
# gets goreleaser's standard checksums.txt instead.
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
                // GITHUB_TOKEN is empty for non-tag builds; goreleaser
                // only consults it during the publish step, which is
                // gated on --snapshot anyway. Loading the credential on
                // every build keeps the Docker create line uniform.
                withCredentials([string(credentialsId: 'github-token-akagent', variable: 'GITHUB_TOKEN')]) {
                    sh 'docker rm -f ${BUILD_CONTAINER} 2>/dev/null || true'
                    sh 'docker create --name ${BUILD_CONTAINER} -w /build -e GITHUB_TOKEN=${GITHUB_TOKEN} ${BUILD_IMAGE} /build/ci-build.sh'
                    sh 'docker cp ${WORKSPACE}/. ${BUILD_CONTAINER}:/build/'
                    sh 'docker start -a ${BUILD_CONTAINER}'
                    sh 'docker cp ${BUILD_CONTAINER}:/build/dist/. ${WORKSPACE}/dist/'
                    sh 'docker rm ${BUILD_CONTAINER}'
                }
            }
        }

        stage('Upload to S3') {
            when {
                buildingTag()
            }
            environment {
                TAG_VERSION = "${env.TAG_NAME?.replaceFirst('^v', '') ?: 'snapshot'}"
                S3_BUCKET = 'alertkick-agent-packages'
                SUPERADMIN_URL = 'http://superadmin.ssidhu.io:3002'
            }
            steps {
                withCredentials([usernamePassword(credentialsId: 'aws-s3-packages', usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh '''
                        set -eu
                        AWS_DEFAULT_REGION=us-east-1
                        UPLOADER=pkg-uploader-${BUILD_NUMBER}

                        # Jenkins runs in Docker against the host daemon, so bind-mounting
                        # ${WORKSPACE}/dist fails (path doesn't exist on host). Use the same
                        # docker create + docker cp pattern as the build stage.
                        docker rm -f ${UPLOADER} 2>/dev/null || true
                        docker run -d --name ${UPLOADER} \
                            -e AWS_ACCESS_KEY_ID \
                            -e AWS_SECRET_ACCESS_KEY \
                            -e AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} \
                            --entrypoint sleep \
                            amazon/aws-cli 3600
                        PAYLOAD_FILE=""
                        cleanup() {
                            docker rm -f ${UPLOADER} 2>/dev/null || true
                            [ -n "$PAYLOAD_FILE" ] && rm -f "$PAYLOAD_FILE"
                        }
                        trap cleanup EXIT

                        docker exec ${UPLOADER} mkdir -p /dist
                        docker cp dist/. ${UPLOADER}:/dist/

                        # upload_one wraps `aws s3 cp` and lazily provisions the bucket on
                        # NoSuchBucket — the slow setup-infra call is skipped on the happy
                        # path. Subsequent files in the loop hit the warm bucket directly.
                        upload_one() {
                            DST="s3://${S3_BUCKET}/packages/v${TAG_VERSION}/$1"
                            ERR=$(docker exec ${UPLOADER} aws s3 cp "/dist/$1" "$DST" 2>&1) && return 0
                            echo "$ERR"
                            case "$ERR" in
                                *NoSuchBucket*)
                                    echo "  bucket missing — bootstrapping packages.alertkick.com infra…"
                                    SETUP_RESP=$(curl --fail-with-body -sS --max-time 60 -X POST "${SUPERADMIN_URL}/fleet-api/agent-packages/setup-infra")
                                    echo "$SETUP_RESP"
                                    case "$SETUP_RESP" in
                                        *'"bucket_ready":true'*) ;;
                                        *) echo "ERROR: bucket still not ready after setup-infra"; return 1 ;;
                                    esac
                                    docker exec ${UPLOADER} aws s3 cp "/dist/$1" "$DST"
                                    ;;
                                *) return 1 ;;
                            esac
                        }

                        echo "=== Uploading packages to S3 ==="
                        # Bucket policy grants public read on packages/*, so no per-object ACL.
                        for f in dist/*.deb dist/*.rpm dist/*.tar.gz dist/*.zip dist/*.checksum; do
                            [ -f "$f" ] || continue
                            BASENAME=$(basename "$f")
                            echo "  uploading $BASENAME → s3://${S3_BUCKET}/packages/v${TAG_VERSION}/"
                            upload_one "$BASENAME"
                        done

                        echo "=== Registering with superadmin ==="
                        # Build payload with printf + single-quoted format strings so Jenkins/Groovy
                        # doesn't mangle backslash-escaped quotes. Write to a file, POST with -d @.
                        PAYLOAD_FILE=$(mktemp)
                        FIRST=true
                        printf '{"version":"%s","tag":"%s","packages":[' "$TAG_VERSION" "$TAG_NAME" > "$PAYLOAD_FILE"
                        for f in dist/*.deb dist/*.rpm dist/*.tar.gz; do
                            [ -f "$f" ] || continue
                            BASENAME=$(basename "$f")
                            CHECKSUM=""
                            if [ -f "${f}.checksum" ]; then
                                CHECKSUM=$(awk '{print "sha256:"$1}' "${f}.checksum")
                            fi
                            SIZE=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)

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

                            if [ "$FIRST" = true ]; then FIRST=false; else printf ',' >> "$PAYLOAD_FILE"; fi
                            printf '{"os":"linux","arch":"%s","format":"%s","filename":"%s","checksum":"%s","size":%s}' \
                                "$ARCH" "$FORMAT" "$BASENAME" "$CHECKSUM" "$SIZE" >> "$PAYLOAD_FILE"
                        done
                        printf ']}' >> "$PAYLOAD_FILE"

                        echo "Payload:"
                        cat "$PAYLOAD_FILE"
                        echo

                        curl --fail-with-body -sS --max-time 30 -X POST "${SUPERADMIN_URL}/fleet-api/agent-packages/register" \
                            -H "Content-Type: application/json" \
                            --data-binary "@$PAYLOAD_FILE"
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
            sh 'docker rm -f pkg-uploader-${BUILD_NUMBER} 2>/dev/null || true'
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
