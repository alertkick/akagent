// Dedicated job to build the static `yara` binaries the agent bundles. Run this
// only when bumping YARA_VERSION (not on every agent build) — it publishes the
// per-arch binaries to S3, and the main akagent build downloads them in its
// "Fetch YARA binaries" stage. Suggested Jenkins job: alertkick/akagent-yara
// (manual / parameterized trigger).
pipeline {
    agent any

    parameters {
        string(name: 'YARA_VERSION', defaultValue: '4.5.2', description: 'YARA release tag to build (without the leading v)')
    }

    environment {
        S3_BUCKET = 'alertkick-agent-packages'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Build static yara (amd64 + arm64)') {
            steps {
                sh '''
                    set -eu
                    # qemu for cross-arch emulation, then a buildx builder.
                    docker run --rm --privileged tonistiigi/binfmt --install arm64 || true
                    docker buildx inspect yarabuilder >/dev/null 2>&1 || docker buildx create --name yarabuilder
                    docker buildx use yarabuilder

                    rm -rf out-amd64 out-arm64
                    for arch in amd64 arm64; do
                        docker buildx build --platform linux/${arch} \
                            --build-arg YARA_VERSION=${YARA_VERSION} \
                            -f Dockerfile.yara --target export \
                            --output type=local,dest=out-${arch} .
                    done
                    ls -l out-amd64/yara out-arm64/yara
                '''
            }
        }

        stage('Upload to S3') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'aws-s3-packages', usernameVariable: 'AWS_ACCESS_KEY_ID', passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) {
                    sh '''
                        set -eu
                        AWS_DEFAULT_REGION=us-east-1
                        UP=yara-uploader-${BUILD_NUMBER}
                        docker rm -f ${UP} 2>/dev/null || true
                        docker run -d --name ${UP} \
                            -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
                            -e AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION} \
                            --entrypoint sleep amazon/aws-cli 600
                        trap 'docker rm -f ${UP} 2>/dev/null || true' EXIT

                        for arch in amd64 arm64; do
                            docker cp out-${arch}/yara ${UP}:/yara-${arch}
                            # Versioned copy (history) + a "latest" pointer the agent build reads.
                            docker exec ${UP} aws s3 cp /yara-${arch} s3://${S3_BUCKET}/yara/${YARA_VERSION}/yara-${arch}
                            docker exec ${UP} aws s3 cp /yara-${arch} s3://${S3_BUCKET}/yara/latest/yara-${arch}
                        done
                        echo "Published yara ${YARA_VERSION} (amd64, arm64) to s3://${S3_BUCKET}/yara/"
                    '''
                }
            }
        }
    }
}
