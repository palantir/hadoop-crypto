# Runs the crypto-core tests on an ibm jvm
docker run --rm \
    -w '/workspace' \
    -v "$(pwd):/workspace" \
    -v "$HOME/.gradle:/root/.gradle" \
    -v "$HOME/.docker:/root/.docker" \
    -v "$HOME/.m2:/root/.m2" \
    -e OVERRIDE_KEY_SAFETY_PROTECTIONS=true \
    'ibmjava:8-sdk@sha256:5334bbeaebe15e044f379879e1bb900c0a98f6f3e93fd7dbc6ea18bb9ae263ca' \
    ./gradlew crypto-core:test
