docker run --rm \
    -w '/workspace' \
    -v "$(pwd):/workspace" \
    -v "$HOME/.gradle:/root/.gradle" \
    -v "$HOME/.docker:/root/.docker" \
    -v "$HOME/.m2:/root/.m2" \
    -e OVERRIDE_KEY_SAFETY_PROTECTIONS=true \
    'ibmjava:8-sdk' \
    ./gradlew crypto-core:test
