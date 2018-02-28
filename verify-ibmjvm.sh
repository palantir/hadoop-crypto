# Runs the crypto-core tests on an ibm jvm
docker build -t ibm .
docker run --rm \
    -w '/workspace' \
    -v "$HOME/.gradle:/root/.gradle" \
    -v "$HOME/.docker:/root/.docker" \
    -v "$HOME/.m2:/root/.m2" \
    -e OVERRIDE_KEY_SAFETY_PROTECTIONS=true \
    -e DISABLE_ERROR_PRONE=true \
    ibm \
    ./gradlew --no-daemon crypto-core:test
