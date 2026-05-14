# ---- Build Stage ----
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /app

COPY gradle/ gradle/
COPY gradlew .
COPY settings.gradle.kts .
COPY build.gradle.kts .

# Copy all module build files for dependency caching
COPY domain/build.gradle.kts domain/
COPY application/build.gradle.kts application/
COPY adapters/inbound/http/build.gradle.kts adapters/inbound/http/
COPY adapters/inbound/scheduler/build.gradle.kts adapters/inbound/scheduler/
COPY adapters/outbound/persistence/build.gradle.kts adapters/outbound/persistence/
COPY adapters/outbound/crypto/build.gradle.kts adapters/outbound/crypto/
COPY infrastructure/build.gradle.kts infrastructure/

# Copy version catalog for dependency resolution
COPY gradle/libs.versions.toml gradle/

RUN ./gradlew dependencies --no-daemon || true

COPY . .

RUN ./gradlew :infrastructure:installDist --no-daemon -x test

# Minimal JRE via jlink — same module set as scaffold's monolith but adds modules used by:
#   - BouncyCastle ML-KEM (java.security.jgss)
#   - HMAC-SHA-512 audit chain (jdk.crypto.cryptoki already covered)
#   - JCA cert factory for the cert-chain extractor (java.security)
RUN jlink \
    --add-modules java.base,java.desktop,java.logging,java.naming,java.rmi,java.sql,java.net.http,java.management,java.management.rmi,java.security.sasl,java.security.jgss,java.xml,jdk.crypto.ec,jdk.crypto.cryptoki,jdk.unsupported,jdk.naming.dns \
    --strip-debug \
    --no-man-pages \
    --no-header-files \
    --compress=2 \
    --output /opt/jre

# ---- Runtime Stage ----
FROM alpine:3.19 AS runtime
WORKDIR /app

RUN addgroup -S secgroup && adduser -S -G secgroup secuser

COPY --from=build /opt/jre /opt/jre
COPY --from=build /app/infrastructure/build/install/infrastructure/ .

ENV PATH="/opt/jre/bin:${PATH}"
ENV JAVA_TOOL_OPTIONS="-XX:+UseG1GC -XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"

USER secuser

EXPOSE 8443

# Health probe: the service requires mTLS on every endpoint including /v1/health, so this
# probe uses the server's own cert against the in-container CA bundle. Stream-E secrets
# layout mounts the CA + a probe client cert at /run/secrets/security-service/.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider --no-check-certificate https://localhost:8443/v1/health || exit 1

ENTRYPOINT ["./bin/infrastructure"]
