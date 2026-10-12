# Single image: React dashboard + Java DNS server + REST API, one process.
#   docker build -t dns-filter .
#   docker run -p 5300:5300/udp -p 8081:8081 dns-filter
# Any config key can be overridden with DNSFILTER_<KEY> env vars (see backend Config.java).

# ---- 1. dashboard ----
FROM node:20-alpine AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- 2. backend ----
FROM maven:3.9-eclipse-temurin-17 AS api
WORKDIR /src/backend
COPY backend/pom.xml ./
RUN mvn -q -B dependency:go-offline
COPY backend/src ./src
RUN mvn -q -B package -DskipTests

# ---- 3. runtime ----
FROM eclipse-temurin:17-jre
RUN useradd --system --uid 10001 dnsfilter
WORKDIR /app/backend
COPY --from=api /src/backend/target/dns-filter.jar ./dns-filter.jar
COPY --from=ui /src/frontend/dist /app/frontend/dist
COPY blocklists /app/blocklists
RUN mkdir -p /app/blocklists/downloaded && chown -R dnsfilter /app/blocklists
USER dnsfilter

# Public resolvers by default (the campus resolver in config.properties only works on campus).
ENV DNSFILTER_UPSTREAM_HOST=1.1.1.1 \
    DNSFILTER_UPSTREAM_FALLBACK=8.8.8.8 \
    DNSFILTER_DNS_PORT=5300 \
    DNSFILTER_API_PORT=8081

EXPOSE 5300/udp 8081/tcp
CMD ["java", "-XX:MaxRAMPercentage=75", "-jar", "dns-filter.jar"]
