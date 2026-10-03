FROM node:22-trixie-slim

WORKDIR /app

# Build tools for better-sqlite3, plus Python (3.13 on trixie) for the Garmin bridge
RUN apt-get update \
	&& apt-get install -y --no-install-recommends python3 python3-venv make g++ ca-certificates tzdata \
	&& rm -rf /var/lib/apt/lists/*

# Garmin bridge dependencies in an isolated venv
COPY garmin/requirements.txt ./garmin/requirements.txt
RUN python3 -m venv /opt/garmin \
	&& /opt/garmin/bin/pip install --no-cache-dir -r garmin/requirements.txt

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source files
COPY tsconfig.json ./
COPY src ./src
COPY garmin ./garmin

# Build TypeScript
RUN npm run build

# Create data directory for SQLite
RUN mkdir -p /data

ENV DB_PATH=/data/whoop.db
ENV MCP_MODE=http
ENV PORT=3000
ENV GARMIN_PYTHON=/opt/garmin/bin/python

EXPOSE 3000

CMD ["node", "dist/index.js"]
