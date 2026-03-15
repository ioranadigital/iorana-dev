# ══════════════════════════════════════════════════════════
#  iorana.dev — Dockerfile
# ══════════════════════════════════════════════════════════

FROM node:20-alpine

# Usuario no-root para mayor seguridad
RUN addgroup -S iorana && adduser -S iorana -G iorana

WORKDIR /app

# Instalar dependencias primero (capa cacheada)
COPY package*.json ./
RUN npm install --omit=dev

# Copiar código fuente
COPY --chown=iorana:iorana . .

# No copiar .env al contenedor (se inyecta via docker-compose env)
RUN rm -f .env

USER iorana

EXPOSE 3000

CMD ["node", "server.js"]
