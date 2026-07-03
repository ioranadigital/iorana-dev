FROM node:18-alpine
RUN npm install -g pnpm
WORKDIR /app
COPY package*.json ./
RUN pnpm install
COPY . .
EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "server.js"]
