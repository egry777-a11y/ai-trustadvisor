FROM node:18-alpine
WORKDIR /app
COPY package.json package-lock.json* ./ || true
COPY server ./server
COPY frontend ./frontend
RUN npm install --production
EXPOSE 4000
CMD ["node","server/index.js"]
