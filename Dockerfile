FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --omit=dev --ignore-scripts

COPY dist/ dist/

EXPOSE 3100

ENTRYPOINT ["node", "dist/src/index.js"]
