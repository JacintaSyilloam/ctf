FROM node:23-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --production

COPY . .

EXPOSE 10009

CMD ["node", "chall.js"]