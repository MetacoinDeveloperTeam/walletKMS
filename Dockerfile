FROM node:12.19.0-buster

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install
RUN npm ci --only=production

COPY . .

EXPOSE 10210
CMD [ "node", "src/inblockkms.js" ]
