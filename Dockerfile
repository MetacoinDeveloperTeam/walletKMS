FROM inblock/walletkms:ssc-1.0
WORKDIR /usr/src/app
EXPOSE 10210
CMD [ "node", "src/inblockkms.js" ]
