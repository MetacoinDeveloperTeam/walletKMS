FROM inblock/wallet_kms:ssc-1.0.1
WORKDIR /usr/src/app
EXPOSE 10210
CMD [ "node", "src/inblockkms.js" ]
