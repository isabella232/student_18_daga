from node:alpine

# create app directory
WORKDIR /opt/poc-rp-app

# add app dependencies
# wildcard to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY poc-rp-app/package*.json ./

RUN npm install

# add app sources
COPY poc-rp-app .

# app listen port
ARG PORT 
ENV PORT=$PORT
EXPOSE $PORT

CMD ["npm", "start"]} 
