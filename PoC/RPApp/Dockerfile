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

# app listen port, used from node app too, hence ENV
ARG PORT 
ENV PORT=$PORT
EXPOSE $PORT

# express session secret/salt via $(hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/urandom)
ENV SESSION_SECRET 51374E06252A40B57807037E721AAFED

# TODO find working and acceptable trick to set this programatically
ENV DOCKER_HOST_IP 172.17.0.1
#RUN echo "export DOCKER_HOST_IP=$(route -n | awk '/UG[ \t]/{print $2}')" > /etc/profile.d/export.sh

CMD ["npm", "start"]} 
