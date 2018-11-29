from golang:alpine

# create app directory
WORKDIR /opt/poc-op-app

# grab and build dex
RUN apk add --no-cache --update alpine-sdk 
RUN go get -d github.com/sarkortrantor/dex

WORKDIR /go/src/github.com/sarkortrantor/dex 
RUN make release-binary 
RUN cp -rv web /opt/poc-op-app/
WORKDIR /opt/poc-op-app

# add app sources (dex config)
COPY poc-op-app .

# app listen port
#ARG PORT 
#ENV PORT=$PORT
#EXPOSE $PORT

ENTRYPOINT ["dex"]
CMD ["serve", "./config.yaml"]
