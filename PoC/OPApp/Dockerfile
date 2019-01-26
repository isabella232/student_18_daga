from golang:alpine

# create app directory
WORKDIR /opt/poc-op-app

# grab and build dex
RUN apk add --no-cache --update alpine-sdk 

#.only temp! TODO remove and find better way
WORKDIR /go/src/github.com/dexidp
RUN go get -d github.com/sarkortrantor/dex
RUN cp -r ../sarkortrantor/dex/ dex
WORKDIR dex 
RUN git checkout daga_connector
WORKDIR ../../dedis
RUN git clone https://github.com/dedis/student_18_daga.git
WORKDIR ../dexidp/dex/cmd/dex
#to fix dedis vanity
RUN go get go.dedis.ch/kyber
RUN go get -u
WORKDIR ../..
RUN make release-binary


# add app sources (dex config.yaml + web dir + tls cert/key)
WORKDIR /opt/poc-op-app
COPY poc-op-app .

# apps listen ports 
ARG PORT 
ARG RPPORT
EXPOSE $PORT

# update dex's config.yaml
RUN sed -i "s/%OPPORT%/$PORT/g;s/%RPPORT%/$RPPORT/g" ./config.yaml 

ENTRYPOINT ["dex"]
CMD ["serve", "./config.yaml"]
