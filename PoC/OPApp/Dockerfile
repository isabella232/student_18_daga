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

RUN go get -d github.com/dedis/student_18_daga || true
WORKDIR ${GOPATH}/src/github.com/dedis/student_18_daga
#4th december ..
RUN git checkout 3768


WORKDIR ${GOPATH}/src/github.com/dexidp/dex/cmd/dex
RUN go get || true

WORKDIR ${GOPATH}/src/github.com/dedis/kyber
RUN git checkout 42e21
WORKDIR ../onet
RUN git checkout 4af7
WORKDIR ../protobuf
RUN git checkout 70b99
#WORKDIR ../cothority
#RUN git checkout 12e27

WORKDIR ${GOPATH}/src/github.com/dexidp/dex
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
