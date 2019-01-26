FROM golang:alpine

# grab and build daga cothority
RUN apk add git
#RUN go get go.jonnrb.io/vanity
#COPY dedis_vanity.go .
#RUN go run dedis_vanity.go & go get 

#4th december .....
RUN go get -d github.com/dedis/student_18_daga || true
WORKDIR ${GOPATH}/src/github.com/dedis/student_18_daga/dagacothority/conode 
RUN git checkout 3768

RUN go get || true
WORKDIR ${GOPATH}/src/github.com/dedis/kyber
RUN git checkout 42e21
WORKDIR ../onet
RUN git checkout 4af7
WORKDIR ../protobuf
RUN git checkout 70b99
WORKDIR ../cothority
RUN git checkout 12e27
WORKDIR ../student_18_daga/dagacothority/conode
RUN go install

# setup and run daga cothority
WORKDIR /opt/poc-dagacothority

ENTRYPOINT ["./run_conode.sh"]
# defaults to 5 nodes, debug log lvl 3
CMD ["5", "3"]
