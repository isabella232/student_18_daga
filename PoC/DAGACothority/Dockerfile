FROM golang:alpine

# grab and build daga cothority
RUN apk add git
#RUN go get go.jonnrb.io/vanity
#COPY dedis_vanity.go .
#RUN go run dedis_vanity.go & go get 
RUN go get go.dedis.ch/kyber
RUN go get github.com/dedis/student_18_daga/dagacothority/conode

# setup and run daga cothority
WORKDIR /opt/poc-dagacothority

ENTRYPOINT ["./run_conode.sh"]
# defaults to 5 nodes, debug log lvl 3
CMD ["5", "3"]
