FROM golang:alpine


# grab and build daga cothority
RUN apk add --no-cache --update alpine-sdk
WORKDIR /go/src/github.com/dedis
RUN git clone -b PoC https://github.com/dedis/student_18_daga.git
WORKDIR student_18_daga/dagacothority
RUN go get ./...
WORKDIR conode
RUN go install

# setup and run daga cothority
WORKDIR /opt/poc-dagacothority

ENTRYPOINT ["./run_conode.sh"]
# defaults to 5 nodes, debug log lvl 3
CMD ["5", "3"]
