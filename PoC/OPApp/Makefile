PORT=5556
RPPORT=8080

all: build run

build:
	docker build --build-arg PORT=$(PORT) --build-arg RPPORT=$(RPPORT) --rm -t opapp .
clean: 
	docker rmi opapp
run:
	docker run --rm -p$(PORT):$(PORT) opapp
devshell:
	docker run -it --rm -v $(shell pwd):/opt/poc-op-app opapp /bin/ash
