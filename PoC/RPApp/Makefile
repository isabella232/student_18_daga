PORT=8080
OPPORT=5556

all: build run

build:
	docker build --build-arg PORT=$(PORT) --build-arg OPPORT=$(OPPORT) --rm -t rpapp .
clean: 
	docker rmi rpapp
run:
	docker run --rm -p$(PORT):$(PORT) -p9229:9229 rpapp
devshell:
	docker run -it --rm -v $(shell pwd):/opt/poc-rp-app rpapp /bin/ash
