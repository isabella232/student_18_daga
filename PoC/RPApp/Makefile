PORT=8080

all: build run

build:
	docker build --build-arg PORT=$(PORT) --rm -t rpapp .
clean: 
	docker rmi rpapp
run:
	docker run --rm -p$(PORT):$(PORT) rpapp
