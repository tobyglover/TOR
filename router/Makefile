

build:
	docker build --build-arg proj=router --build-arg port=$(PORT) --build-arg pport=$(PPORT) --build-arg pip=$(PIP) -t router.img ..

start: build
	-docker container start router.cont || docker run -p $(PORT):$(PORT) --net=host --privileged -v /dev/:/dev/ -t --name router.cont router.img

stop:
	-docker container stop router.cont

clean: stop
	-docker container rm router.cont
