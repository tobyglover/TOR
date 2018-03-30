

build:
	docker build --build-arg proj=router --build-arg path=/router/main.py --build-arg port=$(PORT) --build-arg pport=$(PPORT) --build-arg pip=$(PIP) -t router.img ..

start: build
	-docker container start router.cont || docker run -p $(PORT):$(PORT) --privileged --name router.cont router.img

stop:
	-docker container stop router.cont

clean: stop
	-docker container rm router.cont
