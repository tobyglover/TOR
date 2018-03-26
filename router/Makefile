

build: check-args
	docker build --build-arg proj=router --build-arg port=$(PORT) --build-arg pport=$(PPORT) --build-arg pip=$(PIP) -t router.img ..

start: build
	-docker container start router.cont || docker run -p $(PORT):$(PORT) --net=host --privileged -v /dev/:/dev/ -t --name router.cont router.img

check-args:
ifndef PORT
    $(error PORT is undefined)
endif
ifndef PPORT
    $(error PPORT is undefined)
endif
ifndef PIP
    $(error PIP is undefined)
endif