

build:
	docker build --build-arg proj=TorPathingServer --build-arg path=/TorPathingServer/TorPathingServer/main.py --build-arg port=$(PORT) -t pathing-server.img ..

start: clean build
	-docker run -it -d=true -p $(PORT):$(PORT) --name pathing-server.cont pathing-server.img

stop:
	-docker container stop pathing-server.cont

clean: stop
	-docker container rm pathing-server.cont
