

build:
	docker build --build-arg proj=TorRouter --build-arg path=/TorRouter/TorRouter/main.py --build-arg args="$(ARGS)" --build-arg port=$(PORT) -t router.img ..

start: clean build
	-docker run -p $(PORT):$(PORT) -d --privileged --name router$(CONT).cont router.img &

juststart:
	-docker run -p $(PORT):$(PORT) -d --privileged --name router$(CONT).cont router.img &

stop:
	-docker container stop router$(CONT).cont

clean:
	-docker exec router$(CONT).cont kill -s SIGINT $$(docker exec -it router$(CONT).cont ps | grep 'TorRouter' | awk '{print $$1}') ; \
	sleep 1 ; \
    docker container stop router$(CONT).cont ; \
	docker container rm router$(CONT).cont
