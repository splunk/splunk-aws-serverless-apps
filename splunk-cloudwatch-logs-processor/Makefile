CONTAINER = dummy

IMAGE	  = cloudwatch-to-splunk

#	The zip file is created by 'npm run build:zip', which is called
#	by 'docker build'.
ZIP_FILE  = splunk-cloudwatch-logs-processor.zip

all: build

build: Dockerfile
	docker build -t $(IMAGE) .
	docker create -it --name $(CONTAINER) $(IMAGE) bash
	docker cp $(CONTAINER):/usr/src/$(ZIP_FILE) .
	docker rm -f $(CONTAINER)

clean:
	docker rm -f $(CONTAINER)
	rm -f $(ZIP_FILE)
