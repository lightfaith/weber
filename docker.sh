#!/bin/bash
[[ "$1" == '--build' ]] && sudo docker build -t lightfaith/weber .
sudo docker run --rm -it -v $PWD/files:/weber/files -p 8080:8080 --user $(id -u):$(id -g) --name weber lightfaith/weber
