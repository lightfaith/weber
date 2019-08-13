FROM python:3.7-alpine
#FROM python:3.7-slim-stretch
EXPOSE 8080/tcp
WORKDIR /weber
VOLUME /weber/files
#RUN apt-get update -y && apt-get -y install libsqlcipher-dev python3-pip
RUN apk --update add g++ libffi-dev openssl-dev python3-dev openssl
#tcpdump
RUN pip3 install --upgrade pip
#RUN apk --update add libxml2-dev libxslt-dev libffi-dev gcc musl-dev libgcc openssl-dev curl
#RUN apk add jpeg-dev zlib-dev freetype-dev lcms2-dev openjpeg-dev tiff-dev tk-dev tcl-dev g++
#RUN pip3 install matplotlib
#RUN pip3 install geotiler python-dateutil reportlab matplotlib graphviz pysqlcipher3
#RUN apt-get -y install graphviz fonts-symbola
CMD python3 ./weber -h 0.0.0.0 -p 8080
ADD requirements.txt /weber/
RUN pip3 install -r requirements.txt
ADD weber /weber/
ADD source /weber/source

