FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl net-tools vim
COPY gateway /gateway
CMD ["/gateway","-c","/cfg/config.json"]

