FROM ubuntu:16.04

RUN apt-get update && apt-get install -y curl build-essential
RUN useradd -u 1000 -m app
RUN mkdir /app && chown 1000:1000 /app

USER app

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH=$PATH:/home/app/.cargo/bin
ENV USER=app
WORKDIR /app
