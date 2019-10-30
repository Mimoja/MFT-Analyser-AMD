FROM mft_go-yara
MAINTAINER Mimoja <git@mimoja.de>

RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go build -o main .

CMD ["/app/main", "config/config.yml"]
