FROM golang:1.20 AS builder


WORKDIR /src
COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o /app


FROM ubuntu

RUN apt-get update && apt-get -y install openssh-client

COPY --from=builder /app /app
COPY ./entrypoint.sh ./entrypoint.sh

EXPOSE 2223

ENTRYPOINT [ "./entrypoint.sh"]
CMD [ "/app", "2223" ]