FROM golang:alpine AS build-env
RUN apk update && apk add --no-cache git
ADD . /src
RUN cd /src && go get -d -v && go build -o goapp

FROM alpine
WORKDIR /app
COPY --from=build-env /src/goapp /app/
COPY --from=build-env /src/people.csv /app/
ENTRYPOINT ./goapp
