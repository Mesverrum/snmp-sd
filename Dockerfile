# Discovery CLI + module library.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY snmpdiscovery ./snmpdiscovery
RUN CGO_ENABLED=0 go build -o /snmp-discovery ./cmd/snmp-discovery

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /snmp-discovery /usr/bin/snmp-discovery
COPY snmp /opt/snmp-sd/snmp
COPY examples /opt/snmp-sd/examples
ENTRYPOINT ["/usr/bin/snmp-discovery"]
