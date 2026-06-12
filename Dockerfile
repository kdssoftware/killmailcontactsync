FROM golang:alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

COPY . .
RUN go mod download

RUN CGO_ENABLED=1 GOOS=linux go build -a -o evecontacts main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/evecontacts .
COPY index.html .
COPY ./data/eve.db ./data/eve.db

EXPOSE 8080
CMD ["./evecontacts"]
