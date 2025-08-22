FROM golang:1.23

WORKDIR  /jwt-authentication

COPY  go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o main .

EXPOSE 8080

CMD ["./main"]