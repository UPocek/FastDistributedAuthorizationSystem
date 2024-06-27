FROM golang:latest

# Add Maintainer Info
LABEL maintainer="AlexanderMishutkin <alexander.mishutkin@example.com>"

# Set the Current Working Directory inside the container

COPY . /app
WORKDIR /app/fdas

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Build the Go app
RUN go build -o main

RUN rm -rf ./db
