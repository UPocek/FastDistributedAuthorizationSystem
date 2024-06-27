# FastDistributedAuthorizationSystem

## Problem
Goal of this project is to create fast and scalable auth service that other users can use as an api service

## Solution

The FastDistributedAuthorizationSystem is a high-performance, scalable authentication and authorization service designed to be used as an API by other applications. It leverages a combination of technologies to achieve speed, reliability, and flexibility:

1. **Go Programming Language**: The core system is written in Go, known for its efficiency and concurrency support, making it ideal for high-performance web services.

2. **Gin Web Framework**: Utilizing Gin for routing and handling HTTP requests, the system benefits from its speed and lightweight nature.

3. **LevelDB**: A fast key-value storage library is used for persisting local data, such as API tokens. This provides quick access to frequently used information.

4. **Consul**: HashiCorp's Consul is employed as a distributed key-value store, enabling the system to manage and distribute authorization rules across multiple instances.

5. **Token-based Authentication**: The system issues and manages API tokens for secure access to its endpoints.

6. **Namespace and ACL Management**: It provides endpoints for creating and managing namespaces and Access Control Lists (ACLs), allowing for flexible and granular permission settings.

7. **Encryption**: Sensitive data, like stored tokens, are encrypted using AES-GCM for enhanced security.

8. **Docker Support**: The entire system can be easily deployed using Docker, ensuring consistency across different environments.

### Key Features:

- Fast token issuance and validation
- Flexible namespace creation for organizing permissions
- Granular ACL management
- Distributed architecture for scalability
- Secure storage of sensitive information
- RESTful API for easy integration with other services

The system's architecture allows for horizontal scaling, with Consul ensuring consistency of authorization rules across multiple instances. This design makes it suitable for high-traffic scenarios where performance and reliability are crucial.

By offering these features as a service, the FastDistributedAuthorizationSystem allows other applications to offload the complex task of managing permissions and access control, focusing instead on their core functionalities while ensuring robust security measures are in place.

### How to use
- To run in docker as dedicated service run:
```
docker compose build
docker compose up
```
- To run on local do:
- Level db is just a library and does not have Docker image so install it with other go libraries just by running the `go get .` and `go mod tidy` commands
- Consul among a lot of cool features has its Key-Value store. Create consul-config.json file with needed configuration and then start the container with this command `docker run -p 8500:8500 -p 8600:8600/udp --name=consul -v ./consul-config.json:/consul/config/consul-config.json hashicorp/consul agent -server -bootstrap -ui -client=0.0.0.0 -config-file=/consul/config/consul-config.json`

### Referances
- https://hub.docker.com/r/hashicorp/consul

- https://developer.hashicorp.com/consul/api-docs/kv#raw
- https://developer.hashicorp.com/consul/docs/dynamic-app-config/kv/store?utm_source=docs
- https://developer.hashicorp.com/consul/docs/dynamic-app-config/kv
- https://github.com/hashicorp/consul?tab=readme-ov-file

- https://pkg.go.dev/github.com/hashicorp/consul/api#section-readme

- https://pkg.go.dev/github.com/syndtr/goleveldb/leveldb#pkg-types
- https://developer.hashicorp.com/consul/api-docs/kv#recurse