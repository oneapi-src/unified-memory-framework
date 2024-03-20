# Content

Dockerfiles and scripts placed in this directory are intended to be used as
development process vehicles and part of continuous integration process.

Images built out of those recipes may be used with Docker or podman as
development environment. If you want to use below instructions with `podman`,
simply replace word `docker` with `podman`.

# How to build docker image

To build docker image on local machine enter the root dir of the repository and execute:

```sh
docker build -t umf:ubuntu-22.04 -f .github/docker/ubuntu-22.04.Dockerfile .
```

To set any build time variable (e.g., an optional ARG from docker recipe), add to the command (after `build`), e.g.:

```sh
 --build-arg TEST_DEPS=""
```

One other example of using these extra build arguments are proxy settings. They are required for accessing network
(e.g., to download dependencies within docker), if a host is using a proxy server. Example usage:

```sh
 --build-arg https_proxy=http://proxy.com:port --build-arg http_proxy=http://proxy.com:port
```

# How to use docker image

To run docker container (using the previously built image) execute:

```sh
docker run --shm-size=4G -v /your/workspace/path/:/opt/workspace:z -w /opt/workspace/ -it umf:ubuntu-22.04 /bin/bash
```

To set (or override) any docker environment variable, add to the command (after `run`):

```sh
 -e ENV_VARIABLE=VALUE
```

To start as a non-root user (created within our Dockerfiles), add to the command (after `run`):

```sh
 --user test_user
```

If you want to run a docker container using your specific user, please follow up, e.g.,
with [this article](https://jtreminio.com/blog/running-docker-containers-as-current-host-user/).
