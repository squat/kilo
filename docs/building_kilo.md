# Build and Test Kilo

This document describes how you can build and test Kilo.

To follow along, you need to install the following utilities:
 - `go` not for building but formatting the code and running unit tests
 - `make`
 - `jq`
 - `git`
 - `curl`
 - `docker`

## Getting Started

Clone the Repository and `cd` into it.
```shell
git clone https://github.com/kilo-io/kilo.git
cd kilo
```

## Build

For consistency, the Kilo binaries are compiled in a Docker container, so make sure the `docker` package is installed and the daemon is running.

### Compile Binaries

To compile the `kg` and `kgctl` binaries run:
```shell
make
```
Binaries are always placed in a directory corresponding to the local system's OS and architecture following the pattern `bin/<os>/<architecture>/`, so on an AMD64 machine running Linux, the binaries will be stored in `bin/linux/amd64/`.

You can build the binaries for a different architecture by setting the `ARCH` environment variable before invoking `make`, e.g.:
```shell
ARCH=<arm|arm64|amd64> make
```

Likewise, to build `kg` for another OS, set the `OS` environment variable before invoking `make`:
```shell
OS=<windows|darwin|linux> make
```
## Test

To execute the unit tests, run:
```shell
make unit
```

To lint the code in the repository, run:
```shell
make lint
```

To execute basic end to end tests, run:
```shell
make e2e
```
> **Note**: The end to end tests are currently flaky, so try running them again if they fail.

To instead run all of the tests with a single command, run:
```shell
make test
```

## Build and Push the Container Images

If you want to build containers for a processor architecture that is different from your computer's, then you will first need to configure QEMU as the interpreter for binaries built for non-native architectures:
```shell
docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

Set the `$IMAGE` environment variable to `<your Docker Hub user name>/kilo`.
This way the generated container images and manifests will be named accordingly.
By skipping this step, you will be able to tag images but will not be able to push the containers and manifests to your own Docker Hub.
```shell
export IMAGE=<docker hub user name>/kilo
```

If you want to use a different container registry, run:
```shell
export REGISTRY=<your registry without a trailing slash>
```

To build containers with the `kg` image for `arm`, `arm64` and `amd64`, run:
```shell
make all-container
```

Push the container images and build a manifest with:
```shell
make manifest
```

To tag and push the manifest with `latest`, run:
```shell
make manifest-latest
```

Now you can deploy the custom build of Kilo to your cluster.
If you are already running Kilo, change the image from `squat/kilo` to `[registry/]<username>/kilo[:sha]`.
