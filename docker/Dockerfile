# BNG Blaster container image with the BNG Blaster controller
#
# The controller REST API (port 8001) is used to create, start and stop
# BNG Blaster instances. The instance directory /var/bngblaster can be
# mounted to provide configurations and additional files (e.g. MRT files)
# and to access logs, reports and captures of the instances directly.
#
# Build from the repository root:
#   docker build -f docker/Dockerfile -t bngblaster .
#
# The controller is built from the latest release, another release tag or
# branch can be selected with --build-arg CONTROLLER_VERSION=<tag|branch>.
#
# Run:
#   docker run -d -p 8001:8001 -v $PWD/instances:/var/bngblaster bngblaster
#
# Additional controller options can be passed as command, e.g. to disable
# the web UI and file upload (supported by controller versions > 0.1.3):
#   docker run -d -p 8001:8001 bngblaster -ui=false -upload=false

ARG DEBIAN_VERSION=trixie

FROM debian:${DEBIAN_VERSION}-slim AS bngblaster-build

ARG LIBDICT_VERSION=1.0.7
ARG BNGBLASTER_VERSION=
ARG GIT_REF=
ARG GIT_SHA=

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates wget \
        libpcap-dev libncurses-dev libssl-dev libjansson-dev \
    && rm -rf /var/lib/apt/lists/*

# libdict is linked statically and built from source to support all architectures
# (the shared library is required by the libdict install target).
RUN wget -qO- https://github.com/rtbrick/libdict/archive/refs/tags/${LIBDICT_VERSION}.tar.gz | tar xz -C /tmp \
    && cmake -S /tmp/libdict-${LIBDICT_VERSION} -B /tmp/libdict-build \
        -DCMAKE_BUILD_TYPE=Release -DLIBDICT_STATIC=YES -DLIBDICT_SHARED=YES \
        -DLIBDICT_TOOLS=NO -DLIBDICT_TESTS=NO \
    && cmake --build /tmp/libdict-build -j "$(nproc)" \
    && cmake --install /tmp/libdict-build

COPY . /src
RUN cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
        -DBNGBLASTER_VERSION="${BNGBLASTER_VERSION}" -DGIT_REF="${GIT_REF}" -DGIT_SHA="${GIT_SHA}" \
    && cmake --build /build -j "$(nproc)" \
    && DESTDIR=/install cmake --install /build

FROM golang:${DEBIAN_VERSION} AS controller-build

# Release tag or branch, latest resolves the latest release.
ARG CONTROLLER_VERSION=latest
ARG CONTROLLER_REPO=https://github.com/rtbrick/bngblaster-controller

# The release tags have no v prefix, therefore the controller is built
# from a clone instead of go install. GOTOOLCHAIN=auto downloads a newer
# Go version if required by the controller.
RUN set -e; \
    version="${CONTROLLER_VERSION}"; \
    if [ "${version}" = "latest" ]; then \
        version=$(curl -fsSI "${CONTROLLER_REPO}/releases/latest" \
            | sed -n 's|^location: .*/tag/\([^[:space:]]*\).*|\1|ip'); \
    fi; \
    echo "Build BNG Blaster controller ${version}"; \
    git clone -q --depth 1 --branch "${version}" "${CONTROLLER_REPO}" /controller; \
    cd /controller; \
    CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath \
        -ldflags "-s -w -X main.Version=${version}" -o /bngblasterctrl ./cmd/bngblasterctrl

FROM debian:${DEBIAN_VERSION}-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3t64 libncurses6 libjansson4 \
        python3 python3-scapy \
        iproute2 ethtool tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bngblaster-build /install/usr/ /usr/
COPY --from=controller-build /bngblasterctrl /usr/bin/bngblasterctrl

VOLUME ["/var/bngblaster"]
EXPOSE 8001

# The executable is set explicitly, older controller versions default to /usr/sbin.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/bin/bngblasterctrl", \
            "-e", "/usr/bin/bngblaster", "-d", "/var/bngblaster", "-addr", ":8001"]
CMD []
