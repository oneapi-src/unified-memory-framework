# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# Dockerfile - a 'recipe' for Docker to build an image of ubuntu-based
#              environment for building the Unified Memory Framework project.
#

# Pull base image ("24.04")
FROM registry.hub.docker.com/library/ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

# Set environment variables
ENV OS ubuntu
ENV OS_VER 24.04
ENV NOTTY 1
ENV DEBIAN_FRONTEND noninteractive

# Base development packages
ARG BASE_DEPS="\
	build-essential \
	cmake \
	git"

# UMF's dependencies
ARG UMF_DEPS="\
	libhwloc-dev \
	libtbb-dev"

# Dependencies for tests (optional)
ARG TEST_DEPS="\
	libnuma-dev"

# Miscellaneous for our builds/CI (optional)
ARG MISC_DEPS="\
	automake \
	clang \
	python3-pip \
	sudo \
	whois"

# Update and install required packages
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
	${BASE_DEPS} \
	${UMF_DEPS} \
	${TEST_DEPS} \
	${MISC_DEPS} \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get clean all

# Install hwloc
COPY .github/scripts/install_hwloc.sh /opt/umf/install_hwloc.sh
RUN apt-get update \
	&& apt-get install -y dos2unix libtool \
	&& dos2unix /opt/umf/install_hwloc.sh \
	&& bash -x /opt/umf/install_hwloc.sh \
	&& ldconfig \
	&& rm -f /opt/umf/install_hwloc.sh

# Install valgrind
RUN apt-get update && \
	apt-get install -y valgrind clang cmake hwloc libhwloc-dev libnuma-dev libtbb-dev

# Install lcov
RUN apt-get update && \
	apt-get install lcov -y

# Prepare a dir (accessible by anyone)
RUN mkdir -p --mode 777 /opt/umf/

# Additional dependencies (installed via pip)
COPY third_party/requirements.txt /opt/umf/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /opt/umf/requirements.txt

# Add a new (non-root) 'test_user' 
ENV USER test_user
ENV USERPASS pass
RUN useradd -m "${USER}" -g sudo -p "$(mkpasswd ${USERPASS})"
USER test_user
