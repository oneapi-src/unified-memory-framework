# Copyright (C) 2024-2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# Dockerfile - a 'recipe' for Docker to build an image of ubuntu-based
#	  environment for building the Unified Memory Framework project.
#

# Pull base image ("20.04")
FROM registry.hub.docker.com/library/ubuntu@sha256:f2034e7195f61334e6caff6ecf2e965f92d11e888309065da85ff50c617732b8

# Set environment variables
ENV OS=ubuntu
ENV OS_VER=20.04
ENV NOTTY=1
ENV DEBIAN_FRONTEND=noninteractive

# Base development packages
ARG BASE_DEPS="\
	build-essential \
	cmake \
	git"

# Hwloc installation dependencies
ARG HWLOC_DEPS="\
	libtool"

# Dependencies for tests (optional)
ARG TEST_DEPS="\
	libnuma-dev \
	libtbb-dev \
	valgrind"

# Miscellaneous for our builds/CI (optional)
ARG MISC_DEPS="\
	automake \
	clang \
	g++-7 \
	lcov \
	python3-pip \
	sudo \
	whois"

# libhwloc-dev is required - installed via script because hwloc version is too old on this OS
COPY .github/scripts/install_hwloc.sh /opt/umf/install_hwloc.sh

# Update and install required packages
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
	${BASE_DEPS} \
	${TEST_DEPS} \
	${MISC_DEPS} \
	${HWLOC_DEPS} \
 && /opt/umf/install_hwloc.sh \
 && rm -rf /var/lib/apt/lists/* \
 && apt-get clean all

# Prepare a dir (accessible by anyone)
RUN mkdir -p --mode 777 /opt/umf/

# Additional dependencies (installed via pip)
# It's actively used and tested only on selected distros. Be aware
# they may not work, because pip packages list differ from OS to OS.
COPY third_party/requirements.txt /opt/umf/requirements.txt

# Add a new (non-root) 'test_user'
ENV USER=test_user
ENV USERPASS=pass
RUN useradd -m -u 1001 "${USER}" -g sudo -p "$(mkpasswd ${USERPASS})"
USER test_user
