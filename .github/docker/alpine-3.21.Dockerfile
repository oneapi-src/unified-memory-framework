# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# Dockerfile - a 'recipe' for Docker to build an image of Alpine
#              environment for building the Unified Memory Framework project.
#

# Pull base Alpine image version 3.21
FROM registry.hub.docker.com/library/alpine@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

# Set environment variables
ENV OS=alpine
ENV OS_VER=3.21

# Base development packages
ARG BASE_DEPS="\
	bash \
	cmake \
	git \
	g++ \
	make \
	sudo"

# UMF's dependencies
ARG UMF_DEPS="\
	hwloc-dev"

# Dependencies for tests
ARG TEST_DEPS="\
	numactl-dev"

# Update and install required packages
RUN apk update \
 && apk add --no-cache \
	${BASE_DEPS} \
	${TEST_DEPS} \
	${UMF_DEPS}

# Add a new (non-root) 'test_user'
ENV USER=test_user
RUN adduser -D -G wheel ${USER}
RUN echo '%wheel ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

USER test_user
