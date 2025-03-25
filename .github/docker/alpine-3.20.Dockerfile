# Copyright (C) 2025 Intel Corporation
# Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#
# Dockerfile - a 'recipe' for Docker to build an image of Alpine
#              environment for building the Unified Memory Framework project.
#

# Pull base Alpine image version 3.20
FROM alpine:3.20

# Set environment variables
ENV OS alpine
ENV OS_VER 3.20

# Base development packages
ARG BASE_DEPS="\
	cmake \
	git \
	g++ \
	make"

# UMF's dependencies
ARG UMF_DEPS="\
	hwloc-dev"

# Dependencies for tests
ARG TEST_DEPS="\
	numactl-dev"

# Update and install required packages
RUN apk update \
 && apk add \
	${BASE_DEPS} \
	${TEST_DEPS} \
	${UMF_DEPS}
