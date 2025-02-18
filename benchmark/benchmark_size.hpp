/*
 * Copyright (C) 2024-2025 Intel Corporation
 *
 * Under the Apache License v2.0 with LLVM Exceptions. See LICENSE.TXT.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

#include <benchmark/benchmark.h>
#include <string>
#include <vector>

class alloc_size_interface {
  public:
    virtual unsigned SetUp([[maybe_unused]] ::benchmark::State &state,
                           [[maybe_unused]] unsigned argPos) = 0;
    virtual void TearDown([[maybe_unused]] ::benchmark::State &state) = 0;
    virtual size_t nextSize() = 0;
    static std::vector<std::string> argsName() { return {""}; };
};

class fixed_alloc_size : public alloc_size_interface {
  public:
    unsigned SetUp(::benchmark::State &state, unsigned argPos) override {
        size = state.range(argPos);
        return argPos + 1;
    }
    void TearDown([[maybe_unused]] ::benchmark::State &state) override {}
    size_t nextSize() override { return size; };
    static std::vector<std::string> argsName() { return {"size"}; }

  private:
    size_t size;
};

class uniform_alloc_size : public alloc_size_interface {
    using distribution = std::uniform_int_distribution<int64_t>;

  public:
    unsigned SetUp(::benchmark::State &state, unsigned argPos) override {
        auto min = state.range(argPos++);
        auto max = state.range(argPos++);
        auto gran = state.range(argPos++);
        if (min % gran != 0 && max % gran != 0) {
            state.SkipWithError("min and max must be divisible by granularity");
            return argPos;
        }
        generator.seed(0);
        dist.param(distribution::param_type(min / gran, max / gran));
        multiplier = gran;
        return argPos;
    }
    void TearDown([[maybe_unused]] ::benchmark::State &state) override {}
    size_t nextSize() override { return dist(generator) * multiplier; }
    static std::vector<std::string> argsName() {
        return {"min_size", "max_size", "granularity"};
    }

  private:
    std::default_random_engine generator;
    distribution dist;
    size_t multiplier = 1;
};
