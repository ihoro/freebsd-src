// Copyright 2025 The Kyua Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
// * Neither the name of Google Inc. nor the names of its contributors
//   may be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "engine/flaky/oneofn_tracker.hpp"

#include "engine/scheduler.hpp"
#include "engine/exceptions.hpp"
#include "model/metadata.hpp"
#include "model/test_case.hpp"
#include "model/test_result.hpp"
#include "utils/format/macros.hpp"


void
engine::flaky::oneofn_tracker::init(const model::test_case& tc)
{
    auto flaky = tc.get_metadata().flaky();
    if (flaky.empty())
        throw engine::error("flaky metadata expected to be set");

    try {
        _attempts_left = std::stoull(flaky);
        if (_attempts_left < 1)
            throw std::exception{};
    } catch (const std::exception&) {
        throw engine::error(F("Invalid flaky spec '%s'") % flaky);
    }
}


void
engine::flaky::oneofn_tracker::attempt_taken(
    const scheduler::test_result_handle* test_result_handle)
{
    const auto result = test_result_handle->test_result().type();
    if (result == model::test_result_passed ||
        result == model::test_result_expected_failure ||
        result == model::test_result_skipped) {
        _attempts_left = 0;
        return;
    }

    if (_attempts_left < 1)
        throw engine::error("_attempts_left expected to be > 0");

    _attempts_left--;
}


std::size_t
engine::flaky::oneofn_tracker::attempts_left() const
{
    return _attempts_left;
}
