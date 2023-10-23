// Copyright (c) 2023 Igor Ostapenko <pm@igoro.pro>
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

/// \file engine/execenv/execenv.hpp
/// Execution environment multiplexer.
///
/// A test case may ask for a specific execution environment like running in
/// a jail, what needs initialization before the test run and cleanup after.
///
/// By default, there is no specific execution environment, so called host
/// environment, and no additional initialization or cleanup is done.

#if !defined(ENGINE_EXECENV_EXECENV_HPP)
#define ENGINE_EXECENV_EXECENV_HPP

#include "model/test_program.hpp"
#include "utils/defs.hpp"
#include "utils/process/operations_fwd.hpp"

namespace engine {
namespace execenv {


void init(const model::test_program&, const std::string&);

void exec(const model::test_program&, const std::string&,
          const utils::process::args_vector&) throw() UTILS_NORETURN;

void cleanup(const model::test_program&, const std::string&);


}  // namespace execenv
}  // namespace engine

#endif  // !defined(ENGINE_EXECENV_EXECENV_HPP)
