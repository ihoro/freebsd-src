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

#include "engine/execenv/jail.hpp"

#include <regex>

#include "model/metadata.hpp"
#include "model/test_case.hpp"
#include "model/test_program.hpp"
#include "utils/fs/path.hpp"
#include "utils/process/jail.hpp"
#include "utils/process/operations.hpp"

namespace execenv = engine::execenv;
namespace process = utils::process;
namespace fs = utils::fs;

using utils::process::args_vector;


namespace {


static std::string
make_jail_name(const fs::path& program, const std::string& test_case_name)
{
    std::string name = std::regex_replace(
        program.str() + "_" + test_case_name,
        std::regex(R"([^A-Za-z0-9_])"),
        "_");

    const std::string::size_type limit =
        255 /* jail name max */ - 4 /* "kyua" prefix */;
    if (name.length() > limit)
        name.erase(0, name.length() - limit);

    return "kyua" + name;
}


}  // anonymous namespace


/// Initialize execution environment.
///
/// It's expected to be called inside a fork which runs interface::exec_test(),
/// so we can fail a test fast if its execution environment setup fails.
///
/// \param program The test program binary absolute path.
/// \param test_case_name Name of the test case.
void
execenv::jail::init(const model::test_program& test_program,
                    const std::string& test_case_name)
{
    const model::test_case& test_case = test_program.find(test_case_name);

    process::jail::create(
        make_jail_name(test_program.absolute_path(), test_case_name),
        test_case.get_metadata().execenv_jail());
}


/// Execute within an execution environment.
///
/// It's expected to be called inside a fork which runs interface::exec_test().
///
/// \param program The test program binary absolute path.
/// \param test_case_name Name of the test case.
void
execenv::jail::exec(const model::test_program& test_program,
                    const std::string& test_case_name,
                    const args_vector& args) throw()
{
    process::jail::exec(
        make_jail_name(test_program.absolute_path(), test_case_name),
        test_program.absolute_path(), args);
}


/// Cleanup execution environment.
///
/// It's expected to be called inside a fork for execenv cleanup.
///
/// \param program The test program binary absolute path.
/// \param test_case_name Name of the test case.
void
execenv::jail::cleanup(const model::test_program& test_program,
                       const std::string& test_case_name)
{
    process::jail::remove(
        make_jail_name(test_program.absolute_path(), test_case_name));
}
