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

#include "utils/process/jail.hpp"

#include <iostream>
#include <regex>

#include "utils/fs/path.hpp"
#include "utils/process/child.ipp"
#include "utils/format/macros.hpp"
#include "utils/process/operations.hpp"
#include "utils/process/status.hpp"

namespace fs = utils::fs;
namespace process = utils::process;
namespace jail = utils::process::jail;

using utils::process::args_vector;
using utils::process::child;


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


/// Functor to run a program.
class run {
    /// Program binary absolute path.
    const utils::fs::path& _program;

    /// Program arguments.
    const args_vector& _args;

public:
    /// Constructor.
    ///
    /// \param program Program binary absolute path.
    /// \param args Program arguments.
    run(
        const utils::fs::path& program,
        const args_vector& args) :
        _program(program),
        _args(args)
    {
    }

    /// Body of the subprocess.
    void
    operator()(void)
    {
        process::exec(_program, _args);
    }
};


}  // anonymous namespace


/// Create a jail based on test program path and case name.
///
/// A new jail will always be 'persist', thus the caller is expected to remove
/// the jail eventually via jail::remove().
///
/// \param program The test program binary absolute path.
/// \param test_case_name Name of the test case.
/// \param jail Set of jail parameters.
void
jail::create(const fs::path& program,
             const std::string& test_case_name,
             const std::set< std::string >& jail)
{
    args_vector av;

    av.push_back("-c");

    // TODO: let's make jail be a string metadata and parse it only here before the jail invocation!

    // some defaults to ease test authors' life
    av.push_back("children.max=16");

    // test defined jail params
    for (std::set< std::string >::iterator it = jail.begin();
         it != jail.end(); ++it) {
        printf("jail::create, jail: %s\n", (*it).c_str());
        av.push_back(*it);
    }

    // jail name
    av.push_back(F("name=%s") % make_jail_name(program, test_case_name));

    // it must be persist
    av.push_back("persist");

    // invoke jail
    std::auto_ptr< process::child > child = child::fork_capture(
        run(fs::path("/usr/sbin/jail"), av));
    process::status status = child->wait();

    // expect success
    if (status.exited() && status.exitstatus() == EXIT_SUCCESS)
        return;

    // otherwise, let us know what jail thinks and fail fast
    char err[330];
    child->output().getline(err, 330);
    std::cerr << err << "\n";
    std::exit(EXIT_FAILURE);
}


/// Executes an external binary in a jail and replaces the current process.
///
/// This function must not use any of the logging features so that the output
/// of the subprocess is not "polluted" by our own messages.
///
/// This function must also not affect the global state of the current process
/// as otherwise we would not be able to use vfork().  Only state stored in the
/// stack can be touched.
///
/// \param program The test program binary absolute path.
/// \param test_case_name Name of the test case.
/// \param args The arguments to pass to the binary, without the program name.
void
jail::exec(const fs::path& program,
                   const std::string& test_case_name,
                   const args_vector& args) throw()
{
    args_vector av(args);
    av.insert(av.begin(), program.str());
    av.insert(av.begin(), make_jail_name(program, test_case_name));

    process::exec(fs::path("/usr/sbin/jexec"), av);
}
