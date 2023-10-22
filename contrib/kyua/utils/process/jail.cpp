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

#include "utils/fs/path.hpp"
#include "utils/process/operations.hpp"

namespace fs = utils::fs;
namespace process = utils::process;


/// Executes an external binary in a jail and replaces the current process.
///
/// This function must not use any of the logging features so that the output
/// of the subprocess is not "polluted" by our own messages.
///
/// This function must also not affect the global state of the current process
/// as otherwise we would not be able to use vfork().  Only state stored in the
/// stack can be touched.
///
/// \param program The binary to execute.
/// \param args The arguments to pass to the binary, without the program name.
/// \param test_case_name Name of the test case.
/// \param jail Set of jail parameters.
/// \param persist Whether a new jail should persist.
void
process::jailexec(const fs::path& program, const args_vector& args,
                  const std::string& test_case_name,
                  const std::set< std::string >& jail,
                  bool persist) throw()
{
    // given program is a jail command
    args_vector av(args);
    std::string command(program.str());
    command.insert(0, "command=");
    av.insert(av.begin(), command);

    av.insert(av.begin(), persist ? "persist" : "nopersist");

    // test defined jail params come last to override defaults if needed
    for (std::set< std::string >::iterator it = jail.begin();
         it != jail.end(); ++it) {
        av.insert(av.begin(), *it);
    }

    // some defaults to ease life for test authors
    av.insert(av.begin(), "allow.raw_sockets");
    av.insert(av.begin(), "vnet");
    av.insert(av.begin(), "children.max=16");

    // TODO: form jail name

    // jail invocation
    av.insert(av.begin(), "-qc");
    process::exec(fs::path("/usr/sbin/jail"), av);
}
