# Nimrod/G Agent

The Nimrod/G agent. It is not recommended to invoke this manually.

## Usage
```
Usage: "agent" [OPTIONS]
Options:
  -v, --version
                          Display version string
  -p, --platform
                          Display platform string
  -u, --user-agent
                          Display HTTP user agent
  -h, --help
                          Display help message
  --cacert=PATH
                          Path to the CA certificate
  --caenc={plain,base64}
                          Encoding of the CA certificate specified by --cacert
                          - plain  = The certificate is a base64-encoded PEM certificate
                          - base64 = The certificate is a base64-encoded, base64-encoded PEM certificate
                          The double-encoding is used to account for the RFC7468 headers
  --no-ca-delete
                          Don't delete the CA certificate after reading
  --no-verify-peer
                          Disable peer verification
  --no-verify-host
                          Disable hostname verification
  --uuid=UUID
                          The UUID of the agent. If omitted, use a random one
  --work-root=PATH
                          Change directory to PATH if specified
  --batch
                          Enter batch mode. Implies --nohup and --output=workroot
                          - Upon start, the agent fork()'s and prints the child PID and a newline character
                            to stdout before exiting
                          - The --output flag may be given to change the behaviour, but will be ignored if
                            it is set to "console"
                          - This is only supported on POSIX systems
  --output={console,off,workroot}
                          Set stdout/stderr redirection mode
                          - console  = Use the attached console's stdout/stderr
                          - off      = Disable stdout/stderr
                          - workroot = Redirect everything to a file called output.txt in the work root
  --nohup
                          Ignore SIGHUP. Ignored on non-POSIX systems.
  --amqp-uri=URI
                          The URI of the AMQP broker
  --amqp-routing-key=KEY
                          The routing key to use to contact the Nimrod master. Defaults to "iamthemaster"
  --amqp-fanout-exchange=NAME
                          The name of the fanout exchange to use. Defaults to "amqp.fanout"
  --amqp-direct-exchange=NAME
                          The name of the direct exchange to use. Defaults to "amqp.direct"
```

## Build Instructions
* Ensure you have a C++17 compiler installed. This should work on recent versions of MSVC (2017+).
* Download and extract `https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.9.0.tar.gz` to the clone directory.
  - If you want to use a different version, change the `add_subdirectory` directive in `CMakeLists.txt`
* Update submodules: `git submodule update --init`
* Decide on a platform string, such as `x86_64-pc-linux-gnu`
* Do an out-of-tree CMake build: `cmake -DNIMRODG_PLATFORM_STRING=x86_64-pc-linux-gnu /path/to/clone/dir`
* Build it: `make -j agent`

The build scripts are designed to build _mostly-static_ binaries. If using _musl_, you can achieve fully-static binaries.
It is recommended against using system-provided libraries due to the nature of the agent.

## License
This project is licensed under the [Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0):

Copyright &copy; 2019 [The University of Queensland](http://uq.edu.au/)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
* * *

For additional 3rd-party licenses, see `3RD-PARTY`
