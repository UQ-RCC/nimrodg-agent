#!/usr/bin/env python3

import os
import os.path
import shutil
import subprocess
import concurrent.futures

base_path = os.path.dirname(os.path.realpath(__file__))

profiles = {
	'x86_64-pc-linux-musl': {
		'toolchain_file': os.path.join(base_path, 'cibuild/x86_64-pc-linux-musl.cmake'),
		'strip': '/opt/x-tools/x86_64-pc-linux-musl/bin/x86_64-pc-linux-musl-strip'
	},
	'i686-pc-linux-musl': {
		'toolchain_file': os.path.join(base_path, 'cibuild/i686-pc-linux-musl.cmake'),
		'strip': '/opt/x-tools/i686-pc-linux-musl/bin/i686-pc-linux-musl-strip'
	},
	'armv6-rpi-linux-gnueabi': {
		'toolchain_file': os.path.join(base_path, 'cibuild/armv6-rpi-linux-gnueabi.cmake'),
		'strip': '/opt/x-tools/armv6-rpi-linux-gnueabi/bin/armv6-rpi-linux-gnueabi-strip'
	},
	'armv8-rpi3-linux-gnueabihf': {
		'toolchain_file': os.path.join(base_path, 'cibuild/armv8-rpi3-linux-gnueabihf.cmake'),
		'strip': '/opt/x-tools/armv8-rpi3-linux-gnueabihf/bin/armv8-rpi3-linux-gnueabihf-strip'
	}
}

cwd = os.getcwd()

bd = {}

for p in profiles:
	builddir = os.path.join(cwd, p)
	shutil.rmtree(builddir, True)
	os.makedirs(builddir, exist_ok=True)
	bd[p] = builddir

# 'cause these are the slowest part
with concurrent.futures.ThreadPoolExecutor(max_workers=len(profiles)) as ex:
	futures = []
	for p in profiles:
		futures.append(ex.submit(subprocess.check_call, [
			'cmake',
			'-G',
			'Unix Makefiles',
			'-DCMAKE_TOOLCHAIN_FILE={0}'.format(profiles[p]['toolchain_file']),
			'-DNIMRODG_PLATFORM_STRING={0}'.format(p),
			'-DCMAKE_BUILD_TYPE=MinSizeRel',
			#'-DCMAKE_BUILD_TYPE=Debug',
			base_path
		], cwd=bd[p]))
	
	concurrent.futures.wait(futures)

for p in profiles:
	builddir = bd[p]
	subprocess.check_call(['make', '-j', '-C', builddir, 'agent'])
	agentpath = os.path.join(builddir, 'agent/agent')
	outagent = os.path.join(cwd, 'agent-{0}'.format(p))
	shutil.copyfile(agentpath, outagent)
	shutil.copymode(agentpath, outagent)
	subprocess.check_call([profiles[p]['strip'], '-s', outagent])
