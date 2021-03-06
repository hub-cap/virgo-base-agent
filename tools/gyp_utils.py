import os
import sys
import zipfile
import hashlib
import subprocess

THIS_FILE = os.path.basename(__file__)

VIRGO_EXPORTS = """/*This file is generated by %s */
#include <string.h>
#include "virgo_exports.h"

const void *virgo_ugly_hack = NULL;
%s

const void *virgo__suck_in_symbols(void)
{
  virgo_ugly_hack = (const char*)

%s;

  return virgo_ugly_hack;
}
"""

LUA_MODULES_INIT = """--[[ This file is generated by %s ]]

return {
  version = "%s",
  lua_modules = {
%s
  },
  statics = {
%s
  }
}
"""


def bytecompile_lua(luajit, lua, dot_c_file):
    """bytecompile lua to a c file.
    this function is necessary because luajit looks for the jit files in stupid places
    (including its cwd)"""
    os.chdir(os.path.dirname(luajit))

    ret = subprocess.check_call([luajit, '-bg', lua, dot_c_file])
    if ret != 0:
        raise Exception('failed call to luajit')


def virgo_exports(out, *luas):
    """auto gens a .c file to suck in virgo lua file symbols
    (so that the linker doesn't cast them away)"""
    casts = []
    declarations = []
    for lua in luas:
        name = os.path.basename(lua).split('.lua')[0]
        declarations.append("extern const char *luaJIT_BC_%s[];" % name)
        casts.append("  (size_t)(const char *)luaJIT_BC_%s" % name)

    header = VIRGO_EXPORTS % (THIS_FILE, "\n".join(declarations), " +\n".join(casts))

    with open(out, 'wb') as fp:
        fp.write(header)


def is_gyp_bundled(path):
    #TODO: make me for reals
    return int(False)


def _split_path(p):
    split = []
    while p:
        p, chunk = os.path.split(p)
        split.insert(0, chunk)
    return split


def stupid_find(root):
    file_list = []
    for base_path, _, files in os.walk(root):
        file_list += ["%s/%s" % (base_path, f) for f in files]
    return file_list


def bundle_list_from_list_file(bundle_list_file):
    file_list = []
    with open(bundle_list_file) as f:
        lines = f.readlines()
        for line in lines:
            filepath = os.path.abspath(os.path.relpath(line.strip(' \t\r\n'), "HACK_DIRECTORY"))
            if os.path.isfile(filepath):
                if sys.platform == 'win32':
                    # fix for weird gyp path excaping problem
                    filepath = filepath.replace('\\', '\\\\')
                file_list.append(filepath)
    return file_list


class VirgoZip(zipfile.ZipFile):
    def __init__(self, root, out):
        zipfile.ZipFile.__init__(self, out, 'w', zipfile.ZIP_DEFLATED)
        self.root = root
        self.lua_modules = set()
        self.statics = []

    def add(self, source):
        relPath = os.path.relpath(source, self.root)
        self.write(source, relPath)
        split = _split_path(relPath)

        #record lua modules we find
        if split[0] == "lua_modules":
            module = os.path.splitext(split[1])[0]
            self.lua_modules.add(module)
        elif split[0] == "static":
            self.statics.append(relPath)

    def insert_lua_modules_init(self, bundle_version):
        """make a lua importable file with some meta info about the bundle"""
        modules = ',\n'.join(['    "%s"' % x for x in self.lua_modules])
        statics = ',\n'.join(['    "%s"' % x for x in self.statics])
        init = LUA_MODULES_INIT % (THIS_FILE, bundle_version, modules, statics)
        if sys.platform == 'win32':
            # store the paths with forward slashes, so the lua path.posix will work
            init = init.replace('\\', '/')
        self.writestr('lua_modules/init.lua', init)


def make_bundle(root, bundle_version, out, bundle_list_file):
    z = VirgoZip(root, out)

    file_list = bundle_list_from_list_file(bundle_list_file)
    for lua in file_list:
        z.add(lua)

    z.insert_lua_modules_init(bundle_version)
    z.close()

    print('Wrote %d files to %s' % (len(file_list), out))


def hash(*args):
    m = hashlib.md5()
    for arg in args:
        m.update(arg)
    return m.hexdigest()

if __name__ == "__main__":
    args = sys.argv[2:]
    func = locals().get(sys.argv[1], None)
    if not func:
        raise AttributeError('you tried to call a function that doesn\'t exist %s' % (sys.argv[1]))
    response = func(*args)
    if isinstance(response, (list, tuple)):
        response = "\n".join(response)
    if response:
        print response
