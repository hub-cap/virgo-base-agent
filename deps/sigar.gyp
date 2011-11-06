{
  'targets': [
    {
      'target_name': 'sigar',
      'type': 'static_library',
      'sources': [
        'sigar/src/sigar.c',
        'sigar/src/sigar_cache.c',
        'sigar/src/sigar_fileinfo.c',
        'sigar/src/sigar_format.c',
        'sigar/src/sigar_getline.c',
        'sigar/src/sigar_ptql.c',
        'sigar/src/sigar_signal.c',
        'sigar/src/sigar_util.c',
        'sigar-configs/sigar_version_autoconf_<(OS).c',
      ],
      'include_dirs': [
          'sigar/include',
        ],
      'direct_dependent_settings': {
        'include_dirs': [
          'sigar/include',
        ],
      },
      'conditions': [
        [ 'OS=="win"', {
          'include_dirs': [
            'sigar/src/os/win32',
          ],
          'defines': [
            'WIN32_LEAN_AND_MEAN',
            '_BIND_TO_CURRENT_MFC_VERSION=1',
            '_BIND_TO_CURRENT_CRT_VERSION=1',
            '_CRT_SECURE_NO_WARNINGS',
          ],
          'sources': [
            'sigar/src/os/win32/peb.c',
            'sigar/src/os/win32/win32_sigar.c',
            'sigar/src/os/win32/wmi.cpp',
          ],
        }],
        ['OS=="mac" or OS=="freebsd"', {
          'defines': [
            # TODO: test on freebsd
            'DARWIN',
          ],
          'include_dirs': [
            'sigar/src/os/darwin',
            '/Developer/Headers/FlatCarbon/',
          ],
          'sources': [
            'sigar/src/os/darwin/darwin_sigar.c',
          ],
        }],
        ['OS=="solaris"', {
          'include_dirs': [
            'sigar/src/os/solaris',
          ],
          'sources': [
            'sigar/src/os/solaris/get_mib2.c',
            'sigar/src/os/solaris/kstats.c',
            'sigar/src/os/solaris/procfs.c',
            'sigar/src/os/solaris/solaris_sigar.c',
          ],
        }],
        ['OS=="linux"', {
          'include_dirs': [
            'sigar/src/os/linux',
          ],
          'sources': [
            'sigar/src/os/linux/linux_sigar.c',
          ],
        }],
      ],
    }
  ],
}
