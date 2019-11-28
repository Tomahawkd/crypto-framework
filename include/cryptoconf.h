//
// Created by Ghost on 2019/10/18.
//

#ifndef CRYPTO_FRAMEWORK_CRYPTOCONF_H
#define CRYPTO_FRAMEWORK_CRYPTOCONF_H

#if defined _WIN32 || defined __CYGWIN__
# ifdef Dll_EXPORTS
#  ifdef __GNUC__
#   define LIB_API __attribute__ ((dllexport))
#  else
#   define LIB_API __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
#  endif
# else
#  ifdef __GNUC__
#   define LIB_API __attribute__ ((dllimport))
#  else
#   define LIB_API __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
#  endif
# endif
# define LIB_INTERNAL
#else
# if __GNUC__ >= 4
#  define LIB_API __attribute__ ((visibility ("default")))
#  define LIB_INTERNAL  __attribute__ ((visibility ("hidden")))
# else
#  define LIB_API
#  define LIB_INTERNAL
# endif
#endif

#endif //CRYPTO_FRAMEWORK_CRYPTOCONF_H
