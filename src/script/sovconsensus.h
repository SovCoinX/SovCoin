// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SOV_SOVCONSENSUS_H
#define SOV_SOVCONSENSUS_H

#if defined(BUILD_SOV_INTERNAL) && defined(HAVE_CONFIG_H)
#include "config/sov-config.h"
  #if defined(_WIN32)
    #if defined(DLL_EXPORT)
      #if defined(HAVE_FUNC_ATTRIBUTE_DLLEXPORT)
        #define EXPORT_SYMBOL __declspec(dllexport)
      #else
        #define EXPORT_SYMBOL
      #endif
    #endif
  #elif defined(HAVE_FUNC_ATTRIBUTE_VISIBILITY)
    #define EXPORT_SYMBOL __attribute__ ((visibility ("default")))
  #endif
#elif defined(MSC_VER) && !defined(STATIC_LIBSOVCONSENSUS)
  #define EXPORT_SYMBOL __declspec(dllimport)
#endif

#ifndef EXPORT_SYMBOL
  #define EXPORT_SYMBOL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SOVCONSENSUS_API_VER 0

typedef enum sovconsensus_error_t
{
    sovconsensus_ERR_OK = 0,
    sovconsensus_ERR_TX_INDEX,
    sovconsensus_ERR_TX_SIZE_MISMATCH,
    sovconsensus_ERR_TX_DESERIALIZE,
} sovconsensus_error;

/** Script verification flags */
enum
{
    sovconsensus_SCRIPT_FLAGS_VERIFY_NONE                = 0,
    sovconsensus_SCRIPT_FLAGS_VERIFY_P2SH                = (1U << 0), // evaluate P2SH (BIP16) subscripts
    sovconsensus_SCRIPT_FLAGS_VERIFY_DERSIG              = (1U << 2), // enforce strict DER (BIP66) compliance
    sovconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9), // enable CHECKLOCKTIMEVERIFY (BIP65)
};

/// Returns 1 if the input nIn of the serialized transaction pointed to by
/// txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
/// the additional constraints specified by flags.
/// If not NULL, err will contain an error/success code for the operation
EXPORT_SYMBOL int sovconsensus_verify_script(const unsigned char *scriptPubKey, unsigned int scriptPubKeyLen,
                                    const unsigned char *txTo        , unsigned int txToLen,
                                    unsigned int nIn, unsigned int flags, sovconsensus_error* err);

EXPORT_SYMBOL unsigned int sovconsensus_version();

#ifdef __cplusplus
} // extern "C"
#endif

#undef EXPORT_SYMBOL

#endif // SOV_SOVCONSENSUS_H
