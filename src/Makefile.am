DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

SOV_CONFIG_INCLUDES=-I$(builddir)/config
SOV_INCLUDES=-I$(builddir) -I$(builddir)/obj $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

SOV_INCLUDES += -I$(srcdir)/secp256k1/include
SOV_INCLUDES += $(UNIVALUE_CFLAGS)

LIBSOV_SERVER=libsov_server.a
LIBSOV_WALLET=libsov_wallet.a
LIBSOV_COMMON=libsov_common.a
LIBSOV_CLI=libsov_cli.a
LIBSOV_UTIL=libsov_util.a
LIBSOV_CRYPTO=crypto/libsov_crypto.a
LIBSOVQT=qt/libsovqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  crypto/libsov_crypto.a \
  libsov_util.a \
  libsov_common.a \
  libsov_server.a \
  libsov_cli.a
if ENABLE_WALLET
SOV_INCLUDES += $(BDB_CPPFLAGS)
EXTRA_LIBRARIES += libsov_wallet.a
endif
if ENABLE_ZMQ
EXTRA_LIBRARIES += libsov_zmq.a
endif

if BUILD_SOV_LIBS
lib_LTLIBRARIES = libsovconsensus.la
LIBSOV_CONSENSUS=libsovconsensus.la
else
LIBSOV_CONSENSUS=
endif

bin_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_SOVD
  bin_PROGRAMS += sovd
endif

if BUILD_SOV_UTILS
  bin_PROGRAMS += sov-cli sov-tx
endif

.PHONY: FORCE check-symbols check-security
# sov core #
SOV_CORE_H = \
  addrdb.h \
  activemasternode.h \
  addressindex.h \
  spentindex.h \
  addrman.h \
  alert.h \
  amount.h \
  arith_uint256.h \
  base58.h \
  bip39.h \
  bip39_english.h \
  bloom.h \
  cachemap.h \
  cachemultimap.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  core_io.h \
  core_memusage.h \
  privatesend.h \
  privatesend-client.h \
  privatesend-server.h \
  privatesend-util.h \
  dsnotificationinterface.h \
  governance.h \
  governance-classes.h \
  governance-exceptions.h \
  governance-object.h \
  governance-validators.h \
  governance-vote.h \
  governance-votedb.h \
  flat-database.h \
  hash.h \
  hdchain.h \
  httprpc.h \
  httpserver.h \
  init.h \
  instantx.h \
  key.h \
  keepass.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  masternode.h \
  masternode-payments.h \
  masternode-sync.h \
  masternodeman.h \
  masternodeconfig.h \
  memusage.h \
  merkleblock.h \
  messagesigner.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netfulfilledman.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  prevector.h \
  primitives/block.h \
  primitives/transaction.h \
  protocol.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpc/client.h \
  rpc/protocol.h \
  rpc/server.h \
  scheduler.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  serialize.h \
  spork.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/pagelocker.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  tinyformat.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utilstrencodings.h \
  utiltime.h \
  validation.h \
  validationinterface.h \
  version.h \
  versionbits.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/obj/build.h \
	  $(abs_top_srcdir)
libsov_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between sovd and sov-qt
libsov_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libsov_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsov_server_a_SOURCES = \
  activemasternode.cpp \
  addrman.cpp \
  addrdb.cpp \
  alert.cpp \
  bloom.cpp \
  chain.cpp \
  checkpoints.cpp \
  dsnotificationinterface.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  instantx.cpp \
  dbwrapper.cpp \
  governance.cpp \
  governance-classes.cpp \
  governance-object.cpp \
  governance-validators.cpp \
  governance-vote.cpp \
  governance-votedb.cpp \
  masternode.cpp \
  masternode-payments.cpp \
  masternode-sync.cpp \
  masternodeconfig.cpp \
  masternodeman.cpp \
  merkleblock.cpp \
  messagesigner.cpp \
  miner.cpp \
  net.cpp \
  netfulfilledman.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  privatesend.cpp \
  privatesend-server.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/masternode.cpp \
  rpc/governance.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  sendalert.cpp \
  spork.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(SOV_CORE_H)

if ENABLE_ZMQ
LIBSOV_ZMQ=libsov_zmq.a

libsov_zmq_a_CPPFLAGS = $(SOV_INCLUDES) $(ZMQ_CFLAGS)
libsov_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsov_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between sovd and sov-qt, but only linked
# when wallet enabled
libsov_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES)
libsov_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsov_wallet_a_SOURCES = \
  keepass.cpp \
  privatesend-client.cpp \
  privatesend-util.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  policy/rbf.cpp \
  $(SOV_CORE_H)

# crypto primitives library
crypto_libsov_crypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_CONFIG_INCLUDES) $(PIC_FLAGS)
crypto_libsov_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(PIC_FLAGS)
crypto_libsov_crypto_a_SOURCES = \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/aes_helper.c \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h

# x16r
crypto_libsov_crypto_a_SOURCES += \
  crypto/blake.c \
  crypto/bmw.c \
  crypto/cubehash.c \
  crypto/echo.c \
  crypto/groestl.c \
  crypto/jh.c \
  crypto/keccak.c \
  crypto/luffa.c \
  crypto/shavite.c \
  crypto/simd.c \
  crypto/skein.c \
  crypto/sph_hamsi.c \
  crypto/sph_hamsi_helper.c \
  crypto/sph_fugue.c \
  crypto/sph_shabal.c \
  crypto/sph_whirlpool.c \
  crypto/sph_sha2.c \
  crypto/sph_sha512.c \
  crypto/sph_blake.h \
  crypto/sph_bmw.h \
  crypto/sph_cubehash.h \
  crypto/sph_echo.h \
  crypto/sph_groestl.h \
  crypto/sph_jh.h \
  crypto/sph_keccak.h \
  crypto/sph_luffa.h \
  crypto/sph_shavite.h \
  crypto/sph_simd.h \
  crypto/sph_skein.h \
  crypto/sph_hamsi.h \
  crypto/sph_fugue.h \
  crypto/sph_shabal.h \
  crypto/sph_whirlpool.h \
  crypto/sph_sha2.h \
  crypto/sph_types.h

# common: shared between sovd, and sov-qt and non-server tools
libsov_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES)
libsov_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsov_common_a_SOURCES = \
  amount.cpp \
  arith_uint256.cpp \
  base58.cpp \
  bip39.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/merkle.cpp \
  core_read.cpp \
  core_write.cpp \
  hash.cpp \
  hdchain.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  primitives/block.cpp \
  primitives/transaction.cpp \
  protocol.cpp \
  pubkey.cpp \
  scheduler.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/sign.cpp \
  script/standard.cpp \
  $(SOV_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libsov_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES)
libsov_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsov_util_a_SOURCES = \
  support/pagelocker.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  random.cpp \
  rpc/protocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  uint256.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(SOV_CORE_H)

if GLIBC_BACK_COMPAT
libsov_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between sov-cli and sov-qt
libsov_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES)
libsov_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsov_cli_a_SOURCES = \
  rpc/client.cpp \
  $(SOV_CORE_H)

nodist_libsov_util_a_SOURCES = $(srcdir)/obj/build.h
#

# sovd binary #
sovd_SOURCES = sovd.cpp
sovd_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES)
sovd_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
sovd_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
sovd_SOURCES += sovd-res.rc
endif

sovd_LDADD = \
  $(LIBSOV_SERVER) \
  $(LIBSOV_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBSOV_UTIL) \
  $(LIBSOV_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

if ENABLE_ZMQ
sovd_LDADD += $(LIBSOV_ZMQ) $(ZMQ_LIBS)
endif

if ENABLE_WALLET
sovd_LDADD += libsov_wallet.a
endif

sovd_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)

# sov-cli binary #
sov_cli_SOURCES = sov-cli.cpp
sov_cli_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES) $(EVENT_CFLAGS)
sov_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
sov_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
sov_cli_SOURCES += sov-cli-res.rc
endif

sov_cli_LDADD = \
  $(LIBSOV_CLI) \
  $(LIBUNIVALUE) \
  $(LIBSOV_UTIL)
sov_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# sov-tx binary #
sov_tx_SOURCES = sov-tx.cpp
sov_tx_CPPFLAGS = $(AM_CPPFLAGS) $(SOV_INCLUDES)
sov_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
sov_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

if TARGET_WINDOWS
sov_tx_SOURCES += sov-tx-res.rc
endif

sov_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBSOV_COMMON) \
  $(LIBSOV_UTIL) \
  $(LIBSOV_CRYPTO) \
  $(LIBSECP256K1)

sov_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# sovconsensus library #
if BUILD_SOV_LIBS
include_HEADERS = script/sovconsensus.h
libsovconsensus_la_SOURCES = \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  hash.cpp \
  primitives/transaction.cpp \
  pubkey.cpp \
  script/sovconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  uint256.cpp \
  utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libsovconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libsovconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libsovconsensus_la_LIBADD = $(LIBSECP256K1)
libsovconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_SOV_INTERNAL
libsovconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a
CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = obj/build.h

EXTRA_DIST = leveldb

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
