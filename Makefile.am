# Copyright (C) 2014-2016 Cryptotronix, LLC.

# This file is part of libcryptoauth.

# libcryptoauth is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# libcryptoauth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with libcryptoauth.  If not, see <http://www.gnu.org/licenses/>.

SUBDIRS = lib . test utils
## Place generated object files (.o) into the same directory as their source
## files, in order to avoid collisions when non-recursive make is used.
AUTOMAKE_OPTIONS = subdir-objects

## Define the Data dir so we know where our data files are
AM_CFLAGS = -DDATA_DIR=\"$(pkgdatadir)\"

## Additional flags to pass to aclocal when it is invoked automatically at
## make time. The ${ACLOCAL_FLAGS} variable is picked up from the environment
## to provide a way for the user to supply additional arguments.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

libcryptoauth_la_CPPFLAGS = $(XML_CFLAGS) $(YACL_CFLAGS)
libcryptoauth_la_LIBADD = $(XML_LIBS) $(YACL_LIBS)

pkglib_LTLIBRARIES = libcryptoauth.la

libcryptoauth_la_SOURCES =	src/util.c \
				src/log.c \
		        	src/crc.c \
				src/command_adaptation.c \
				src/i2c.c \
				src/hash.c \
				src/ecdsa.c \
                                src/command_util.c \
                                src/atsha204_command.c \
                                src/atecc108_command.c \
                                src/init.c \
			        src/configfile.c \
				src/otp.c \
				src/util.h \
				src/crc.h \
				src/command_adaptation.h \
				src/hash.h \
				src/command_util.h \
				src/atsha204_command.h

noinst_PROGRAMS = lca-simple lca-really-simple

lca_simple_SOURCES = src/driver.c $(top_builddir)/libcryptoauth.h
lca_simple_LDADD = libcryptoauth.la $(XML_LIBS) $(YACL_LIBS)
#lca_simple_LDFLAGS = -all-static
lca_simple_CPPFLAGS = $(XML_CFLAGS) $(YACL_CFLAGS)

#check_db_LDFLAGS = -all-static  -Wl,--undefined=AES_wrap_key


lca_really_simple_SOURCES = src/simple.c

libcryptoauth_la_LDFLAGS = -version-info $(CRYPTOAUTH_SO_VERSION) \
		           -release $(CRYPTOAUTH_API_VERSION)

## Define the list of public header files and their install location.  The
## nobase_ prefix instructs Automake to not strip the directory part from each
## filename, in order to avoid the need to define separate file lists for each
## installation directory.  This only works if the directory hierarchy in the
## source tree matches the hierarchy at the install location, however.
cryptoauth_includedir = $(includedir)/cryptoauth-$(CRYPTOAUTH_API_VERSION)
nobase_cryptoauth_include_HEADERS = libcryptoauth.h

## Data files
dist_pkgdata_DATA = data/atecc108_default.xml

## The generated configuration header is installed in its own subdirectory of
## $(libdir).  The reason for this is that the configuration information put
## into this header file describes the target platform the installed library
## has been built for.  Thus the file must not be installed into a location
## intended for architecture-independent files, as defined by the Filesystem
## Hierarchy Standard (FHS).
## The nodist_ prefix instructs Automake to not generate rules for including
## the listed files in the distribution on 'make dist'.  Files that are listed
## in _HEADERS variables are normally included in the distribution, but the
## configuration header file is generated at configure time and should not be
## shipped with the source tarball.
cryptoauth_libincludedir = $(libdir)/cryptoauth-$(CRYPTOAUTH_API_VERSION)/include

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = cryptoauth.pc


dist_noinst_SCRIPTS = autogen.sh
