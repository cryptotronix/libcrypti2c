# Copyright (C) 2014-2015 Cryptotronix, LLC.

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
TESTS = check_libcryptoauth
check_PROGRAMS = check_libcryptoauth
check_libcryptoauth_SOURCES = test_hmac.c $(top_builddir)/libcryptoauth.h
check_libcryptoauth_CFLAGS = @CHECK_CFLAGS@
check_libcryptoauth_LDADD = ../libcryptoauth-@CRYPTOAUTH_API_VERSION@.la @CHECK_LIBS@ -lgpg-error

bin_PROGRAMS = csu
csu_SOURCES = csu.c $(top_builddir)/libcryptoauth.h
csu_LDADD = -lgcrypt -lgpg-error ../libcryptoauth-@CRYPTOAUTH_API_VERSION@.la
