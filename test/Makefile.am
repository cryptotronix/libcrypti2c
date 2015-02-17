# Copyright (C) 2014 Cryptotronix, LLC.

# This file is part of libcrypti2c.

# libcrypti2c is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# libcrypti2c is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with libcrypti2c.  If not, see <http://www.gnu.org/licenses/>.
TESTS = check_libcrypti2c
check_PROGRAMS = check_libcrypti2c
check_libcrypti2c_SOURCES = test_hmac.c $(top_builddir)/libcrypti2c.h
check_libcrypti2c_CFLAGS = @CHECK_CFLAGS@
check_libcrypti2c_LDADD = ../libcrypti2c-0.1.la @CHECK_LIBS@
