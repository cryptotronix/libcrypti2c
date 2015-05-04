# Cryptotronix libcryptoauth

[![Build Status](https://travis-ci.org/cryptotronix/libcrypti2c.png)](https://travis-ci.org/cryptotronix/libcrypti2c)
[![Stories in Ready](https://badge.waffle.io/cryptotronix/libcrypti2c.png?label=ready&title=Ready)](https://waffle.io/cryptotronix/libcrypti2c)
<a href="https://scan.coverity.com/projects/2309">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/2309/badge.svg"/>
</a>

## About


`libcryptoauth` is a library for interfacing with the Atmel
CryptoAuthentication device. It implements a command middleware that
can be called in other application.

## Installing

Probably best to pick the latest
[release](https://github.com/cryptotronix/libcrypti2c/releases). Clone
this repo if you want to pull the latest source to hack on libcryptoauth.

## Dependencies

- libgcrypt
- libxml
- check (for unit testing)

# Supported Device

Currently the library is designed for the following devices:

- [Atmel ATSHA204](http://www.atmel.com/devices/atsha204.aspx)
- [Atmel ECC108](http://www.atmel.com/devices/atecc108.aspx)

# Status

This software is currently in ***BETA***. Expect numerous changes to the ABI.

# Post install

After installing, don't forget to run `ldconfig`.


![LGPLv3](https://www.gnu.org/graphics/lgplv3-147x51.png)
