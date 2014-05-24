# Cryptotronix libcrypti2c

[![LGPLv3](https://www.gnu.org/graphics/lgplv3-147x51.png)]

[![Build Status](https://travis-ci.org/cryptotronix/libcrypti2c.png)](https://travis-ci.org/cryptotronix/libcrypti2c)

## About


`libcrypti2c` is a user space library for interfacing with embedded cryptographic devices on the I2C bus. It is a small collection of utility functions that handling:

- memory allocation (wrappers that zero out allocated memory)
- very basic logging
- i2c bus acquisition
- crc
- Guile extensions for interactive i2c programming

# Supported Device

Currently the library is design for the following devices:

- Atmel ATSHA204
- Atmel ECC108

# Status

This software is currently in beta.
