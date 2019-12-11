# SQRL Service Provider API for Linux

*SQRL's Service Provider (SSP) API defines a proven application programming interface to support the externalization of SQRL services from the relying website.*

See https://www.grc.com/sqrl/sspapi.htm for further details.

This is an implementation of the SSP API for Linux written in pure C.

## Installation

SSP API Installation for 64-bit Linux (Ubuntu 18.04.3 LTS):
* Create a directory in your downloads folder and cd into it: 
 `mkdir ~/Downloads/SSP-API && cd $_`

* Clone the project's Github repository
`git clone https://github.com/sqrldev/SSP-API-Linux.git`.

* Open <a href="install.html">install.html</a> for further instructions.

## Dependencies

This project currently relies on the following dependencies:

    libsodium-1.0.18-stable
    mbedtls-2.16.3-apache
    openssl-1.1.1d
    qrencode-4.0.2
    LodePNG-20190210
    Blowfish (written by Andrew Carter)
    Berkeley DB 18.1.32
    
 Using `xampp-linux-x64-7.3.11-0` is required only if you haven't got an Apache/PHP environment set up already or want to do so manually.

## License

This project is licensed under the MIT Open Source License.
For more information, please read the file <a href="LICENSE">LICENSE</a>

Please note however, that the dependencies listed are all subject to their own licensing terms and conditions.
