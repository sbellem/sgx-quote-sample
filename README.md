**NOTE**: Experimental work-in-progress repository based on Intel's original
[sgx-ra-sample](https://github.com/intel/sgx-ra-sample) repository. The goal is to
provide a minimal client example that only requests a quote from an enclave. The server
component that communicates with Intel's attestation service has been removed.

# Intel&reg; SGX Quote Generation Sample

<!--
* [Introduction](#intro)
* [What's New](#new)
* [License](#license)
* [Building](#build)
  * [Linux*](#build-linux)
    * [Linux build notes](#build-linux-notes)
* [Running (Quick-start)](#running-quick)
* [Running (Advanced)](#running-adv)
* [Sample Output](#output)

## <a name="intro"></a>Introduction
-->
This code sample demonstrates a simple client requesting a quote from an enclave. Upon
receiving the quote from the enclave, the client dumps it to the terminal. It could be
sent to Intel's Attestation Service (IAS) by another component.

A docker-compose based development environment is provided, and is the recommended way
to try this sample, as it has not been tested on other platforms. See the Quickstart
section just below to see how to try it.

## <a name="quickstart"></a>Quickstart
### Prerequisites
* You need [docker](https://docs.docker.com/engine/install/) and
  [docker-compose](https://docs.docker.com/compose/install/).

* The docker-based development environment assumes it is running on an SGX-enabled
  processor. If you are not sure whether your computer supports SGX, and/or how to
  enable it, see https://github.com/ayeks/SGX-hardware#test-sgx.

* Obtain an **Unlinkable** subscription key for the
  [Intel SGX Attestation Service Utilizing Enhanced Privacy ID (EPID)](https://api.portal.trustedservices.intel.com/).

* Edit the `settings` file to add your `SPID`, `IAS_PRIMARY_SUBSCRIPTION_KEY`, and
  `IAS_SECONDARY_SUBSCRIPTION_KEY`. **DO NOT COMMIT changes for this file, as it will
  contain secret data, namely your subscription keys.**

Build the image:

```shell
$ docker-compose build
```

Generate a quote:

```shell
$ docker-compose up genquote
sgx-quote-sample_aesm_1 is up-to-date
Recreating sgx-quote-sample_genquote_1 ... done
Attaching to sgx-quote-sample_genquote_1
genquote_1  |
genquote_1  | MRENCLAVE:        5abbaaa5dc057d0a1c82815ca513ca610778d440e367d42fbd8a01de5cc68d54
genquote_1  | MRSIGNER:         bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd
genquote_1  | Report Data:      7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d90690000000000000000000000000000000000000000000000000000000000000000
genquote_1  |
genquote_1  | Quote, ready to be sent to IAS (POST /attestation/v4/report):
genquote_1  | {
genquote_1  |   "isvEnclaveQuote":"AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+hkvH3eqUYIQqw8ZooL4SSwCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFq7qqXcBX0KHIKBXKUTymEHeNRA42fUL72KAd5cxo1UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/g7Flf/H8U7ktwYFIodZd/C1LH6PWdyhK3dIAEm2QaQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAABAug2XSbZYmz5e2QxUpqpKqisbwLr7Et/kfDVFEWrp1ha+YeIA64w132OSpxthtki4g31YB1MnQrL5AgUAN075asTXS4DN/FJp7xxAnH2aJr49pdW+OuqwIFx3WdSNLRX31mn5c0ZwQRT6hV40XTiYXgOC8ov5/k+Nz2H4xrkpk1E/GFu40GloZrL5IYmFCemSeAGWXYCDUDQ5cszFQX80ew54kr5hdXjWdodRVIb5dEDiPECqMcMdFEqigr+euewZi6KS33wA1PgwlkX1TRmTZQhDWdZtIfXjd+z/4F6RpDkntkiN3qhAAGfgbkbM1ilXxsHCwgpTZNTXZmzCRtoYkYvyiDJ2Tgl5E8UBMwtXrMRAhl77KcrMEn/zTtynkgx/63JePd9E4+Ra3DmgBAABNtiNesQr+XcnDwXabSsUSBxtD9GfudBA7FKYztf5dxv7zdzdW5zZprCQ+fU2u+8Sb/1Eu7ACMOhEVgKKTXN3Ij/OHo3Yoot1qjdQx3YejX00JhSVY/+WxcpbfxUwiMbBDTxqTzPxPG8AUqvwIeqNVkeDgJ4cFwgp5vMvQtlNJlM3NCIPLnG+EfjQnOMEIBJyKjNuRKjgBWirYNrWI8PwvbHKkkuwXfOnxYXc6wKoKlX+r4k4bBsxEulgTk2ZBCbHvdnd2ybgPvojXitQPG/3rhBUur2/WIESOdUvlErvizCxC1x5OKuBAImnt/0JWarV3AQlUy6zJ5WofaGZM7q1zfhssMMlPv7m9G0d9zrWmqin7N25+5mCPG/hK0q7HReqS8JYl+KjKDvbLCBnKrj44fRWEo7QDzOoNsI1x6HNh1ZSixz+bmr2A2OvQ+OOo7f5/cnuGFHxi/Leybtmyulz7EOQyE2f7i61E8kus7gRIo8sm5dFg3I/a",
genquote_1  |   "nonce":"b516b8e1e63d4437930cb2ea56f1c451"
genquote_1  | }
genquote_1  |
genquote_1  | See https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf
sgx-quote-sample_genquote_1 exited with code 0
```

In the above output, the `MRENCLAVE`, `MRSIGNER` and report data of the quote are shown,
in hexadecimal format. The first 32 bytes of the report data are the sha256 of the
string 'Hello World!'. This is currently hardcoded in the enclave code just as an
example of using the report data field with custom data.

The quote is printed out in a json-like format, which is ready to be sent to IAS for
verification. The API specifications for IAS is documented at
https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf.

### Sending the quote to IAS
Here's a simple example of sending out the quote to IAS for verification using Python's
`requests` library:

```python
import requests

url = 'https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report'
request_body = {
    'isvEnclaveQuote': 'AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+hkvH3eqUYIQqw8ZooL4SSwCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFq7qqXcBX0KHIKBXKUTymEHeNRA42fUL72KAd5cxo1UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/g7Flf/H8U7ktwYFIodZd/C1LH6PWdyhK3dIAEm2QaQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAABAug2XSbZYmz5e2QxUpqpKqisbwLr7Et/kfDVFEWrp1ha+YeIA64w132OSpxthtki4g31YB1MnQrL5AgUAN075asTXS4DN/FJp7xxAnH2aJr49pdW+OuqwIFx3WdSNLRX31mn5c0ZwQRT6hV40XTiYXgOC8ov5/k+Nz2H4xrkpk1E/GFu40GloZrL5IYmFCemSeAGWXYCDUDQ5cszFQX80ew54kr5hdXjWdodRVIb5dEDiPECqMcMdFEqigr+euewZi6KS33wA1PgwlkX1TRmTZQhDWdZtIfXjd+z/4F6RpDkntkiN3qhAAGfgbkbM1ilXxsHCwgpTZNTXZmzCRtoYkYvyiDJ2Tgl5E8UBMwtXrMRAhl77KcrMEn/zTtynkgx/63JePd9E4+Ra3DmgBAABNtiNesQr+XcnDwXabSsUSBxtD9GfudBA7FKYztf5dxv7zdzdW5zZprCQ+fU2u+8Sb/1Eu7ACMOhEVgKKTXN3Ij/OHo3Yoot1qjdQx3YejX00JhSVY/+WxcpbfxUwiMbBDTxqTzPxPG8AUqvwIeqNVkeDgJ4cFwgp5vMvQtlNJlM3NCIPLnG+EfjQnOMEIBJyKjNuRKjgBWirYNrWI8PwvbHKkkuwXfOnxYXc6wKoKlX+r4k4bBsxEulgTk2ZBCbHvdnd2ybgPvojXitQPG/3rhBUur2/WIESOdUvlErvizCxC1x5OKuBAImnt/0JWarV3AQlUy6zJ5WofaGZM7q1zfhssMMlPv7m9G0d9zrWmqin7N25+5mCPG/hK0q7HReqS8JYl+KjKDvbLCBnKrj44fRWEo7QDzOoNsI1x6HNh1ZSixz+bmr2A2OvQ+OOo7f5/cnuGFHxi/Leybtmyulz7EOQyE2f7i61E8kus7gRIo8sm5dFg3I/a',
    'nonce': 'b516b8e1e63d4437930cb2ea56f1c451',
}
headers = {
    'Content-Type': 'application/json',
    'Ocp-Apim-Subscription-Key': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
}

res = requests.post(url, json=request_body, headers=headers)
```

The json response:

```python
>>> res.json()
{'nonce': 'b516b8e1e63d4437930cb2ea56f1c451',
 'id': '333333333333333333333333333333333333333',
 'timestamp': '2021-03-18T22:50:28.912733',
 'version': 4,
 'advisoryURL': 'https://security-center.intel.com',
 'advisoryIDs': ['INTEL-SA-00161',
  'INTEL-SA-00381',
  'INTEL-SA-00389',
  'INTEL-SA-00320',
  'INTEL-SA-00329',
  'INTEL-SA-00220',
  'INTEL-SA-00270',
  'INTEL-SA-00293'],
 'isvEnclaveQuoteStatus': 'GROUP_OUT_OF_DATE',
 'platformInfoBlob': '150200650400090000111102040101070000000000000000000B00000B000000020000000000000B5BCC672AFB05A02923F4DDE83DC489558DB86EE96AFFE6FBDC98A75F2191E7C67676FE11323B08951B511E68EBD0614C14641F75593FDC7FBAE9520268FFC0CB42',
 'isvEnclaveQuoteBody': 'AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+hkvH3eqUYIQqw8ZooL4SSwCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFq7qqXcBX0KHIKBXKUTymEHeNRA42fUL72KAd5cxo1UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/g7Flf/H8U7ktwYFIodZd/C1LH6PWdyhK3dIAEm2QaQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'}
```

#### Verifying the report authenticity
TODO: check report signature, in response header

#### Verifying the MRENCLAVE, and report data
Getting the MRENCLAVE, MRSIGNER and report data out of the report requires to know
the structure of a quote:

```C
typedef struct _quote_t
{
    uint16_t            version;        /* 0   */
    uint16_t            sign_type;      /* 2   */
    sgx_epid_group_id_t epid_group_id;  /* 4   */
    sgx_isv_svn_t       qe_svn;         /* 8   */
    sgx_isv_svn_t       pce_svn;        /* 10  */
    uint32_t            xeid;           /* 12  */
    sgx_basename_t      basename;       /* 16  */
    sgx_report_body_t   report_body;    /* 48  */
    uint32_t            signature_len;  /* 432 */
    uint8_t             signature[];    /* 436 */
} sgx_quote_t;
```

The report body is the structure that contains the MRENCLAVE:

```C
typedef struct _report_body_t
{
    sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
    sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
    uint8_t                 reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  /* ( 20) */
    sgx_isvext_prod_id_t    isv_ext_prod_id;/* ( 32) ISV assigned Extended Product ID */
    sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
    sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
    uint8_t                 reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  /* ( 96) */
    sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
    uint8_t                 reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  /* (160) */
    sgx_config_id_t         config_id;      /* (192) CONFIGID */
    sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
    sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
    sgx_config_svn_t        config_svn;     /* (260) CONFIGSVN */
    uint8_t                 reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  /* (262) */
    sgx_isvfamily_id_t      isv_family_id;  /* (304) ISV assigned Family ID */
    sgx_report_data_t       report_data;    /* (320) Data provided by the user */
} sgx_report_body_t;
```

```python
import base64
import hashlib

isv_enclave_quote_body = res.json()['isvEnclaveQuoteBody']
report_body = base64.b64decode(isv_enclave_quote_body)[48:432]

report_body[64:96].hex()    # mrenclave
# 5abbaaa5dc057d0a1c82815ca513ca610778d440e367d42fbd8a01de5cc68d54

report_body[320:384].hex()  # report data
# 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d90690000000000000000000000000000000000000000000000000000000000000000

# The sha256 of 'Hello World!' is supposed to be in the report data ...
report_body[320:384][:32].hex() == hashlib.sha256(b'Hello World!').hexdigest()
# True
```

<!--
## <a name="new"></a>What's New

See the [full release history](CHANGES.md).

### v3.1

Release on 6/25/2020.

 * Default to version 4 of the Attestation API.

 * Remove references to the PSE in Linux builds.

## <a name="license"></a>License

Except as otherwise noted, source code is made available under the
Intel Sample Source Code license. See the LICENSE file for terms.

## <a name="build"></a>Building the Sample

For simplicity, the client and server are packaged and built together. In a real-world environment, these would be separate builds.

The service provider's remote attestation server _does not require Intel SGX hardware or software to run_. The server in this code sample requires the Intel SGX SDK header files in order to simplify the code and build process, but this is not strictly necessary.

### <a name="build-linux"></a>Linux

#### Prerequisites

* Obtain a subscription key for the [Intel SGX Attestation Service Utilizing Enhanced Privacy ID (EPID)](https://api.portal.trustedservices.intel.com/)

* Ensure that you have one of the following operating systems:

  * CentOS 7.4 (64-bit)
  * Ubuntu 18.04 LTS (64-bit)

* Ensure that you have built and installed the Intel SGX packages:

  * [Intel SGX Software Development Kit and Platform Software package for Linux](https://github.com/intel/linux-sgx) 2.8 or later
  * [Intel SGX Driver for Linux](https://github.com/intel/linux-sgx)


* Run the following commands to install the required packages to build the RA code sample (this assumes you have installed the dependencies for the Intel SGX SDK and PSW package)

  * On CentOS 7.4

  ```
  $ yum install libcurl-devel
  ```

* Run the following command to get your system's OpenSSL version. It must be
at least 1.1.0:

 ```
 $ openssl version
 ```

  * If necessary, download the source for the latest release of OpenSSL 1.1.0, then build and install it into a _non-system directory_ such as /opt (note that both `--prefix` and `--openssldir` should be set when building OpenSSL 1.1.0). For example:

   ```
  $ wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
  $ tar xf openssl-1.1.0i.tar.gz
  $ cd openssl-1.1.0i
  $ ./config --prefix=/opt/openssl/1.1.0i --openssldir=/opt/openssl/1.1.0i
  $ make
  $ sudo make install
   ```

#### Configure and compile

First, prepare the build system (GNU* automake and autoconf) by running `bootstrap`, and then configure the software package using the `configure` command. You'll need to specify the location of OpenSSL 1.1.0. See the build notes section for additional options to `configure`.

  ```
  $ ./bootstrap
  $ ./configure --with-openssldir=/opt/openssl/1.1.0i
  $ make
  ```

As this is a code sample and not a production application, 'make install' is
not implemented.

Both `make clean` and `make distclean` are supported.

#### <a name="build-linux-notes"></a>Linux build notes

##### User agents

The service provider sample supports two user agents on Linux for communicating with the Intel Attestation Server (IAS): libcurl and wget.

The **wget** agent runs `wget` via execvp(2) to GET and POST data to IAS.

The **libcurl** agent does not depend on external commands. Pre-packaged distributions of libcurl are typically built against OpenSSL, GnuTLS, or NSS.

libcurl may be built against your local distribution's OpenSSL package (which is 1.0.x for the supported OS's). If so, you will receive a warning message at link time _which can be ignored_. Only libcrypto is required from the OpenSSL 1.1.0 build and it will not conflict with libcurl's OpenSSL dependencies.

##### Configuration options

You can disable libcurl at build time by supplying `--disable-agent-libcurl` to `configure`, in which case the server will fall back to using `wget` as its agent.

The `configure` script will attempt to auto-detect your Intel SGX SDK directory, but if for some reason it can't find it, then you should supply the path via `--with-sgxsdk=PATH`.

You can build the client for simulation mode using `--enable-sgx-simulation`. Note that Remote Attestation will fail for clients running in simulation mode, as this mode has no hardware protection.


### Enclave Verification Policy

The build process automatically generates a file named ```policy``` on Linux which
contains the enclave verification policy settings. The server validates the enclave
by examining the contents of the report, and ensuring the following attributes in the
report match those specified in the policy file:

 * The enclave's MRSIGNER value (this is a SHA256 hash generated from the signing key)

 * The enclave's MRENCLAVE value (this is a SHA256 hash generated from the enclave's
   measurement)

 * The Product ID number ('''ProdID''' in `Enclave.config.xml`)

 * The software vendor's enclave version number ('''ISVSVN''' in `Enclave.config.xml`)

 * Whether or not the enclave was built in debug mode

The policy file is prepopulated with the correct values. By modifying the parameters in the
policy file, you can create requirements that the enclave report doesn't meet and thus
trigger attestation failures.

This demonstrates one of the key functions of remote attestation: the client enclave can be
rejected if it originates from an unrecognized signer, containes an unrecognized product identifier,
or if it's simply too old. The first prevents unauthorized and unknown enclaves from using the
service. The latter two allows software venders to force end users to update their software.

The policy file is also set to specifically allow debug-mode enclaves. ''This is acceptable
for a code sample, but a debug-mode enclave should never, ever be accepted by production service
provider!''

### Linux

A wrapper script, `run-client` is provided for convenience. This is a Bourne shell
script that does the following:

* Set LD_LIBRARY_PATH
* Parse the `settings` and `policy` files (which are sourced as shell scripts)
* Execute the client application with the corresponding command-line options

You can pass command-line options to the underlying executables via the wrapper scripts.

To execute:

* Edit the `settings` file

* Run the client:

  ```
  ./run-client [ options ] [ host[:port] ]
  ```

The `policy` file is automatically generated for you from the Enclave metadata
in `Enclave_config.xml` and the signed enclave, `Enclave.signed.so`. In order to test
the policy validation functions, you can edit the parameters in this file and
restart the server. Your changes will be lost, however, if you do a
`make clean`.

## <a name="running-adv"></a>Running the Sample (Advanced Options)

Use verbose mode (`-v`) to see additional details about the messages sent between the client and server. This information is printed to stderr.

Use debug mode (`-d`) to view debugging information.

### Client

```
usage: client [ options ] [ host[:port] ]

Required:
  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte
                           ASCII hex string

  -P, --pubkey-file=FILE   File containing the public key of the service
                           provider.

  -S, --spid-file=FILE     Set the SPID from a file containing a 32-byte
                           ASCII hex string

  -d, --debug              Show debugging information

  -e, --epid-gid           Get the EPID Group ID instead of performing
                           an attestation.

  -l, --linkable           Specify a linkable quote (default: unlinkable)

  -m, --pse-manifest       Include the PSE manifest in the quote

  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string

  -p, --pubkey=HEXSTRING   Specify the public key of the service provider
                           as an ASCII hex string instead of using the
                           default.

  -q                       Generate a quote instead of performing an
                           attestation.

  -r                       Generate a nonce using RDRAND

  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string

  -v, --verbose            Print decoded RA messages to stderr

  -z                       Read from stdin and write to stdout instead
                           connecting to a server.

```
By default, the client connects to a server running on localhost, port 7777, and attempts a remote attestation.

If `-z` is supplied, it will run interactively, accepting input from stdin and writing to stdout. This makes it possible to copy and paste output from the client to the server, and visa-versa.

The `-q` option will generate and print a quote instead of performing remote attestation. This quote can be submitted as-is to the Intel Attestation Service, and is intended for debugging RA workflows and IAS communications.

The `-p` and `-P` options let you override the service provider's public key for debugging and testing purposes. This key is normally hardcoded into the enclave to ensure it only attests to the expected service provider.

### Client

```
---- Copy/Paste Msg0||Msg1 Below to SP -------------------------------------
000000006beaf1641d386157559ecbc95330c407442f5169c0adc13e9faa6b94e1011acbdfb157867dbd65633b023cc95a1d19eda341f5bbfed20eebdc04c708b99e40b2e00a0000
----------------------------------------------------------------------------
Waiting for msg2

---- Copy/Paste Msg3 Below to SP -------------------------------------------
d0cf09ac6230516154c174906b2937476beaf1641d386157559ecbc95330c407442f5169c0adc13e9faa6b94e1011acbdfb157867dbd65633b023cc95a1d19eda341f5bbfed20eebdc04c708b99e40b20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000e00a00000700060000000000928a6b0e3cddad56eb3badaa3b63f71f26e915240eea8bff76b4f95c099997ff04040204ff8000000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000700000000000000c168cba257604a3ba4ac9650cbf02c8bb1474bac999566dd3f9e2e9c7ed0dd280000000000000000000000000000000000000000000000000000000000000000bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007275d839674afa2a4236b8a98d414db129efdf8264d25dee20b758bd5c589a3b0000000000000000000000000000000000000000000000000000000000000000a802000071b644877107086edf039798938260c194b21e3ee07315692fc8132fe6c051b16f9efabb0351cbd26da9996769ccb8b4b048f7438b0a1fa3da114afd7b549bf39f5ee406e84657b6b98abd3f2d47c07b3a90538dcbba978de8d049879cf68730208cb4b4de24280dd1179086062ab303ac7f5b1dcae6129ea3befeafa1d4dcba800264baa52cf1541c17b664d801f2b51d1bf2e2e231b9bd359d22979194de11162564e76b0bdb9eae825ea684823cb140d2567262e7834483e8a0db0f389f89253f75bf17295b29bb219f6e8dfb68c0e8f836ee6706191321c2c94489e01efd9fa8568cb0c175b85e8c0261a423202bd5a051227a5ef88cc9a798bcebd958dbc4bdf57f377a954112d072123bea83fe7049092e7b5f78a3e3d9af75d34f94bef36ded123364305fc4ae72e168010000a1e4f316f843d77dcdce958bea5111667110e171720c63c0e71e4e497f553790894d058dc36881ce30017263667e24d35b3ea6666840f3c84ee7ec4343e6268d043bdf35a3768a0689bda434e87c0289a9c353584dbe58e7400e763ac0b7d935a3365665363c6d2b607a74c8fc7fe4ed2c9458186b2b9db88a46d4b0d16021f79082873b483b1e593e5ba589f93a462c1fcf0a2122732ed3bc2af337ab2d7e767e644b32ef100948b448a2bf335890c4ef199b2ffc9009b5068e2eecb7b3455c905c2c3e1c4845d753e17d025e04fb983a7994b455244d01345f71b575ad43d381453b848cd6e29cca2947ef3df72fe3ae61bd5bb15d46ba55b262dbdd4060faf7ed787a50e208e970d7dcea273770ace4ee597135766629fd628529cfd6cc28385192ad83506d97bdcacd2e4814a31f6bd1bd6452599b76aff500a24f137428ded821df2893702bb4887fa6fd2bec51b3d0addf94e80e11edb7515b7572a3d911e1f709e3967ea21f3c0c695afca00b29fe6a88e4911a0a
----------------------------------------------------------------------------

---- Enclave Trust Status from Service Provider ----------------------------
Enclave TRUSTED
```
-->
