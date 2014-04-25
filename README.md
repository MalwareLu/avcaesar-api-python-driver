avcaesar-api-python-driver
==========================

Python & OS Support
-------------------

avcaesar\_api works with python 3.
avcaesar\_api works on Unix/Linux, OS X, and Windows.

Installation
------------

If you have installed pip3, you can install with `pip-3.2 install avcaesar_api` (The command name for pip depends of your python installation).
Otherwise you can install from the project source by downloading it and do `python3 setup.py install`.

Configuration
-------------

To configure your API key, create a new file `~/.avcaesar_api.cfg` in your home directory with the following content:

    [api]
    key=YOUR_API_KEY

Command line usage
------------------

    usage: avcaesar.py [-h]
                    (-c hash [hash ...] | -u file [file ...] | -d reference [reference ...] | -i reference [reference ...] | --update reference [reference ...] | -r reference [reference ...] | --analysis-history | --is-authenticated | --quota)
                    [--private] [--page PAGE] [--per-page PER_PAGE]
                    [--api-key API_KEY] [--api-url API_URL]
                    [--api-server-cert API_SERVER_CERT] [--version]
    AVCaesar API tools
    optional arguments:
      -h, --help            show this help message and exit
      -c hash [hash ...], --check hash [hash ...]
                            Check a hash.
      -u file [file ...], --upload file [file ...]
                            Upload a sample.
      -d reference [reference ...], --download reference [reference ...]
                            Download a sample. (Only in public mode)
      -i reference [reference ...], --info reference [reference ...]
                            Show sample info.
      --update reference [reference ...]
                            Rescan a sample. (Only in public mode)
      -r reference [reference ...], --remove reference [reference ...]
                            Remote a sample. (Only in private mode)
      --analysis-history    Show your analysis history.
      --is-authenticated    Check your authentication
      --quota               Show your quota.
      --private             Activate mode private.
      --page PAGE           Specify the desired page.
      --per-page PER_PAGE   Specify the desired limit per page.
      --api-key API_KEY     Specify the api key.
      --api-url API_URL     Specify the api url.
      --api-server-cert API_SERVER_CERT
                            Specify the api server cert.
      --version             show program's version number and exit

Library usage
-------------
Make a connection to AVCaesar API.

    import avcaesar_api
    conn = avcaesar_api.Connector(key=YOUR_API_KEY, **avcaesar_api.config_malware_lu)

You can see an example of library usage in the script avcaesar.py.
