To generate HTML documentation run the `generate_docs.py` script from the `build` dir.
It will create extra `./docs_build` directory, where the intermediate and final files
will be created. HTML docs will be in the `./docs_build/generated/html` directory.

The script requires:
 * [Doxygen](http://www.doxygen.nl/) at least v1.9.1
 * [Python](https://www.python.org/downloads/) at least v3.8
 * and python pip requirements, as defined in `third_party/requirements.txt`
