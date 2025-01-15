import os

# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = "Intel Unified Memory Framework"
copyright = "2023-2025, Intel"
author = "Intel"

# The full version, including alpha/beta/rc tags
release = os.getenv("UMF_VERSION", "")
print(
    f"UMF_VERSION used in docs: {release}"
    if release != ""
    else "please set UMF_VERSION environment variable before running this script"
)

# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = ["breathe", "sphinxcontrib.spelling"]

spelling_show_suggestions = True
spelling_word_list_filename = "spelling_exceptions.txt"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

primary_domain = "c"

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_book_theme"

# -- Extension configuration -------------------------------------------------

# -- Options for breathe extension -------------------------------------------
# 'doxyxml' dir is generated with Doxygen; it's supposed to be in a directory
# one above the config directory.
breathe_projects = {project: "../doxyxml"}
breathe_default_project = project
breathe_show_include = False
breathe_default_members = ("members", "undoc-members")
breathe_domain_by_extension = {"h": "c"}
