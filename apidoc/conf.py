#!/usr/bin/env python3
# vim: set list et ts=8 sts=4 sw=4 ft=python:

import os
import sys
sys.path.insert(0, os.path.abspath('..'))


# -- General configuration ------------------------------------------------

# needs_sphinx = '1.0'

extensions = ['sphinx.ext.autodoc']
source_suffix = '.rst'
master_doc = 'index'

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

autodoc_member_order = 'groupwise'
pygments_style = 'sphinx'
todo_include_todos = False

import re
import acefile
project = 'acefile'
copyright = re.sub(r'^[^0-9]+', '', acefile.__copyright__)
author = acefile.__author__
release = acefile.__version__
version = re.sub(r'^([0-9]+\.[0-9]+)\..*$', r'\1', release)

rst_epilog = """
.. |project| replace:: %s
""" % (project)


# -- Options for HTML output ----------------------------------------------

html_theme = 'classic'
# html_theme_options = {}
html_static_path = ['_static']
html_sidebars = {
    '**': ['localtoc.html'],
}
html_domain_indices = False
html_use_index = False
html_copy_source = False
html_title = '%s %s' % (project, release)
#html_short_title = ''




