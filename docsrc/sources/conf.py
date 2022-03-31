# Configuration file for the Sphinx documentation builder.

# -- Project information

project = 'BNG Blaster'
copyright = '2020-2022, RtBrick, Inc.'
author = 'Christian Giese'
release = '0.0'
version = '0.0.0'

# -- General configuration

extensions = [
    'sphinx_tabs.tabs'
]

master_doc = 'index'
html_logo = 'images/rtbrick_logo.png'

templates_path = ['_templates']

# -- Options for HTML output

html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'logo_only': False,
    'display_version': False,
}

# -- Options for EPUB output

epub_show_urls = 'footnote'
