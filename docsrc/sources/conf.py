# Configuration file for the Sphinx documentation builder.

# -- Project information

project = 'BNG Blaster'
copyright = '2020-2025, RtBrick, Inc.'
author = 'Christian Giese'
release = '0.9'
version = '0.9.X'

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
html_static_path = ['_static']
html_css_files = [
    'custom.css',  # Add your custom CSS file
]

# -- Options for EPUB output

epub_show_urls = 'footnote'
