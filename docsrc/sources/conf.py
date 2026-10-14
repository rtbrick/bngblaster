# Configuration file for the Sphinx documentation builder.

# -- Project information

project = 'BNG Blaster'
copyright = '2020-2026, RtBrick, Inc.'
author = 'Christian Giese'
release = '1.0'
version = '1.0.X'

# -- General configuration

extensions = [
    'sphinx_tabs.tabs'
]

master_doc = 'index'
html_logo = 'images/rtbrick_neu.png'

templates_path = ['_templates']

# -- Options for HTML output

html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'logo_only': False
}
html_static_path = ['_static']
html_css_files = [
    'custom.css',  # Add your custom CSS file
]

# -- Options for EPUB output

epub_show_urls = 'footnote'
