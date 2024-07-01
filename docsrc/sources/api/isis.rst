+-----------------------------------+----------------------------------------------------------------------+
| Command                           | Description                                                          |
+===================================+======================================================================+
| **isis-adjacencies**              | | Display ISIS adjacencies.                                          |
+-----------------------------------+----------------------------------------------------------------------+
| **isis-database**                 | | Display ISIS database (LSDB).                                      |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``instance`` Mandatory                                             |
|                                   | | ``level`` Mandatory                                                |
+-----------------------------------+----------------------------------------------------------------------+
| **isis-load-mrt**                 | | Load ISIS MRT file.                                                |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``instance`` Mandatory                                             |
|                                   | | ``file`` Mandatory                                                 |
+-----------------------------------+----------------------------------------------------------------------+
| **isis-lsp-update**               | | Update ISIS LSP.                                                   |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``instance`` Mandatory                                             |
|                                   | | ``pdu`` Mandatory                                                  |
+-----------------------------------+----------------------------------------------------------------------+
| **isis-lsp-purge**                | | Purge ISIS LSP based on LSP identifier.                            |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``instance`` Mandatory                                             |
|                                   | | ``level`` Mandatory                                                |
|                                   | | ``id`` Mandatory LSP identifier                                    |
+-----------------------------------+----------------------------------------------------------------------+
| **isis-lsp-flap**                 | | Flap ISIS LSP based on LSP identifier.                             |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``instance`` Mandatory                                             |
|                                   | | ``level`` Mandatory                                                |
|                                   | | ``timer`` Optional flap timer (default 30s)                        |
|                                   | | ``id`` Mandatory LSP identifier                                    |
+-----------------------------------+----------------------------------------------------------------------+
| **isis-update-priority**          | | Update ISIS interface priority.                                    |
|                                   | |                                                                    |
|                                   | | **Arguments:**                                                     |
|                                   | | ``interface`` Mandatory                                            |
|                                   | | ``level`` Mandatory                                                |
|                                   | | ``priority`` Mandatory priority (0-127)                            |
+-----------------------------------+----------------------------------------------------------------------+
| **isis-teardown**                 | | Teardown ISIS.                                                     |
+-----------------------------------+----------------------------------------------------------------------+