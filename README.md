# mod_ecache
An AHTSE httpd tile handler for Esri V2 bundle caches

* SkippedLevels N

The convention is that level 0 has only 1 tile. This is used to block requests for tiles outside of the bounding box.  For some cases such as WGS84, the esri convention is to have two tiles (possible 4) at level 0.  Setting SkippedLevels to 1, allows those caches to be served.  The folder naming is not affected.
