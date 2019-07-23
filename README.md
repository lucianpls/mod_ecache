# mod_ecache
An AHTSE httpd tile handler for Esri V2 bundle caches

## Apache Configuration Directives

* *ECache_RegExp* Match  
May appear multiple times, the tile requests have to match at least one of these patterns

* *ECache_ConfigurationFile* File  
File which contains the AHTSE configuration directives for this location

* *ECache_Source* Path  
If set, this should be an internal redirect path where a tile service exists. Then the bundled cache will be built from tile from this location, as needed. Should start from http docroot

* *ECache_Password* word  
If set, the request password parameter value has to match

* *ECache_UnauthorizedCode* code  
HTTP return code when the password is set but the request doesn't match it.  Defaults to 404 (not found), which is the safe choice

* *ECache_Indirect* On  
If set, the module activates only on subrequests


## AHTSE Configuration file directives

Most of the basic AHTSE raster configuration are supported.

* *DataPath* LocalPath  

A folder path where the LNN folders are located.  Should be a local path when caching

* *SkippedLevels* N  

The convention is that level 0 has only 1 tile. This is used to block requests for tiles outside of the bounding box.  For some cases such as WGS84, the esri convention is to have two tiles (possible 4) at level 0.  Setting SkippedLevels to 1, allows those caches to be served.  The folder naming is not affected.

* *MaxTileSize* N  

The maximum tile size for this cache, used to size the receive buffer when requesting tiles from the source. It defaults to 4MB, it can be set between 128K and 512MB.  Too large of a value will lead to memory overflow.  Too small of a value may truncate cached tiles
