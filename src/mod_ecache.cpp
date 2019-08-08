/*
 *
 * An AHTSE source module that serves tiles 
 * from Esri compact cache V2 bundles
 * It can cache a source service in bundles
 *
 * Lucian Plesea
 * (C) 2019
 * 
 */

#include <ahtse.h>
#include <receive_context.h>
#include <http_log.h>
#include <http_request.h>

using namespace std;

NS_AHTSE_USE

extern module AP_MODULE_DECLARE_DATA ecache_module;

#if defined(APLOG_USE_MODULE)
APLOG_USE_MODULE(ecache);
#endif

static const int BSZ = 128;
static const int TMASK = BSZ - 1;
static const int OBITS = 40;

struct ecache_conf {
    apr_array_header_t *arr_rxp;
    // Raster configuration
    TiledRaster raster;
    char *dpath;     // Disk (or remote) path where cache resides

    char *source;    // The path to fetch tiles from and store them in this cache
    char *postfix;   // the source request postfix
    int retries;     // If the source is on an object store that may fail

    char *password;  // Should be a table, in case multiple passwords are to be used
    int indirect;    // Subrequests only
    int unauth_code; // Return code for password missmatch
};

static void *create_dir_config(apr_pool_t *p, char *dummy) {
    auto *c = reinterpret_cast<ecache_conf *>(
        apr_pcalloc(p, sizeof(ecache_conf)));
    c->retries = 4;
    c->unauth_code = HTTP_NOT_FOUND; // Default action on password missmatch is decline
    return c;
}

static const char *set_regexp(cmd_parms *cmd, ecache_conf *c, const char *pattern)
{
    return add_regexp_to_array(cmd->pool, &c->arr_rxp, pattern);
}

static const char *configure(cmd_parms *cmd, ecache_conf *c, const char *fname) {
    const char *err_message, *line;
    apr_table_t *kvp = readAHTSEConfig(cmd->temp_pool, fname, &err_message);
    if (NULL == kvp)
        return err_message;

    // This reads the ETag
    err_message = configRaster(cmd->pool, kvp, c->raster);
    if (err_message)
        return err_message;
    if (c->raster.size.z != 1)
        return "Extra dimension not supported";

    line = apr_table_get(kvp, "DataPath");
    if (!line)
        return "DataPath directive missing";
    c->dpath = apr_pstrdup(cmd->pool, line);
    // Trim the last slash in the path
    if ((c->dpath[strlen(c->dpath) - 1] == '/') || (c->dpath[strlen(c->dpath) - 1] == '\\'))
        c->dpath[strlen(c->dpath) - 1] = 0;

    line = apr_table_get(kvp, "RetryCount");
    c->retries = 1 + (line ? atoi(line) : c->retries);
    if ((c->retries < 1) || (c->retries > 100))
        return "Invalid RetryCount value, expected 0 to 99";

    line = apr_table_get(kvp, "EmptyTile");
    if (line && strlen(line) && (err_message = readFile(
        cmd->pool, c->raster.missing.data, line)))
        return err_message;

    return NULL;
}

// Quiet error
#define REQ_ERR_IF(X) if (X) {\
    return HTTP_BAD_REQUEST; \
}

// Logged error
#define SERR_IF(X, msg) if (X) { \
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", msg);\
    return HTTP_INTERNAL_SERVER_ERROR; \
}

// This should be part of AHTSE, but it would become ap dependent 
// Also, APLOG_MARK only works within a module

// Tile address should already be adjusted for skipped levels, 
// and within source raster bounds
// returns success or remote code
static int get_tile(request_rec *r, const char *remote, sloc_t tile, 
    storage_manager &dst, char **psETag = NULL, const char *postfix = NULL)
{
    ap_filter_rec_t *receive_filter = ap_get_output_filter_handle("Receive");
    if (!receive_filter) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "Can't find receive filter, did you load mod_receive?");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    receive_ctx rctx;
    rctx.buffer = dst.buffer;
    rctx.maxsize = dst.size;
    rctx.size = 0;
    char *stile = apr_psprintf(r->pool, "/%d/%d/%d/%d",
        static_cast<int>(tile.z), static_cast<int>(tile.l),
        static_cast<int>(tile.y), static_cast<int>(tile.x));

    if (stile[1] == '0') // Don't send the M if zero
        stile += 2;

    char *sub_uri = apr_pstrcat(r->pool, remote, "/tile", stile, postfix, NULL);
    request_rec *sr = ap_sub_req_lookup_uri(sub_uri, r, r->output_filters);
    ap_filter_t *rf = ap_add_output_filter_handle(receive_filter, &rctx, sr, sr->connection);
    int code = ap_run_sub_req(sr); // returns http code
    dst.size = rctx.size;
    const char *sETag = apr_table_get(sr->headers_out, "ETag");

    if (psETag && sETag)
        *psETag = apr_pstrdup(r->pool, sETag);

    ap_remove_output_filter(rf);
    ap_destroy_sub_req(sr);

    if (code == APR_SUCCESS)
        return APR_SUCCESS;
    ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "%s failed, %d", sub_uri, code);
    return code;
}

// Use a range get to read from a remote file
static int remote_pread(request_rec *r, const char *remote, apr_off_t offset, 
    storage_manager &dst, int tries = 4)
{
    ap_filter_rec_t *receive_filter = ap_get_output_filter_handle("Receive");
    if (!receive_filter) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
            "Can't find receive filter, did you load mod_receive?");
        return 0;
    }

    receive_ctx rctx;
    rctx.buffer = dst.buffer;
    rctx.maxsize = dst.size;
    rctx.size = 0;

    char *srange = apr_psprintf(r->pool,
        "bytes=%" APR_UINT64_T_FMT "-%" APR_UINT64_T_FMT,
        offset, offset + dst.size);

    // S3 may return less than requested, so we retry the request a couple of times
    bool failed = false;
    apr_time_t now = apr_time_now();
    do {
        request_rec *sr = ap_sub_req_lookup_uri(remote, r, r->output_filters);
        apr_table_setn(sr->headers_in, "Range", srange);
        ap_filter_t *rf = ap_add_output_filter_handle(receive_filter, &rctx,
            sr, sr->connection);
        int status = ap_run_sub_req(sr);
        ap_remove_output_filter(rf);
        ap_destroy_sub_req(sr);

        if (status != APR_SUCCESS)
            failed = true;
        else {
            switch (sr->status) {
            case HTTP_PARTIAL_CONTENT:
                if (0 == tries--) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "Can't fetch data from %s, took %" APR_TIME_T_FMT "us",
                        remote, apr_time_now() - now);
                    failed = true;
                }
            case HTTP_OK:
                break;
            default: // Any other return code is unrecoverable
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                    "Can't fetch data from %s, remote returned %d",
                    remote, sr->status);
                failed = true;
            }
        }
    } while (!failed && rctx.size != dst.size);

    return failed ? 0 : rctx.size;
}

static int file_pread(request_rec *r, const char *fname, apr_off_t offset, 
    storage_manager &dst, bool locking = false)
{
    apr_file_t *pfh;
    apr_size_t size = static_cast<apr_size_t>(dst.size);

    if (locking) {
        if (APR_SUCCESS !=
            apr_file_open(&pfh, fname,
                READ_RIGHTS | APR_FOPEN_SHARELOCK | APR_FOPEN_XTHREAD | APR_FOPEN_NOCLEANUP,
                0, r->pool))
            return 0;

        if (APR_SUCCESS != apr_file_lock(pfh, APR_FLOCK_SHARED)
            || APR_SUCCESS != apr_file_seek(pfh, APR_SET, &offset)
            || APR_SUCCESS != apr_file_read(pfh, dst.buffer, &size))
                size = 0;

        apr_file_unlock(pfh);
        apr_file_close(pfh);
        dst.size = static_cast<int>(size);
        return dst.size;
    }

    // Non locking
    if (APR_SUCCESS !=
        apr_file_open(&pfh, fname, READ_RIGHTS | APR_FOPEN_NOCLEANUP, 0, r->pool))
        return 0;

    if (APR_SUCCESS != apr_file_seek(pfh, APR_SET, &offset)
        || APR_SUCCESS != apr_file_read(pfh, dst.buffer, &size))
        size = 0;

    apr_file_close(pfh);
    dst.size = static_cast<int>(size);
    return dst.size;
}

// Read tile from bundle, either local or remote
static int bundle_pread(request_rec *r, storage_manager &mgr,
    apr_off_t offset, const char *name, const char *token = "BUNDLE")
{
    auto  cfg = get_conf<ecache_conf>(r, &ecache_module);
    bool redirect = (strlen(name) > 3 && name[0] == ':' && name[1] == '/');
    if (redirect)
        return remote_pread(r, name + 2, offset, mgr, cfg->retries);
    else
        return file_pread(r, name, offset, mgr, cfg->source == nullptr);
}

// Called when caching and reading from the bundlename failed
// Try to create a bundle file, retun success if it worked
static int binit(request_rec *r, const char *bundlename)
{
    const int flags = APR_FOPEN_WRITE | APR_FOPEN_CREATE
        | APR_FOPEN_EXCL | APR_FOPEN_SPARSE 
        | APR_FOPEN_BINARY | APR_FOPEN_NOCLEANUP;
    apr_file_t *bundlefile;
    apr_status_t stat = apr_file_open(&bundlefile, bundlename, 
                  flags, APR_FPROT_OS_DEFAULT, r->pool);

    if (stat != APR_SUCCESS) {
        // Maybe it was created already, check thta it can be read
        const int rflags = READ_RIGHTS | APR_FOPEN_NOCLEANUP;
        stat = apr_file_open(&bundlefile, bundlename, rflags, 0, r->pool);
        if (APR_SUCCESS == stat)
            apr_file_close(bundlefile);
        // Report success or failure
        return stat;
    }

    apr_file_trunc(bundlefile, 64 + BSZ * BSZ * 8);
    apr_file_close(bundlefile);
    return APR_SUCCESS;
}

// HTTP return
// Fetch the tile from remote, store it and serve it
static int dynacache(request_rec *r, sloc_t tile, const char *bundlename)
{
    const int flags = APR_FOPEN_WRITE | APR_FOPEN_BINARY | APR_FOPEN_XTHREAD
        | APR_FOPEN_SHARELOCK | APR_FOPEN_LARGEFILE | APR_FOPEN_NOCLEANUP;

    auto *cfg = get_conf<ecache_conf>(r, &ecache_module);

    char *sETag = NULL;
    storage_manager tilebuf;
    tilebuf.size = cfg->raster.maxtilesize;
    tilebuf.buffer = static_cast<char *>(apr_palloc(r->pool, tilebuf.size));
    if (!tilebuf.buffer) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Out of memory");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    // Undo the level adjustment, so the remote gets the right tile
    tile.l -= cfg->raster.skip;

    int code = get_tile(r, cfg->source, tile, tilebuf, &sETag, cfg->postfix);
    if (APR_SUCCESS != code)
        return code;

    // Got the tile, store it
    apr_file_t *pfh;
    apr_status_t stat = apr_file_open(&pfh, bundlename, flags, 0, r->pool);
    if (APR_SUCCESS != stat) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Can't update file %s", bundlename);
    }
    else {
        apr_file_lock(pfh, APR_FLOCK_EXCLUSIVE); // ignore the status
        apr_off_t idx_offset = 0; // Where the tile goes
        apr_file_seek(pfh, APR_END, &idx_offset);

        range_t tinfo;
        tinfo.offset = idx_offset;
        tinfo.size = tilebuf.size;

        apr_size_t size = tilebuf.size;
        apr_file_write(pfh, tilebuf.buffer, &size);
        idx_offset = 64 + 8 * ((tile.y & TMASK) * BSZ + (tile.x & TMASK));
        apr_file_seek(pfh, APR_SET, &idx_offset);
        idx_offset = tinfo.offset; // Keep a clean copy

        // prepare the joined index
        tinfo.offset = htole64(tinfo.offset + (tinfo.size << OBITS));
        size = 8; // sizeof(tinfo.offset)
        apr_file_write(pfh, &tinfo.offset, &size);
        apr_file_unlock(pfh);
        apr_file_close(pfh);
        // idx_offset has the local tile offset to compute the ETag
        // Use the same formula as the main handler

        sETag = reinterpret_cast<char *>(apr_palloc(r->pool, 16));
        // Very poor etag
        tobase32(cfg->raster.seed ^ ((tinfo.size < 1) ^ (idx_offset << 7)), sETag);
    }
    
    // The tile data is still int the buffer
    // Don't check the ETag since it was just computed
    apr_table_set(r->headers_out, "ETag", sETag);
    return sendImage(r, tilebuf);
}

static int handler(request_rec *r) {
    if (r->method_number != M_GET)
        return DECLINED;

    auto *cfg = get_conf<ecache_conf>(r, &ecache_module);
    if ((cfg->indirect && !r->main)
        || (cfg->password && !r->args) // Password has to be a parameter
        || !requestMatches(r, cfg->arr_rxp))
        return DECLINED;

    apr_hash_t *params = argparse(r);
    if (cfg->password && !params)
        return cfg->unauth_code;

    // Password checking should be a libahtse function
    if (cfg->password) {
        auto *pass = reinterpret_cast<const char *>(
            apr_hash_get(params, "password", APR_HASH_KEY_STRING));
        // No tolerance, has to have the right password
        if (!pass || strcmp(pass, cfg->password)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                "Invalid password in %s?%s", r->uri, r->args);
            return cfg->unauth_code;
        }
    }

    // Our request
    apr_pool_t *pool = r->pool;
    sz tile;
    REQ_ERR_IF(APR_SUCCESS != getMLRC(r, tile));
    REQ_ERR_IF(tile.z); // Until M Dimension
    const TiledRaster &raster = cfg->raster;
    if (tile.l < 0)
        return sendEmptyTile(r, raster.missing);

    tile.l += raster.skip;
    REQ_ERR_IF(tile.l >= raster.n_levels);
    const rset &level = raster.rsets[tile.l];
    REQ_ERR_IF(tile.x >= level.w || tile.y >= level.h);

    // Bundle row and column, good to level 23
    apr_uint32_t blev = static_cast<apr_uint32_t>(tile.l);
    apr_uint32_t bcol = static_cast<apr_uint32_t>((tile.x / BSZ) * BSZ);
    apr_uint32_t brow = static_cast<apr_uint32_t>((tile.y / BSZ) * BSZ);

    // The raster.skip doesn't affect the folder name
    const char *bundlename = apr_psprintf(pool, 
        "%s/L%02d/R%04xC%04x.bundle", cfg->dpath, blev - raster.skip, brow, bcol);

    range_t tinfo = { 0, 0 };
    apr_off_t idx_offset = 64 + 8 * ((tile.y & TMASK) * BSZ + (tile.x & TMASK));

    storage_manager sm(&tinfo.offset, sizeof(tinfo.offset));
    if (sizeof(tinfo.offset) != bundle_pread(r, sm, idx_offset, bundlename)) {
        if (!cfg->source)
            return sendEmptyTile(r, raster.missing);
        // We have a source but no bundle? Try creating it
        if (APR_SUCCESS != binit(r, bundlename)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                "File access error in %s", bundlename);
            return sendEmptyTile(r, raster.missing);
        }
        // We have a fresh bundle
        tinfo.offset = tinfo.size = 0;
    }

    // Unpack the index
    tinfo.offset = le64toh(tinfo.offset);
    tinfo.size = tinfo.offset >> OBITS;
    tinfo.offset &= (static_cast<apr_uint64_t>(1) << OBITS) -1;

    // Unchecked tile, cache it and serve it
    if (cfg->source && tinfo.size == 0 && tinfo.offset == 0)
        return dynacache(r, tile, bundlename);

    if (tinfo.size < 4)
        return sendEmptyTile(r, raster.missing);

    SERR_IF(MAX_TILE_SIZE < tinfo.size,  
        apr_psprintf(pool, "Tile too large, %s", r->uri));

    char ETag[16];
    // Very poor etag
    tobase32(raster.seed ^ ((tinfo.size < 1) ^ (tinfo.offset << 7)), ETag);
    if (etagMatches(r, ETag)) {
        apr_table_set(r->headers_out, "ETag", ETag);
        return HTTP_NOT_MODIFIED;
    }

    // Read the data and send it
    sm.size = static_cast<int>(tinfo.size);
    sm.buffer = reinterpret_cast<char *>(apr_palloc(pool, 
        static_cast<apr_size_t>(tinfo.size)));

    SERR_IF(!sm.buffer, "Allocation error");
    SERR_IF(sm.size != bundle_pread(r, sm, tinfo.offset, bundlename), 
        apr_psprintf(pool, "Data read error from %s", bundlename));

    // Got the data, send it
    apr_table_set(r->headers_out, "ETag", ETag);
    return sendImage(r, sm);
}

static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec cmds[] = {
    AP_INIT_TAKE1(
        "ECache_RegExp",
        (cmd_func)set_regexp,
        0, // self pass arg, added to the config address
        ACCESS_CONF,
        "The request pattern the URI has to match"
    )

    ,AP_INIT_TAKE1(
        "ECache_ConfigurationFile",
        (cmd_func) configure,
        0, // self pass arg, added to the config address
        ACCESS_CONF,
        "The configuration file"
    )

    ,AP_INIT_FLAG(
        "ECache_Indirect",
        (cmd_func) ap_set_flag_slot,
        (void *)APR_OFFSETOF(ecache_conf, indirect),
        ACCESS_CONF, // availability
        "If set, module activates only on subrequests"
    )

    ,AP_INIT_TAKE1(
        "ECache_Password",
        (cmd_func) ap_set_string_slot,
        (void *)APR_OFFSETOF(ecache_conf, password),
        ACCESS_CONF,
        "If set, the request password paramter value has to match"
    )

    ,AP_INIT_TAKE1(
        "ECache_UnauthorizedCode",
        (cmd_func)ap_set_int_slot,
        (void *)APR_OFFSETOF(ecache_conf, unauth_code),
        ACCESS_CONF,
        "HTTP error code to return when the password is set but the request doesn't "
        "match it. It defaults to 404 (not found), which is the safest choice"
    )

    ,AP_INIT_TAKE1(
        "ECache_Source",
        (cmd_func) set_source<ecache_conf>,
        0,
        ACCESS_CONF,
        "Set to a redirect path containing the AHTSE service which will be cached in this ecache"
    )

    ,{NULL}
};

module AP_MODULE_DECLARE_DATA ecache_module = {
    STANDARD20_MODULE_STUFF,
    create_dir_config,
    0,  // merge_dir_config
    0,  // create_server_config
    0,  // merge_server_config
    cmds,
    register_hooks
};
