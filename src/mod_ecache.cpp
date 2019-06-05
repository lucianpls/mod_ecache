/*
 *
 * An AHTSE source module that serves tiles 
 * from Esri compact cache V2 bundles
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

static int BSZ = 128;
static int TMASK = BSZ - 1;
static int OBITS = 40;

struct ecache_conf {
    apr_array_header_t *arr_rxp;
    // Raster configuration
    TiledRaster raster;
    char *source;
    char *password;
    int indirect;  // Subrequests only
    int retries;   // If the source is on an object store
};

static void *create_dir_config(apr_pool_t *p, char *dummy) {
    auto *c = reinterpret_cast<ecache_conf *>(
        apr_pcalloc(p, sizeof(ecache_conf)));
    c->retries = 4;
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

    line = apr_table_get(kvp, "Source");
    if (!line)
        return "Source directive missing";
    c->source = apr_pstrdup(cmd->pool, line);
    // Trim the last slash in the path
    if ((c->source[strlen(c->source) - 1] == '/') || (c->source[strlen(c->source) - 1] == '\\'))
        c->source[strlen(c->source) - 1] = 0;

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

static int file_pread(request_rec *r, storage_manager &mgr,
    apr_off_t offset, const char *name, const char *token = "BUNDLE")
{
    auto  cfg = get_conf<ecache_conf>(r, &ecache_module);
    bool redirect = (strlen(name) > 3 && name[0] == ':' && name[1] == '/');
    if (redirect) {
        // Remote
        name = name + 2;
        ap_filter_rec_t *receive_filter = ap_get_output_filter_handle("Receive");
        if (!receive_filter) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "Can't find receive filter, did you load mod_receive?");
            return 0;
        }

        // buffer for the image
        receive_ctx rctx;
        rctx.buffer = mgr.buffer;
        rctx.maxsize = mgr.size;
        rctx.size = 0;

        char *range = apr_psprintf(r->pool,
            "bytes=%" APR_UINT64_T_FMT "-%" APR_UINT64_T_FMT,
            offset, offset + mgr.size);

        // S3 may return less than requested, so we retry the request a couple of times
        int tries = cfg->retries;
        bool failed = false;
        apr_time_t now = apr_time_now();
        do {
            request_rec *sr = ap_sub_req_lookup_uri(name, r, r->output_filters);
            apr_table_setn(sr->headers_in, "Range", range);
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
                            name, apr_time_now() - now);
                        failed = true;
                    }
                case HTTP_OK:
                    break;
                default: // Any other return code is unrecoverable
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                        "Can't fetch data from %s, remote returned %d",
                            name, sr->status);
                    failed = true;
                }
            }
        } while (!failed && rctx.size != mgr.size);

        return failed ? 0 : rctx.size;
    } // Redirect read

    apr_file_t *pfh;

    if (APR_SUCCESS != 
        apr_file_open(&pfh, name, READ_RIGHTS | APR_FOPEN_BUFFERED, 0, r->pool))
        return 0;

    apr_size_t sz = static_cast<apr_size_t>(mgr.size);

    if (APR_SUCCESS != apr_file_seek(pfh, APR_SET, &offset) 
        || APR_SUCCESS != apr_file_read(pfh, mgr.buffer, &sz))
        sz = 0;

    apr_file_close(pfh);
    mgr.size = static_cast<int>(sz);
    return mgr.size;
}

static int handler(request_rec *r) {
    if (r->method_number != M_GET)
        return DECLINED;

    auto *cfg = get_conf<ecache_conf>(r, &ecache_module);
    if ((cfg->indirect && !r->main)
        || !requestMatches(r, cfg->arr_rxp))
        return DECLINED;

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
        "%s/L%02d/R%04xC%04x.bundle", cfg->source, blev - raster.skip, brow, bcol);

    range_t tinfo;
    apr_off_t idx_offset = 64 + 8 * ((tile.y & TMASK) * BSZ + (tile.x & TMASK));

    storage_manager sm(&tinfo.offset, sizeof(tinfo.offset));
    if (sizeof(tinfo.offset) != file_pread(r, sm, idx_offset, bundlename)) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "File access error in %s", bundlename);
        return sendEmptyTile(r, raster.missing);
    }

    // Unpack the index
    tinfo.offset = le64toh(tinfo.offset);
    tinfo.size = tinfo.offset >> OBITS;
    tinfo.offset &= (static_cast<apr_uint64_t>(1) << OBITS) -1;
    if (tinfo.size < 4)
        return sendEmptyTile(r, raster.missing);

    SERR_IF(MAX_TILE_SIZE < tinfo.size,  
        apr_psprintf(pool, "Tile too large from %s", r->uri));

    // TODO: Check ETAG
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
    SERR_IF(sm.size != file_pread(r, sm, tinfo.offset, bundlename), 
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
        (cmd_func) set_regexp,
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
        "Ecache_Indirect",
        (cmd_func) ap_set_flag_slot,
        (void *)APR_OFFSETOF(ecache_conf, indirect),
        ACCESS_CONF, // availability
        "If set, module activates only on subrequests"
    )

    ,AP_INIT_TAKE1(
        "Ecache_Password",
        (cmd_func) ap_set_string_slot,
        (void *)APR_OFFSETOF(ecache_conf, password),
        ACCESS_CONF,
        "If set, the request password paramter value has to match"
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
