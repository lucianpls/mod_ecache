/*
 *
 * An AHTSE source module that serves tiles from 
 * Esri compact cache V2 bundles
 *
 * Lucian Plesea
 * (C) 2019
 * 
 */

#include <ahtse.h>
#include <receive_context.h>

using namespace std;

NS_AHTSE_USE

extern module AP_MODULE_DECLARE_DATA ecache_module;

struct ecache_conf {
    apr_array_header_t *arr_rxp;
    int indirect;  // Subrequests only
};

static void *create_dir_config(apr_pool_t *p, char *dummy) {
    auto *c = reinterpret_cast<ecache_conf *>(
        apr_pcalloc(p, sizeof(ecache_conf)));
    return c;
}

static const char *set_regexp(cmd_parms *cmd, ecache_conf *c, const char *pattern)
{
    return add_regexp_to_array(cmd->pool, &c->arr_rxp, pattern);
}

static int handler(request_rec *r) {
    if (r->method_number != M_GET)
        return DECLINED;

    auto *cfg = get_conf<ecache_conf>(r, &ecache_module);
    if ((cfg->indirect && !r->main)
        || !requestMatches(r, cfg->arr_rxp))
        return DECLINED;

    // Our request
    sz tile;
    if (APR_SUCCESS != getMLRC(r, tile))
        return HTTP_BAD_REQUEST;

    return DECLINED;
}

static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(handler, NULL, NULL, APR_HOOK_LAST);
}

static const command_rec cmds[] = {
    AP_INIT_TAKE1(
        "ecache_RegExp",
        (cmd_func) set_regexp,
        0, // self pass arg, added to the config address
        ACCESS_CONF,
        "The request pattern the URI has to match"
    )

    ,AP_INIT_FLAG(
        "Ecache_Indirect",
        (cmd_func) ap_set_flag_slot,
        (void *)APR_OFFSETOF(ecache_conf, indirect),
        ACCESS_CONF, // availability
        "If set, module only activates on subrequests"
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
