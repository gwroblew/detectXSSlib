
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "detectxsslib.h"

typedef struct {
    int dummy;
} ngx_http_detectxsslib_main_conf_t;

typedef struct {
    int dummy;
} ngx_http_detectxsslib_loc_conf_t;

static void *ngx_http_detectxsslib_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_detectxsslib_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_detectxsslib_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_detectxsslib_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_detectxsslib_commands[] = {

      ngx_null_command
};


static ngx_http_module_t  ngx_http_detectxsslib_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_detectxsslib_init,             /* postconfiguration */

    ngx_http_detectxsslib_create_main_conf, /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_detectxsslib_create_loc_conf,  /* create location configuration */
    ngx_http_detectxsslib_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_detectxsslib_module = {
    NGX_MODULE_V1,
    &ngx_http_detectxsslib_module_ctx,      /* module context */
    ngx_http_detectxsslib_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_detectxsslib_handler(ngx_http_request_t *r)
{
    xsslibUrl url;
    
    xsslibUrlInit(&url);
    
    xsslibUrlSetUrl2(&url, (char *)r->unparsed_uri.data, r->unparsed_uri.len);
    
    if(xsslibUrlScan(&url) == XssFound)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "XSS detected!");
    }

    return NGX_DECLINED;
}


static void *
ngx_http_detectxsslib_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_detectxsslib_main_conf_t  *dmcf;

    dmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_detectxsslib_main_conf_t));
    if (dmcf == NULL) {
        return NULL;
    }

    return dmcf;
}


static void *
ngx_http_detectxsslib_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_detectxsslib_loc_conf_t  *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_detectxsslib_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_detectxsslib_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    //ngx_http_detectxsslib_loc_conf_t  *prev = parent;
    //ngx_http_detectxsslib_loc_conf_t  *conf = child;

    //ngx_conf_merge_uint_value(conf->degrade, prev->degrade, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_detectxsslib_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_detectxsslib_handler;

    return NGX_OK;
}  
