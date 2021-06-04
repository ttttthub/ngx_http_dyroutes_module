#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <string.h>

#define DEFAULT_NOT_FOUND "NOT_FOUND"
#define NGX_RURU_SHM_NAME_LEN 256

/*
    存储路由信息，
    host权重2，path权重1.
    查询顺序：
            1.先找host和path都能匹配得上的；
            2.如果步骤1没找到，找host可以匹配得上的；
            3.如果步骤2没找到，找path可以匹配得上的；
            4.上述都没找到，返回404；

*/
typedef struct {
    char        *routename;
    char        *service;       //proxy_pass address;
    char        *host;
    ngx_queue_t queue;
 //   char        *method;
    char        *paths;
} ngx_http_ruru_route_t;

static ngx_int_t
ngx_http_ruru_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t
ngx_http_ruru_pre_conf(ngx_conf_t *cf);
static ngx_int_t 
ruru_add_variables(ngx_conf_t *cf);
static ngx_int_t
ngx_http_ruru_init_process(ngx_cycle_t *cycle);
static void
ngx_http_ruru_send_response(ngx_http_request_t *r, ngx_int_t status, ngx_str_t *content);
static char *
ngx_http_ruru_init_shm(ngx_conf_t *cf, void *conf);
static void *
ngx_http_ruru_create_main_conf(ngx_conf_t *cf);
static char *
ngx_http_ruru_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_ruru_interface_handler(ngx_http_request_t *r);
static void
ngx_http_ruru_body_handler(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ruru_add_route(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ruru_delete_route(ngx_http_request_t *r);
static ngx_int_t
ngx_http_ruru_get_route(ngx_http_request_t *r, ngx_str_t *ret);
static ngx_int_t
ruru_service_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_array_t *
ngx_ruru_parse_uri(ngx_pool_t *pool, ngx_str_t *path);
static ngx_int_t 
ngx_http_ruru_pre_conf(ngx_conf_t *conf); 
static char *
ngx_http_ruru_init_main_conf(ngx_conf_t *cf, void *conf);


static ngx_uint_t ngx_http_ruru_shm_generation = 0;

//ruru模块支持的指令
/*
   指令： ruru_interface
   功能： 用于接收管理请求，添加路由规则
*/
static ngx_command_t ngx_http_ruru_commands[] = {
    {
        ngx_string("ruru_interface"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_ruru_interface,
        0,
        0,
        NULL },
    ngx_null_command
};

//ruru模块的自定义变量
/*
    变量：service_host
    功能：存储route对应的service的地址
*/

static ngx_http_variable_t ruru_variables[] = {
    {
        ngx_string("service_host"),
        NULL,
        ruru_service_get,
        0,
        0,
        0
    },
    {ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_http_module_t ngx_http_ruru_module_ctx = {
    ngx_http_ruru_pre_conf,		    /* preconfiguration */
    NULL,                               /* postconfiguration */

    ngx_http_ruru_create_main_conf,   /* create main configuration */
    ngx_http_ruru_init_main_conf,     /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    NULL,                               /* create location configuration */
    NULL                                /* merge location configuration */
};

ngx_module_t ngx_http_ruru_module = {
    NGX_MODULE_V1,
    &ngx_http_ruru_module_ctx,
    ngx_http_ruru_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_ruru_init_process,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

typedef struct {
    size_t          shm_size;
    ngx_flag_t      enable;
    ngx_str_t       shm_name;
} ngx_http_ruru_main_conf_t;

typedef struct {
    ngx_queue_t queue;
} ngx_ruru_shctx_t;

typedef struct {
    ngx_slab_pool_t     *shpool;
    ngx_ruru_shctx_t    *sh;
} ngx_global_ruru_ctx_t;


typedef struct {
    ngx_queue_t queue;
    char        *host;
} ngx_ruru_value_t;

static ngx_global_ruru_ctx_t ngx_global_ruru_ctx;

static ngx_int_t
ngx_http_ruru_init_process(ngx_cycle_t *cycle)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_ruru_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool,
    ngx_uint_t generation)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, NGX_RURU_SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, NGX_RURU_SHM_NAME_LEN, "%s#%ui",
                        "ngx_http_ruru_module", generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ruru_pre_conf(ngx_conf_t *cf)
{
    if(ruru_add_variables(cf) == NGX_OK) {
        return NGX_OK;
    }
    return NGX_ERROR;   
}

static ngx_int_t ruru_add_variables(ngx_conf_t *cf)
{
    int i;
    ngx_http_variable_t *var;

    for (i=0; ruru_variables[i].name.len>0; ++i) {
        var = ngx_http_add_variable(cf, &ruru_variables[i].name, ruru_variables[i].flags);
        if (var==NULL) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "ruru add variable '%s' failed.", ruru_variables[i].name.data);
            return NGX_ERROR;
        }

        var->set_handler = ruru_variables[i].set_handler;
        var->get_handler = ruru_variables[i].get_handler;
        var->data = ruru_variables[i].data;
    }

    return NGX_OK;
}


static void *
ngx_http_ruru_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ruru_main_conf_t       *rmcf;
    rmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ruru_main_conf_t));
    if(rmcf == NULL){
        return NULL;
    }

    rmcf->shm_size = NGX_CONF_UNSET_SIZE;
    rmcf->enable = NGX_CONF_UNSET;
    return      rmcf;
}


static char *
ngx_http_ruru_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_http_ruru_main_conf_t *rmcf = conf;
    ngx_shm_zone_t            *shm_zone;

    ngx_http_ruru_shm_generation++;

    if(ngx_http_ruru_get_shm_name(&rmcf->shm_name, cf->pool, ngx_http_ruru_shm_generation) != NGX_OK){
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &rmcf->shm_name, rmcf->shm_size, &ngx_http_ruru_module);
    if(shm_zone == NULL){
        return NGX_CONF_ERROR;
    }

     ngx_log_error(NGX_LOG_DEBUG, cf->log, 0, "[goblin] init shm: %V, size: %ui", &rmcf->shm_name, rmcf->shm_size);

     shm_zone->data = cf->pool;
     shm_zone->init = ngx_http_ruru_init_shm_zone;
     
     return NGX_CONF_OK;

}

static ngx_int_t
ngx_http_ruru_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t             *shpool;
    ngx_ruru_shctx_t          *sh;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = ngx_slab_calloc(shpool, sizeof(ngx_ruru_shctx_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&sh->queue);

    ngx_global_ruru_ctx.sh = sh;
    ngx_global_ruru_ctx.shpool = shpool;

    return NGX_OK;
}

static char *
ngx_http_ruru_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_ruru_main_conf_t           *rmcf = conf;
    if(rmcf->enable == NGX_CONF_UNSET){
        rmcf->enable = 0;
    }

    if(rmcf->shm_size == NGX_CONF_UNSET_SIZE){
        rmcf->shm_size = (size_t)20 * (size_t)1024 *(size_t)1024;
    }

    return ngx_http_ruru_init_shm(cf, conf);
}

static char *
ngx_http_ruru_interface(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_ruru_main_conf_t   *rmcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_ruru_interface_handler;

    rmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ruru_module);
    rmcf->enable = 1;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ruru_interface_handler(ngx_http_request_t *r)
{
    ngx_int_t       rc;
    rc = ngx_http_read_client_request_body(r, ngx_http_ruru_body_handler);
    if(rc >= NGX_HTTP_SPECIAL_RESPONSE){
        return rc;
    }

    return NGX_DONE;
}

/*                  请求方法       路由名称   参数
    添加路由规则示例：   POST        /name   path： host:   upstream:
    删除路由规则示例：   DELETE      /name
    查看路由规则示例：   GET         /name

*/

static void
ngx_http_ruru_body_handler(ngx_http_request_t *r)
{
    ngx_str_t       rv;
    ngx_int_t       status, rc;
//    ngx_buf_t       *body;
//    ngx_array_t     *paths;
//    *hosts;
 //   char            **value, *last_path;

    ngx_str_set(&rv, "");
    status = NGX_HTTP_OK;
  /*
    if(r->method != NGX_HTTP_POST && r->method != NGX_HTTP_DELETE && r->method != NGX_HTTP_GET){
        ngx_str_set(&rv, "request method is not allowed\n");
        status = NGX_HTTP_NOT_ALLOWED;
        goto finish;
    }
*/
    //添加路由规则
    if(r->method == NGX_HTTP_POST){
        rc = ngx_http_ruru_add_route(r);
        if(rc == -1){
            ngx_str_set(&rv, "add route failed\n");
            status = NGX_HTTP_BAD_REQUEST;
            goto finish;
        }
    }

    //删除路由规则
    if(r->method == NGX_HTTP_DELETE){
        rc = ngx_http_ruru_delete_route(r);
        if(rc == -1){
            ngx_str_set(&rv, "delete route failed\n");
            status = NGX_HTTP_BAD_REQUEST;
            goto finish;
        }
    }

    if(r->method == NGX_HTTP_GET){
        rc = ngx_http_ruru_get_route(r, &rv);
        if(rc == -1){
            ngx_str_set(&rv, "get route infomation failed\n");
            status = NGX_HTTP_BAD_REQUEST;
            goto finish;
        }
    }

finish:
    ngx_http_ruru_send_response(r, status, &rv);
}

static void
ngx_http_ruru_send_response(ngx_http_request_t *r, ngx_int_t status, ngx_str_t *content)
{
    ngx_int_t   rc;
    ngx_buf_t   *b;
    ngx_chain_t out;

    r->headers_out.status = status;
    r->headers_out.content_length_n = content->len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    if (content->len == 0) {
        ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_FLUSH));
        return;
    }

    b = ngx_create_temp_buf(r->pool, content->len);
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    b->pos = content->data;
    b->last = content->data + content->len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;

    ngx_http_finalize_request(r, ngx_http_output_filter(r, &out));
}

static ngx_array_t *
ngx_ruru_parse_uri(ngx_pool_t *pool, ngx_str_t *path)
{
    ngx_array_t             *arr;
    char                    *uri, *p, **h;
    ngx_int_t               key_start = 0;

    arr = ngx_pcalloc(pool, sizeof(ngx_array_t));
    if (arr == NULL) {
        return NULL;
    }

    if (ngx_array_init(arr, pool, 5, sizeof(char *)) != NGX_OK) {
        return NULL;
    }

    uri = ngx_pcalloc(pool, path->len + 1);
    if (uri == NULL) {
        return NULL;
    }

    strncpy(uri, (char *)path->data, path->len);
    uri[path->len] = '\0';

    p = uri;

    while(*p != '\0') {
        switch (*p) {
        case '/':
            if (key_start == 0) {
                break;
            }

            *p = '\0';

            key_start = 0;

            break;
        default:
            if (key_start == 0) {
                h = ngx_array_push(arr);
                if (h == NULL) {
                    return NULL;
                }

                *h = p;

                key_start = 1;
            }

            break;
        }

        p++;
    }

    return arr;
}

static ngx_buf_t *
ngx_http_ruru_read_body(ngx_http_request_t *r)
{
    size_t              len;
    ngx_buf_t           *buf, *next, *body;
    ngx_chain_t         *cl;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "[ruru] interface read post body.");

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        return buf;
    } else {
        next = cl->next->buf;
        len = (buf->last - buf->pos) + (next->last - next->pos);

        body = ngx_create_temp_buf(r->pool, len);
        if (body == NULL) {
            return NULL;
        }

        body->last = ngx_cpymem(body->last, buf->pos, buf->last - buf->pos);
        body->last = ngx_cpymem(body->last, next->pos, next->last - next->pos);
    }

    return body;
}

static ngx_int_t
ngx_http_ruru_parse_body(ngx_http_request_t *r, ngx_buf_t *b, ngx_array_t *args)
{
    char                *p, *body, *host = "", **h;
    ngx_uint_t          len, host_start = 1, n;


    len = b->last - b->pos;

    body = ngx_pcalloc(r->pool, len + 1);
    if (body == NULL) {
        return NGX_ERROR;
    }

    strncpy(body, (char *)b->pos, len);
    body[len] = '\0';

    p = body;

    n = len + 1;
    while (n--) {
        switch(*p) {
        case '&':
        case '\0':
            if (host_start == 0) {
                *p = '\0';
                host_start = 1;

                if (strlen(host) > 50) {
                    return NGX_ERROR;
                }

                h = ngx_array_push(args);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                *h = host;
            }

            break;
        default:
            if (host_start == 1) {
                host_start = 0;

                host = p;
            }

            break;
        }

        p++;
    }

    if (args->nelts == 0) {
        return NGX_ERROR;
    }

    return NGX_OK;
}



static ngx_int_t
ngx_http_ruru_add_route(ngx_http_request_t *r)
{
  //  char            *route_name;
    ngx_array_t     *paths, *args;
    char            **value;
    ngx_slab_pool_t *shpool;
    ngx_ruru_shctx_t  *sh;
    ngx_http_ruru_route_t *route;
    ngx_buf_t       *body;
    ngx_uint_t       i, j, k;
    ngx_int_t       rc;
    char            *host;
    char            *service;
    char            **arg;

    service = NULL;
    host = NULL;

    args = ngx_array_create(r->pool, 1024, sizeof(char*));
    paths = ngx_ruru_parse_uri(r->pool, &r->uri);
    if(paths->nelts != 2){
        return NGX_ERROR;
    }
    value = paths->elts;
    if(strlen(value[0]) != 5 || ngx_strncmp(value[0], "route", 5)){
        return NGX_ERROR;
    }

    body = ngx_http_ruru_read_body(r);
    if(body == NULL){
        return NGX_ERROR;
    }

    rc = ngx_http_ruru_parse_body(r, body, args);
    if(rc == NGX_ERROR){
        return NGX_ERROR;
    }

    shpool = ngx_global_ruru_ctx.shpool;
    sh = ngx_global_ruru_ctx.sh;

    //parse :
    arg = args->elts;

    route = ngx_slab_calloc(shpool, sizeof(ngx_http_ruru_route_t));
    if(route == NULL){
        return NGX_ERROR;
    }

    for(i = 0; i != args->nelts; i++)
    {
        for(j = 0; j != strlen(arg[i]); j++)
        {
            if(arg[i][j] == ':')
                break;
        }

        if(j == strlen(arg[i]) - 1){
            return NGX_ERROR;
        }

        //parse host
        if(j == 4 && !ngx_strncmp(arg[i], "host", 4)){
            host = ngx_slab_calloc(shpool, strlen(arg[i]) - 4 + 1);
            if(host == NULL){
                goto finish;
            }
            for(k = 0;k != strlen(arg[i]) - 5;k++){
                host[k] = arg[i][j + 1 + k];
            }
            host[k] = '\0';
        }
        //parse proxypass
        if(j == 9 && !ngx_strncmp(arg[i], "proxypass", 9)){
            service = ngx_slab_calloc(shpool, strlen(arg[i]) - 10 + 1);
            if(service == NULL){
                goto finish;
            }
            for(k = 0;k != strlen(arg[i]) - 10;k++){
                service[k] = arg[i][j + 1 + k];
            }
            service[k] = '\0';
        }
    }

    route->routename = ngx_slab_calloc(shpool, strlen(value[1]) + 1);
    if(route->routename == NULL){
        goto finish;
    }

    for(k = 0; k != strlen(value[1]);k++){
        route->routename[k] = value[1][k];
    }
    route->routename[k] = '\0';
    route->host = host;
    route->paths = NULL;
    route->service = service;
    ngx_queue_insert_tail(&sh->queue, &route->queue);
    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;

finish:
    if(route != NULL){

        if(route->host != NULL){
            ngx_slab_free(shpool, route->routename);
        }
        if(route->service == NULL){
            ngx_slab_free(shpool, route->service);
        }
        if(route->host == NULL){
            ngx_slab_free(shpool, route->host);
        }
        ngx_slab_free(shpool, route);

    }
    return NGX_ERROR;
    //parse url    get route_name
}

static ngx_int_t
ruru_service_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    char             *host;
    ngx_ruru_shctx_t *sh;
    ngx_slab_pool_t  *shpool;
    ngx_queue_t       *q;
    ngx_http_ruru_route_t *route;
    ngx_uint_t        flag;
    char              *result;

    result = DEFAULT_NOT_FOUND;

    if(r->headers_in.server.data == NULL){
        return NGX_ERROR;
    }
    host = (char *)r->headers_in.server.data;

    flag = 0;

    sh = ngx_global_ruru_ctx.sh;
    shpool = ngx_global_ruru_ctx.shpool;

    //mutex
     ngx_shmtx_lock(&shpool->mutex);
     for(q = ngx_queue_head(&sh->queue); q != ngx_queue_sentinel(&sh->queue); q = ngx_queue_next(q)) {
        route = ngx_queue_data(q, ngx_http_ruru_route_t, queue);
        if(route == NULL){
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }
        if(strlen(host) == strlen(route->host) && !ngx_strncmp(route->host, host, strlen(host))){
            flag = 1;
            result = ngx_palloc(r->pool, strlen(route->service) + 1);
            if(result == NULL){
                flag = 0;
                ngx_shmtx_unlock(&shpool->mutex);
                return NGX_ERROR;
            }
            ngx_memcpy(result, route->service, strlen(route->service) + 1);
            break;
        }
     }

    ngx_shmtx_unlock(&shpool->mutex);

     if(flag == 1){
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (void*)result;
        v->len = strlen(result);

     }

    if(flag == 0){
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (void*)result;
        v->len = strlen(result);

    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_ruru_delete_route(ngx_http_request_t *r){
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_ruru_get_route(ngx_http_request_t *r, ngx_str_t *ret){
    return NGX_ERROR;
}

















