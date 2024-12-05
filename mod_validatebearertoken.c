#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <ap_config.h>
#include <apr_strings.h>
#include <apr_lib.h>
#include <apr_file_io.h>
#include <apr_file_info.h>
#include <apr_general.h>
#include <apr_pools.h>

module AP_MODULE_DECLARE_DATA validatebearertoken_module;

typedef struct {
    const char *validate_script;
} validatebearertoken_config;

static void *create_dir_conf(apr_pool_t *pool, char *context) {
    validatebearertoken_config *config = apr_pcalloc(pool, sizeof(validatebearertoken_config));
    config->validate_script = NULL;
    return config;
}

static const command_rec validatebearertoken_directives[] = {
    AP_INIT_TAKE1("ValidateBearerTokenScript", ap_set_string_slot, 
                  (void *)APR_OFFSETOF(validatebearertoken_config, validate_script), 
                  ACCESS_CONF, "Path to token validation script"),
    {NULL}
};

static int validate_token_with_script(request_rec *r, const char *token, const char *script_path) {
    if (!script_path || !*script_path) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Validation script path is empty.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_procattr_t *attr;
    apr_proc_t proc;
    apr_status_t rv;
    const char *args[3];
    int exit_code;
    apr_exit_why_e why;

    args[0] = script_path;
    args[1] = token ? token : "";
    args[2] = NULL;

    rv = apr_procattr_create(&attr, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to create proc attr");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_procattr_io_set(attr, APR_NO_PIPE, APR_NO_PIPE, APR_NO_PIPE);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to set IO in proc attr");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_procattr_cmdtype_set(attr, APR_PROGRAM);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to set command type");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_proc_create(&proc, args[0], args, NULL, attr, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to run validation script: %s", script_path);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = apr_proc_wait(&proc, &exit_code, &why, APR_WAIT);
    if (rv != APR_CHILD_DONE || why != APR_PROC_EXIT || exit_code != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Token validation failed or script error");
        return HTTP_UNAUTHORIZED;
    }

    return OK;
}

static int validatebearertoken_check_auth(request_rec *r) {
    if (r->method_number != M_GET && r->method_number != M_POST) {
        return DECLINED;
    }

    const char *auth_header = apr_table_get(r->headers_in, "Authorization");
    validatebearertoken_config *config = ap_get_module_config(r->per_dir_config, &validatebearertoken_module);

    if (!config || !config->validate_script) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ValidateBearerTokenScript not set.");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!auth_header || strncmp(auth_header, "Bearer ", 7) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No Bearer token found or invalid format.");
        return HTTP_UNAUTHORIZED;
    }

    int result = validate_token_with_script(r, auth_header + 7, config->validate_script);
    if (result == OK) {
        r->user = apr_pstrdup(r->pool, "authenticated_user");
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Bearer token validated successfully");
        return OK;
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Bearer token validation failed.");
        return result;
    }
}

static void register_hooks(apr_pool_t *p) {
    ap_hook_check_authn(validatebearertoken_check_auth, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(validatebearertoken) = {
    STANDARD20_MODULE_STUFF,
    create_dir_conf,
    NULL,
    NULL,
    NULL,
    validatebearertoken_directives,
    register_hooks
};
