#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>
#include <openssl/sha.h>
#include "bitcoin.h"
#include "config.h"
#include "stratum.h"
#include "utils.h"

// 内存中的当前任务模板
static Template g_current_template;
static pthread_mutex_t g_template_lock = PTHREAD_MUTEX_INITIALIZER;

// CURL 回调
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// 执行 RPC 调用
json_t* rpc_call(const char *method, json_t *params) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk = {0};
    chunk.memory = malloc(1); 
    chunk.size = 0;

    curl = curl_easy_init();
    if (!curl) return NULL;

    json_t *req = json_object();
    json_object_set_new(req, "jsonrpc", json_string("1.0"));
    json_object_set_new(req, "id", json_string("satoshi"));
    json_object_set_new(req, "method", json_string(method));
    if (params) {
        json_object_set_new(req, "params", params);
    } else {
        json_object_set_new(req, "params", json_array());
    }

    char *post_data = json_dumps(req, 0);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "content-type: text/plain;");

    // 设置 Auth
    char auth;
    snprintf(auth, sizeof(auth), "%s:%s", g_config.rpc_user, g_config.rpc_pass);

    curl_easy_setopt(curl, CURLOPT_URL, g_config.rpc_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_USERPWD, auth);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // 10秒超时

    res = curl_easy_perform(curl);
    
    json_t *response = NULL;
    if (res == CURLE_OK) {
        json_error_t error;
        response = json_loads(chunk.memory, 0, &error);
    } else {
        printf(" Curl failed: %s\n", curl_easy_strerror(res));
    }

    free(post_data);
    free(chunk.memory);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_decref(req);

    return response;
}

// 核心：处理 GBT 并广播新任务
void bitcoin_update_template(bool clean_jobs) {
    json_t *params = json_array();
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    
    json_t *gbt_args = json_object();
    json_object_set_new(gbt_args, "rules", rules);
    json_array_append_new(params, gbt_args);

    json_t *resp = rpc_call("getblocktemplate", params);
    if (!resp) return;

    json_t *result = json_object_get(resp, "result");
    if (!result |

| json_is_null(result)) {
        printf(" getblocktemplate failed or node syncing.\n");
        json_decref(resp);
        return;
    }

    pthread_mutex_lock(&g_template_lock);

    // 解析关键字段
    g_current_template.height = json_integer_value(json_object_get(result, "height"));
    const char *prev_hash_str = json_string_value(json_object_get(result, "previousblockhash"));
    g_current_template.version = json_integer_value(json_object_get(result, "version"));
    g_current_template.curtime = json_integer_value(json_object_get(result, "curtime"));
    const char *bits_str = json_string_value(json_object_get(result, "bits"));
    g_current_template.coinbase_value = json_integer_value(json_object_get(result, "coinbasevalue"));
    
    // 转换 PrevHash (RPC是Big Endian, Stratum通常需要Little Endian的字节序，Bitaxe需要反转)
    // 这里简化处理，存储原始 Hex
    strncpy(g_current_template.prev_hash, prev_hash_str, 64);
    strncpy(g_current_template.bits, bits_str, 8);
    
    // 构建 Merkle Branch (此处省略复杂 Merkle 计算，实际需遍历 transactions 数组进行 Hash)
    // 在极简版中，如果交易列表为空（除了Coinbase），Merkle Branch 为空数组
    // 实际上需要实现 build_merkle_tree(json_object_get(result, "transactions"));
    
    // 构造 Job ID
    static int job_counter = 0;
    snprintf(g_current_template.job_id, 32, "%x", ++job_counter);
    
    g_current_template.clean_jobs = clean_jobs;

    // 通知 Stratum Server 广播
    stratum_broadcast_job(&g_current_template);

    pthread_mutex_unlock(&g_template_lock);
    json_decref(resp);
}

int bitcoin_submit_block(const char *hex_data) {
    json_t *params = json_array();
    json_array_append_new(params, json_string(hex_data));
    json_t *resp = rpc_call("submitblock", params);
    
    int success = 0;
    if (resp) {
        json_t *res = json_object_get(resp, "result");
        if (json_is_null(res)) {
            printf(" Block submitted successfully!\n");
            success = 1;
        } else {
            printf(" Submit rejected: %s\n", json_string_value(res));
        }
        json_decref(resp);
    }
    return success;
}

int bitcoin_init() {
    curl_global_init(CURL_GLOBAL_ALL);
    return 0;
}
