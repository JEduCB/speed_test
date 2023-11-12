/*
 * Copyright 2018-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Here is an STORE loader for ENGINE backed keys.  It relies on deprecated
 * functions, and therefore need to have deprecation warnings suppressed.
 * This file is not compiled at all in a '--api=3 no-deprecated' configuration.
 */
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

//OpenSSL includes
#include <openssl/async.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
//OpenSSL includes

/* this is a private URI scheme */
# define ENGINE_SCHEME          "org.openssl.engine"
# define ENGINE_SCHEME_COLON    ENGINE_SCHEME ":"

#include "../include/testrsa.h"
#include "../include/speed_test_lib.h"

typedef struct string_int_pair_st
{
    const char *name;
    int retval;
} OPT_PAIR;

enum
{
    R_RSA_512,
    R_RSA_1024,
    R_RSA_2048, 
    R_RSA_3072,
    R_RSA_4096,
    R_RSA_7680,
    R_RSA_15360,
    RSA_NUM
};

static double rsa_results[RSA_NUM][2];  /* 2 ops: sign then verify */
static long rsa_c[RSA_NUM][2];  /* # RSA iteration test */

typedef struct loopargs_st
{
    ASYNC_JOB *inprogress_job;
    ASYNC_WAIT_CTX *wait_ctx;
    unsigned char *buf;
    unsigned char *buf2;
    unsigned char *buf_malloc;
    unsigned char *buf2_malloc;
    unsigned char *key;
    size_t buflen;
    size_t sigsize;
    EVP_PKEY_CTX *rsa_sign_ctx[RSA_NUM];
    EVP_PKEY_CTX *rsa_verify_ctx[RSA_NUM];
} loopargs_t;

static const int lengths_list[] = { 16, 64, 256, 1024, 8 * 1024, 16 * 1024 };
static const int *lengths = lengths_list;
static unsigned int testnum;

#define OSSL_NELEM(x) (sizeof(x)/sizeof((x)[0]))
#define SIZE_NUM OSSL_NELEM(lengths_list)
#define MAX_MISALIGNMENT 63
#define COND(unused_cond) (run && count < INT_MAX)

#define START   0
#define STOP    1

static int usertime = 1;
static volatile int run = 0;

/*##########Engine Loader##########*/
/*
 * Support for legacy private engine keys via the 'org.openssl.engine:' scheme
 *
 * org.openssl.engine:{engineid}:{keyid}
 *
 * Note: we ONLY support ENGINE_load_private_key() and ENGINE_load_public_key()
 * Note 2: This scheme has a precedent in code in PKIX-SSH. for exactly
 * this sort of purpose.
 */
#  define ossl_toascii(c)       (c)
#define ASCII_IS_UPPER(c)   (c >= 0x41 && c <= 0x5A)
static const int case_change = 0x20;

int ossl_tolower(int c)
{
    int a = ossl_toascii(c);

    return ASCII_IS_UPPER(a) ? c ^ case_change : c;
}

int OPENSSL_strncasecmp(const char *s1, const char *s2, size_t n)
{
    int t;
    size_t i;

    for (i = 0; i < n; i++)
        if ((t = ossl_tolower(*s1) - ossl_tolower(*s2++)) != 0)
            return t;
        else if (*s1++ == '\0')
            return 0;
    return 0;
}

#define HAS_CASE_PREFIX(s, p) (OPENSSL_strncasecmp(s, p "", sizeof(p) - 1) == 0)

#define CHECK_AND_SKIP_CASE_PREFIX(str, pre) (HAS_CASE_PREFIX(str, pre) ? ((str) += sizeof(pre) - 1, 1) : 0)

/* Local definition of OSSL_STORE_LOADER_CTX */
struct ossl_store_loader_ctx_st {
    ENGINE *e;                   /* Structural reference */
    char *keyid;
    int expected;
    int loaded;                  /* 0 = key not loaded yet, 1 = key loaded */
};

static OSSL_STORE_LOADER_CTX *OSSL_STORE_LOADER_CTX_new(ENGINE *e, char *keyid)
{
    OSSL_STORE_LOADER_CTX *ctx = (OSSL_STORE_LOADER_CTX *)OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->e = e;
        ctx->keyid = keyid;
    }
    return ctx;
}

static void OSSL_STORE_LOADER_CTX_free(OSSL_STORE_LOADER_CTX *ctx)
{
    if (ctx != NULL) {
        ENGINE_free(ctx->e);
        OPENSSL_free(ctx->keyid);
        OPENSSL_free(ctx);
    }
}

static OSSL_STORE_LOADER_CTX *engine_open(const OSSL_STORE_LOADER *loader,
                                          const char *uri,
                                          const UI_METHOD *ui_method,
                                          void *ui_data)
{
    const char *p = uri, *q;
    ENGINE *e = NULL;
    char *keyid = NULL;
    OSSL_STORE_LOADER_CTX *ctx = NULL;

    if (!CHECK_AND_SKIP_CASE_PREFIX(p, ENGINE_SCHEME_COLON))
        return NULL;

    /* Look for engine ID */
    q = strchr(p, ':');
    if (q != NULL                /* There is both an engine ID and a key ID */
        && p[0] != ':'           /* The engine ID is at least one character */
        && q[1] != '\0') {       /* The key ID is at least one character */
        char engineid[256];
        size_t engineid_l = q - p;

        strncpy(engineid, p, engineid_l);
        engineid[engineid_l] = '\0';
        e = ENGINE_by_id(engineid);

        keyid = OPENSSL_strdup(q + 1);
    }

    if (e != NULL && keyid != NULL)
        ctx = OSSL_STORE_LOADER_CTX_new(e, keyid);

    if (ctx == NULL) {
        OPENSSL_free(keyid);
        ENGINE_free(e);
    }

    return ctx;
}

static int engine_expect(OSSL_STORE_LOADER_CTX *ctx, int expected)
{
    if (expected == 0
//        || expected == OSSL_STORE_INFO_PUBKEY
        || expected == OSSL_STORE_INFO_PKEY) {
        ctx->expected = expected;
        return 1;
    }
    return 0;
}

static OSSL_STORE_INFO *engine_load(OSSL_STORE_LOADER_CTX *ctx,
                                    const UI_METHOD *ui_method, void *ui_data)
{
    EVP_PKEY *pkey = NULL, *pubkey = NULL;
    OSSL_STORE_INFO *info = NULL;

    if (ctx->loaded == 0) {
        if (ENGINE_init(ctx->e)) {
            if (ctx->expected == 0
                || ctx->expected == OSSL_STORE_INFO_PKEY)
                pkey =
                    ENGINE_load_private_key(ctx->e, ctx->keyid,
                                            (UI_METHOD *)ui_method, ui_data);
            if ((pkey == NULL && ctx->expected == 0)
//                || ctx->expected == OSSL_STORE_INFO_PUBKEY)
                || ctx->expected == OSSL_STORE_INFO_PKEY)
                pubkey =
                    ENGINE_load_public_key(ctx->e, ctx->keyid,
                                           (UI_METHOD *)ui_method, ui_data);
            ENGINE_finish(ctx->e);
        }
    }

    ctx->loaded = 1;

    if (pubkey != NULL)
//        info = OSSL_STORE_INFO_new_PUBKEY(pubkey);
        info = OSSL_STORE_INFO_new_PKEY(pubkey);
    else if (pkey != NULL)
        info = OSSL_STORE_INFO_new_PKEY(pkey);
    if (info == NULL) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(pubkey);
    }
    return info;
}

static int engine_eof(OSSL_STORE_LOADER_CTX *ctx)
{
    return ctx->loaded != 0;
}

static int engine_error(OSSL_STORE_LOADER_CTX *ctx)
{
    return 0;
}

static int engine_close(OSSL_STORE_LOADER_CTX *ctx)
{
    OSSL_STORE_LOADER_CTX_free(ctx);
    return 1;
}

int setup_engine_loader(void)
{
    OSSL_STORE_LOADER *loader = NULL;

    if ((loader = OSSL_STORE_LOADER_new(NULL, ENGINE_SCHEME)) == NULL
        || !OSSL_STORE_LOADER_set_open(loader, engine_open)
        || !OSSL_STORE_LOADER_set_expect(loader, engine_expect)
        || !OSSL_STORE_LOADER_set_load(loader, engine_load)
        || !OSSL_STORE_LOADER_set_eof(loader, engine_eof)
        || !OSSL_STORE_LOADER_set_error(loader, engine_error)
        || !OSSL_STORE_LOADER_set_close(loader, engine_close)
        || !OSSL_STORE_register_loader(loader)) {
        OSSL_STORE_LOADER_free(loader);
        loader = NULL;
    }

    return loader != NULL;
}

void destroy_engine_loader(void)
{
    OSSL_STORE_LOADER *loader = OSSL_STORE_unregister_loader(ENGINE_SCHEME);
    OSSL_STORE_LOADER_free(loader);
}
/*#################################*/

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct rusage rus;
    struct timeval now;
    static struct timeval tmstart;

    if (usertime)
    {
        getrusage(RUSAGE_SELF, &rus), now = rus.ru_utime;
    }
    else
    {
        gettimeofday(&now, NULL);
    }

    if (stop == START)
    {
        tmstart = now;
    }
    else
    {
        ret = ((now.tv_sec + now.tv_usec * 1e-6) - (tmstart.tv_sec + tmstart.tv_usec * 1e-6));
    }

    return ret;
}

static void alarmed(int sig)
{
    signal(SIGALRM, alarmed);
    run = 0;
}

static double Time_F(int s)
{
    double ret = app_tminterval(s, usertime);

    if (s == STOP)
    {
        alarm(0);
    }

    return ret;
}

static void pkey_print_message(const char *str, const char *str2, long num, unsigned int bits, int tm)
{
    printf("Doing %u bits %s %s's for %ds: ", bits, str, str2, tm);
    fflush(stdout);
    run = 1;
    alarm(tm);
}

void show_test_info(int async_jobs, int seconds, int cipher, const char* cipherName)
{
    printf("\n%s Speed Test.\n", cipherName);

    if(async_jobs == 0)
    {
        printf("Running jobs in sync mode.");
    }
    else
    {
        printf("Running %d async jobs.", async_jobs);
    }

    printf("\n\n");
}

static int RSA_sign_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t *rsa_num = &tempargs->sigsize;
    EVP_PKEY_CTX **rsa_sign_ctx = tempargs->rsa_sign_ctx;
    int ret, count;

    for (count = 0; COND(rsa_c[testnum][0]); count++)
    {
        *rsa_num = tempargs->buflen;
        ret = EVP_PKEY_sign(rsa_sign_ctx[testnum], buf2, rsa_num, buf, 36);

        if (ret <= 0)
        {
            printf("RSA sign failure\n");
            count = -1;
            break;
        }
    }

    return count;
}

static int RSA_verify_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t rsa_num = tempargs->sigsize;
    EVP_PKEY_CTX **rsa_verify_ctx = tempargs->rsa_verify_ctx;
    int ret, count;

    for (count = 0; COND(rsa_c[testnum][1]); count++)
    {
        ret = EVP_PKEY_verify(rsa_verify_ctx[testnum], buf2, rsa_num, buf, 36);

        if (ret <= 0)
        {
            printf("RSA verify failure\n");
            count = -1;
            break;
        }
    }

    return count;
}

static int run_benchmark(int async_jobs, int (*loop_function) (void *), loopargs_t * loopargs)
{
    int job_op_count = 0;
    int total_op_count = 0;
    int num_inprogress = 0;
    int error = 0, i = 0, ret = 0;
    OSSL_ASYNC_FD job_fd = 0;
    size_t num_job_fds = 0;

    if (async_jobs == 0)
    {
        return loop_function((void *)&loopargs);
    }

    for (i = 0; i < async_jobs && !error; i++)
    {
        loopargs_t *looparg_item = loopargs + i;

        /* Copy pointer content (looparg_t item address) into async context */
        ret = ASYNC_start_job(&loopargs[i].inprogress_job, loopargs[i].wait_ctx, &job_op_count, loop_function, (void *)&looparg_item, sizeof(looparg_item));
        
        switch (ret)
        {
        case ASYNC_PAUSE:
            ++num_inprogress;
            break;

        case ASYNC_FINISH:
            if (job_op_count == -1)
            {
                error = 1;
            }
            else
            {
                total_op_count += job_op_count;
            }
            break;

        case ASYNC_NO_JOBS:
        case ASYNC_ERR:
            printf("Failure in the job\n");
            error = 1;
            break;
        }
    }

    while (num_inprogress > 0)
    {
        int select_result = 0;
        OSSL_ASYNC_FD max_fd = 0;
        fd_set waitfdset;

        FD_ZERO(&waitfdset);

        for (i = 0; i < async_jobs && num_inprogress > 0; i++)
        {
            if (loopargs[i].inprogress_job == NULL)
            {
                continue;
            }

            if (!ASYNC_WAIT_CTX_get_all_fds(loopargs[i].wait_ctx, NULL, &num_job_fds) || num_job_fds > 1)
            {
                printf("Too many fds in ASYNC_WAIT_CTX\n");
                error = 1;
                break;
            }

            ASYNC_WAIT_CTX_get_all_fds(loopargs[i].wait_ctx, &job_fd, &num_job_fds);
            FD_SET(job_fd, &waitfdset);

            if (job_fd > max_fd)
            {
                max_fd = job_fd;
            }
        }

        if (max_fd >= (OSSL_ASYNC_FD)FD_SETSIZE)
        {
            printf("Error: max_fd (%d) must be smaller than FD_SETSIZE (%d). Decrease the value of async_jobs\n", max_fd, FD_SETSIZE);
            error = 1;
            break;
        }

        select_result = select(max_fd + 1, &waitfdset, NULL, NULL, NULL);

        if (select_result == -1 && errno == EINTR)
        {
            continue;
        }

        if (select_result == -1)
        {
            printf("Failure in the select\n");
            error = 1;
            break;
        }

        if (select_result == 0)
        {
            continue;
        }

        for (i = 0; i < async_jobs; i++)
        {
            if (loopargs[i].inprogress_job == NULL)
            {
                continue;
            }

            if (!ASYNC_WAIT_CTX_get_all_fds(loopargs[i].wait_ctx, NULL, &num_job_fds) || num_job_fds > 1)
            {
                printf("Too many fds in ASYNC_WAIT_CTX\n");
                error = 1;
                break;
            }

            ASYNC_WAIT_CTX_get_all_fds(loopargs[i].wait_ctx, &job_fd, &num_job_fds);

            if (num_job_fds == 1 && !FD_ISSET(job_fd, &waitfdset))
            {
                continue;
            }

            ret = ASYNC_start_job(&loopargs[i].inprogress_job, loopargs[i].wait_ctx, &job_op_count, loop_function, (void *)(loopargs + i), sizeof(loopargs_t));

            switch (ret)
            {
            case ASYNC_PAUSE:
                break;

            case ASYNC_FINISH:
                if (job_op_count == -1)
                {
                    error = 1;
                }
                else
                {
                    total_op_count += job_op_count;
                }

                --num_inprogress;
                loopargs[i].inprogress_job = NULL;

                break;

            case ASYNC_NO_JOBS:
            case ASYNC_ERR:
                --num_inprogress;
                loopargs[i].inprogress_job = NULL;
                printf("Failure in the job\n");
                error = 1;
                break;
            }
        }
    }

    return error ? -1 : total_op_count;
}

int run_speed_test(int async_jobs, int seconds, int cipher, const char* cipherName)
{
    int ret = 1;

    if(async_jobs > 0 && !ASYNC_is_capable())  
    {
        printf("async_jobs specified but async not supported\n");
        return ret;
    }

    /* Set non-default library initialisation settings */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL))
    {
        printf("Error in OpenSSL init\n");
        return ret;
    }

    if(!setup_engine_loader())
    {
        printf("Error in the engine loader\n");
        return ret;
    }

    show_test_info(async_jobs, seconds, cipher, cipherName);

    int async_init = 0;
    unsigned int loopargs_len = 0;
    loopargs_t *loopargs = NULL;
    unsigned int size_num = SIZE_NUM;
    int buflen = 0;
    int misalign = 0;
    const char* engine_id = NULL;
    EVP_PKEY *rsa_key = NULL;
    int st = 0;
    BIGNUM* bn = NULL;
    EVP_PKEY_CTX *genctx = NULL;
    ENGINE* engine = NULL;
    long op_count = 1;
    long count = 0;
    double d = 0.0;
 
    static const struct
    {
        const unsigned char *data;
        unsigned int length;
        unsigned int bits;
    } rsa_keys[] = 
    {
        {   test512,   sizeof(test512),   512 },
        {  test1024,  sizeof(test1024),  1024 },
        {  test2048,  sizeof(test2048),  2048 },
        {  test3072,  sizeof(test3072),  3072 },
        {  test4096,  sizeof(test4096),  4096 },
        {  test7680,  sizeof(test7680),  7680 },
        { test15360, sizeof(test15360), 15360 }
    };

    // const char* openssl_conf = getenv("OPENSSL_CONF");
    // std::string config{openssl_conf ? openssl_conf : ""};

    // if(strstr(config.c_str(), "openssl-qat.cnf"))
    // {
    //     engine_id = "qatengine";
    // }

    /* Initialize the job pool if async mode is enabled */
    if (async_jobs > 0)
    {
        async_init = ASYNC_init_thread(async_jobs, async_jobs);

        if (!async_init)
        {
            printf("Error creating the ASYNC job pool\n");
            return ret;
        }
    }

    loopargs_len = (async_jobs == 0 ? 1 : async_jobs);

    if((loopargs = (loopargs_t *)OPENSSL_malloc(loopargs_len * sizeof(loopargs_t))) == NULL)
    {
        printf("Could not allocate array of loop arguments\n");
        goto cleanup;
    }

    memset(loopargs, 0, loopargs_len * sizeof(loopargs_t));
    
    buflen = lengths[size_num - 1];

    if (buflen < 36) /* size of random vector in RSA benchmark */
    {
        buflen = 36;
    }

    if (INT_MAX - (MAX_MISALIGNMENT + 1) < buflen)
    {
        printf("Error: buffer size too large\n");
        goto cleanup;
    }

    buflen += MAX_MISALIGNMENT + 1;

    for (int i = 0; i < loopargs_len; i++)
    {
        if (async_jobs > 0)
        {
            loopargs[i].wait_ctx = ASYNC_WAIT_CTX_new();

            if (loopargs[i].wait_ctx == NULL)
            {
                printf("Error creating the ASYNC_WAIT_CTX\n");
                goto cleanup;
            }
        }

        if((loopargs[i].buf_malloc = (unsigned char *)OPENSSL_malloc(buflen)) == NULL)
        {
            printf("Could not allocate input buffer 1");
        }

        if((loopargs[i].buf2_malloc = (unsigned char *)OPENSSL_malloc(buflen)) == NULL)
        {
            printf("Could not allocate input buffer 2");
        }

        /* Align the start of buffers on a 64 byte boundary */
        loopargs[i].buf = loopargs[i].buf_malloc + misalign;
        loopargs[i].buf2 = loopargs[i].buf2_malloc + misalign;
        loopargs[i].buflen = buflen - misalign;
        loopargs[i].sigsize = buflen - misalign;
    }

    for (int i = 0; i < loopargs_len; ++i)
    {
        (void)mlock(loopargs[i].buf_malloc, buflen);
        (void)mlock(loopargs[i].buf_malloc, buflen);

        memset(loopargs[i].buf_malloc, 0, buflen);
        memset(loopargs[i].buf2_malloc, 0, buflen);
    }

    /* Initialize the engine */
    //engine = setup_engine(engine_id, 0);

    signal(SIGALRM, alarmed);

    for (testnum = 0; testnum < RSA_NUM; testnum++)
    {
        if(rsa_keys[testnum].bits == cipher)
        {
            break;
        }
    }

    if(testnum == RSA_NUM)
    {
        printf("Invalid num bits for RSA\n");
        goto cleanup;
    }

    { //Use this scope block to avoid compiler error on 'goto cleanup' 
        const unsigned char *p = rsa_keys[testnum].data;

        st = (rsa_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, rsa_keys[testnum].length)) != NULL;
    }

    for (int i = 0; st && i < loopargs_len; i++)
    {
        loopargs[i].rsa_sign_ctx[testnum] = EVP_PKEY_CTX_new(rsa_key, NULL);
        loopargs[i].sigsize = loopargs[i].buflen;

        if (loopargs[i].rsa_sign_ctx[testnum] == NULL || EVP_PKEY_sign_init(loopargs[i].rsa_sign_ctx[testnum]) <= 0 ||
            EVP_PKEY_sign(loopargs[i].rsa_sign_ctx[testnum], loopargs[i].buf2, &loopargs[i].sigsize, loopargs[i].buf, 36) <= 0)
        {                       
            st = 0;
        }
    }

    if (!st)
    {
        printf("RSA sign setup failure. No RSA sign will be done.\n");
        op_count = 1;
    }
    else
    {
        pkey_print_message("private", "rsa", rsa_c[testnum][0], rsa_keys[testnum].bits, seconds);
        
        Time_F(START);
        count = run_benchmark(async_jobs, RSA_sign_loop, loopargs);
        d = Time_F(STOP);
        
        printf("%ld %u bits private RSA's in %.2fs\n", count, rsa_keys[testnum].bits, d);
        rsa_results[testnum][0] = (double)count / d;
        op_count = count;
    }

    for (int i = 0; st && i < loopargs_len; i++)
    {
        loopargs[i].rsa_verify_ctx[testnum] = EVP_PKEY_CTX_new(rsa_key, NULL);
        if (loopargs[i].rsa_verify_ctx[testnum] == NULL || EVP_PKEY_verify_init(loopargs[i].rsa_verify_ctx[testnum]) <= 0 ||
            EVP_PKEY_verify(loopargs[i].rsa_verify_ctx[testnum], loopargs[i].buf2, loopargs[i].sigsize, loopargs[i].buf, 36) <= 0)
        {
            st = 0;
        }
    }

    if (!st)
    {
        printf("RSA verify setup failure.  No RSA verify will be done.\n");
    }
    else
    {
        pkey_print_message("public", "rsa", rsa_c[testnum][1], rsa_keys[testnum].bits, seconds);

        Time_F(START);
        count = run_benchmark(async_jobs, RSA_verify_loop, loopargs);
        d = Time_F(STOP);

        printf("%ld %u bits public RSA's in %.2fs\n", count, rsa_keys[testnum].bits, d);
        rsa_results[testnum][1] = (double)count / d;
    }
 
    EVP_PKEY_free(rsa_key);

    printf("%18ssign    verify    sign/s verify/s\n", " ");
    printf("rsa %4u bits %8.6fs %8.6fs %8.1f %8.1f\n", rsa_keys[testnum].bits, 1.0 / rsa_results[testnum][0], 1.0 / rsa_results[testnum][1], rsa_results[testnum][0], rsa_results[testnum][1]);

cleanup:
   for (int i = 0; i < loopargs_len; i++)
    {
        OPENSSL_free(loopargs[i].buf_malloc);
        OPENSSL_free(loopargs[i].buf2_malloc);

        BN_free(bn);
        EVP_PKEY_CTX_free(genctx);

        for (int k = 0; k < RSA_NUM; k++)
        {
            EVP_PKEY_CTX_free(loopargs[i].rsa_sign_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].rsa_verify_ctx[k]);
        }
    }

    if (async_jobs > 0)
    {
        for (int i = 0; i < loopargs_len; i++)
        {
            ASYNC_WAIT_CTX_free(loopargs[i].wait_ctx);
        }
    }

    if (async_init)
    {
        ASYNC_cleanup_thread();
    }

    OPENSSL_free(loopargs);

    ENGINE_free(engine);
    destroy_engine_loader();

    return ret;
}