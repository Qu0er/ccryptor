/*
 * cryptor — быстрый шифрованный архиватор директорий.
 *
 *   cryptor keygen <keyfile>
 *   cryptor enc -k <keyfile> [-j threads] [-l level] [-c chunk_KiB] <dir> <archive>
 *   cryptor dec -k <keyfile> [-j threads] <archive> <outdir>
 *
 * Конвейер: обход дерева -> N воркеров (deflate + AES-256-GCM) -> упорядоченная запись.
 * Файлы режутся на чанки, поэтому параллелится даже один огромный файл.
 *
 * Формат архива:
 *   header (32 байта, открыто): "CRYPTOR1" | u32 version | u32 chunk | salt[16]
 *   subkey = HKDF-SHA256(ikm = key, salt = salt, info = "cryptor/v1" || header)
 *   далее записи: u32 plen | ciphertext[plen] | tag[16]
 *   nonce записи = 0x00000000 || u64be(порядковый номер записи)
 *     -> перестановка, удаление или подмена записей ломают аутентификацию;
 *        обрезка архива ловится по обязательной финальной записи END.
 *   Внутри (зашифровано): тип записи + метаданные (пути, права, mtime) или данные.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <linux/openat2.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <zlib.h>

#define MAGIC       "CRYPTOR1"
#define VERSION     1u
#define HDR_LEN     32
#define KEY_LEN     32
#define SALT_LEN    16
#define TAG_LEN     16
#define PATH_MAXLEN 4095
#define META_MAX    (1 + 4 + 8 + 4 + 8 + 2 + PATH_MAXLEN + 2 + PATH_MAXLEN)
#define DEF_CHUNK   (1u << 20)
#define MIN_CHUNK   (4u << 10)
#define MAX_CHUNK   (64u << 20)

enum { R_DIR = 1, R_FILE = 2, R_LINK = 3, R_DATA_Z = 4, R_DATA_RAW = 5, R_END = 6 };
enum { K_META = 0, K_DATA = 1 };
enum { S_EMPTY = 0, S_READY, S_DONE };

/* ------------------------------------------------------------------ utils */

static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = v >> (8 * i); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = v >> (8 * i); }
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int write_full(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static ssize_t pread_full(int fd, void *buf, size_t n, off_t off) {
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = pread(fd, p + got, n - got, off + (off_t)got);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) break;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static double now_sec(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

/* --------------------------------------------------------------- pipeline */

typedef struct fref {
    int fd;
    atomic_int refs;
    char *path;
} fref_t;

typedef struct {
    int state;
    uint64_t seq;
    int kind;               /* enc: K_META/K_DATA; dec: тип записи после расшифровки */
    fref_t *fr;             /* enc: исходный файл чанка */
    uint64_t off;
    uint32_t len;
    uint8_t *a, *b;         /* a — открытый текст, b — шифртекст / scratch */
    size_t alen, blen;
    const uint8_t *data;    /* dec: готовые данные для записи */
    size_t dlen;
} slot_t;

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv_free, cv_work, cv_done;
    slot_t *slots;
    unsigned n;
    uint64_t produced, claimed, written;
    int done;
    atomic_int err;
} P = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv_free = PTHREAD_COND_INITIALIZER,
        .cv_work = PTHREAD_COND_INITIALIZER, .cv_done = PTHREAD_COND_INITIALIZER };

static struct {
    int decrypt;
    int level;
    uint32_t chunk;
    size_t max_plain;
    uint8_t subkey[KEY_LEN];
    /* enc */
    size_t prefix;
    dev_t skip_dev;
    ino_t skip_ino;
    FILE *out;
    uint64_t nfiles, ndirs, nlinks, nbytes, outbytes;
} G = { .level = 9, .chunk = DEF_CHUNK };

/* Никогда не вызывать под P.mu. */
static void fail(const char *fmt, ...) {
    pthread_mutex_lock(&P.mu);
    int first = !atomic_exchange(&P.err, 1);
    pthread_cond_broadcast(&P.cv_free);
    pthread_cond_broadcast(&P.cv_work);
    pthread_cond_broadcast(&P.cv_done);
    pthread_mutex_unlock(&P.mu);
    if (!first) return;                 /* печатаем только первопричину */
    va_list ap;
    va_start(ap, fmt);
    fputs("cryptor: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
}

static slot_t *acquire(void) {
    pthread_mutex_lock(&P.mu);
    slot_t *s = &P.slots[P.produced % P.n];
    while (s->state != S_EMPTY && !P.err)
        pthread_cond_wait(&P.cv_free, &P.mu);
    if (P.err) { pthread_mutex_unlock(&P.mu); return NULL; }
    s->seq = P.produced;
    pthread_mutex_unlock(&P.mu);
    return s;
}

static void submit(slot_t *s) {
    pthread_mutex_lock(&P.mu);
    s->state = S_READY;
    P.produced++;
    pthread_cond_signal(&P.cv_work);
    pthread_mutex_unlock(&P.mu);
}

static void finish_producing(void) {
    pthread_mutex_lock(&P.mu);
    P.done = 1;
    pthread_cond_broadcast(&P.cv_work);
    pthread_cond_broadcast(&P.cv_done);
    pthread_mutex_unlock(&P.mu);
}

static int alloc_slots(unsigned n) {
    P.n = n;
    P.slots = calloc(n, sizeof *P.slots);
    if (!P.slots) return -1;
    for (unsigned i = 0; i < n; i++) {
        P.slots[i].a = malloc(G.max_plain);
        P.slots[i].b = malloc(4 + G.max_plain + TAG_LEN);
        if (!P.slots[i].a || !P.slots[i].b) return -1;
    }
    return 0;
}

/* ----------------------------------------------------------------- crypto */

static void mk_iv(uint8_t iv[12], uint64_t seq) {
    memset(iv, 0, 4);
    for (int i = 0; i < 8; i++) iv[4 + i] = seq >> (56 - 8 * i);
}

static int gcm_seal(EVP_CIPHER_CTX *c, uint64_t seq, const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t iv[12];
    int l, f;
    mk_iv(iv, seq);
    if (EVP_EncryptInit_ex(c, NULL, NULL, NULL, iv) != 1) return -1;
    if (EVP_EncryptUpdate(c, out, &l, in, (int)n) != 1) return -1;
    if (EVP_EncryptFinal_ex(c, out + l, &f) != 1) return -1;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, TAG_LEN, out + n) != 1) return -1;
    return 0;
}

static int gcm_open(EVP_CIPHER_CTX *c, uint64_t seq, const uint8_t *in, size_t n, uint8_t *out) {
    uint8_t iv[12];
    int l, f;
    mk_iv(iv, seq);
    if (EVP_DecryptInit_ex(c, NULL, NULL, NULL, iv) != 1) return -1;
    if (EVP_DecryptUpdate(c, out, &l, in, (int)n) != 1) return -1;
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)(in + n)) != 1) return -1;
    if (EVP_DecryptFinal_ex(c, out + l, &f) != 1) return -1;
    return 0;
}

static int derive_subkey(const uint8_t key[KEY_LEN], const uint8_t hdr[HDR_LEN]) {
    uint8_t info[10 + HDR_LEN];
    memcpy(info, "cryptor/v1", 10);
    memcpy(info + 10, hdr, HDR_LEN);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return -1;
    EVP_KDF_CTX *k = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!k) return -1;
    OSSL_PARAM prm[5], *p = prm;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)key, KEY_LEN);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)(hdr + 16), SALT_LEN);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof info);
    *p = OSSL_PARAM_construct_end();
    int ok = EVP_KDF_derive(k, G.subkey, KEY_LEN, prm) == 1;
    EVP_KDF_CTX_free(k);
    return ok ? 0 : -1;
}

static int random_bytes(uint8_t *p, size_t n) {
    while (n) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int load_key(const char *path, uint8_t key[KEY_LEN]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "cryptor: %s: %s\n", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size != KEY_LEN) {
        fprintf(stderr, "cryptor: %s: ключ должен быть ровно %d байт (сгенерируйте через keygen)\n",
                path, KEY_LEN);
        close(fd);
        return -1;
    }
    if (st.st_mode & 077)
        fprintf(stderr, "cryptor: внимание: файл ключа %s доступен другим пользователям (chmod 600)\n", path);
    ssize_t r = pread_full(fd, key, KEY_LEN, 0);
    close(fd);
    if (r != KEY_LEN) { fprintf(stderr, "cryptor: %s: ошибка чтения\n", path); return -1; }
    return 0;
}

/* ---------------------------------------------------------------- workers */

typedef struct {
    EVP_CIPHER_CTX *c;
    z_stream z;
} wctx_t;

static int enc_work(wctx_t *w, slot_t *s) {
    if (s->kind == K_DATA) {
        uint8_t *raw = s->b + 4;            /* scratch: потом перетрётся шифртекстом */
        fref_t *fr = s->fr;
        ssize_t got = pread_full(fr->fd, raw, s->len, (off_t)s->off);
        if (got != (ssize_t)s->len) {
            fail("%s: %s", fr->path, got < 0 ? strerror(errno) : "файл уменьшился во время чтения");
            return 0;
        }
        if (atomic_fetch_sub(&fr->refs, 1) == 1) {
            close(fr->fd);
            free(fr->path);
            free(fr);
        }
        uint8_t *a = s->a;
        put32(a + 1, s->len);
        deflateReset(&w->z);
        w->z.next_in = raw;
        w->z.avail_in = s->len;
        w->z.next_out = a + 5;
        w->z.avail_out = s->len;            /* не влезло меньше исходника -> храним как есть */
        if (deflate(&w->z, Z_FINISH) == Z_STREAM_END && w->z.total_out < s->len) {
            a[0] = R_DATA_Z;
            s->alen = 5 + w->z.total_out;
        } else {
            a[0] = R_DATA_RAW;
            memcpy(a + 5, raw, s->len);
            s->alen = 5 + (size_t)s->len;
        }
    }
    put32(s->b, (uint32_t)s->alen);
    if (gcm_seal(w->c, s->seq, s->a, s->alen, s->b + 4) < 0) { fail("ошибка шифрования"); return 0; }
    s->blen = 4 + s->alen + TAG_LEN;
    return 1;
}

static int dec_work(wctx_t *w, slot_t *s) {
    if (gcm_open(w->c, s->seq, s->b, s->blen, s->a) < 0) {
        fail("запись #%llu: аутентификация не прошла — неверный ключ или архив повреждён/подменён",
             (unsigned long long)s->seq);
        return 0;
    }
    uint8_t t = s->a[0];
    s->kind = t;
    if (t == R_DATA_Z || t == R_DATA_RAW) {
        if (s->blen < 5) goto bad;
        uint32_t raw = get32(s->a + 1);
        if (raw == 0 || raw > G.chunk) goto bad;
        if (t == R_DATA_RAW) {
            if (s->blen - 5 != raw) goto bad;
            s->data = s->a + 5;
        } else {
            inflateReset(&w->z);
            w->z.next_in = s->a + 5;
            w->z.avail_in = (uInt)(s->blen - 5);
            w->z.next_out = s->b;
            w->z.avail_out = raw;
            if (inflate(&w->z, Z_FINISH) != Z_STREAM_END || w->z.total_out != raw || w->z.avail_in)
                goto bad;
            s->data = s->b;
        }
        s->dlen = raw;
    } else {
        s->data = s->a;
        s->dlen = s->blen;
    }
    return 1;
bad:
    fail("запись #%llu: повреждённые данные", (unsigned long long)s->seq);
    return 0;
}

static void *worker(void *arg) {
    (void)arg;
    wctx_t w;
    memset(&w, 0, sizeof w);
    w.c = EVP_CIPHER_CTX_new();
    int ok = w.c != NULL;
    if (ok && !G.decrypt)
        ok = EVP_EncryptInit_ex(w.c, EVP_aes_256_gcm(), NULL, G.subkey, NULL) == 1 &&
             deflateInit2(&w.z, G.level, Z_DEFLATED, -15, 9, Z_DEFAULT_STRATEGY) == Z_OK;
    else if (ok)
        ok = EVP_DecryptInit_ex(w.c, EVP_aes_256_gcm(), NULL, G.subkey, NULL) == 1 &&
             inflateInit2(&w.z, -15) == Z_OK;
    if (!ok) { fail("не удалось инициализировать воркер"); goto out; }

    for (;;) {
        pthread_mutex_lock(&P.mu);
        while (P.claimed == P.produced && !P.done && !P.err)
            pthread_cond_wait(&P.cv_work, &P.mu);
        if (P.err || P.claimed == P.produced) { pthread_mutex_unlock(&P.mu); break; }
        slot_t *s = &P.slots[P.claimed++ % P.n];
        pthread_mutex_unlock(&P.mu);

        if (!(G.decrypt ? dec_work(&w, s) : enc_work(&w, s))) break;

        pthread_mutex_lock(&P.mu);
        s->state = S_DONE;
        pthread_cond_signal(&P.cv_done);
        pthread_mutex_unlock(&P.mu);
    }
out:
    if (G.decrypt) inflateEnd(&w.z); else deflateEnd(&w.z);
    EVP_CIPHER_CTX_free(w.c);
    return NULL;
}

static int enc_consume(slot_t *s);
static int dec_consume(slot_t *s);

static void *writer(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&P.mu);
        slot_t *s = &P.slots[P.written % P.n];
        while (!P.err && !(P.written < P.produced && s->state == S_DONE) &&
               !(P.done && P.written == P.produced))
            pthread_cond_wait(&P.cv_done, &P.mu);
        if (P.err || P.written == P.produced) { pthread_mutex_unlock(&P.mu); break; }
        pthread_mutex_unlock(&P.mu);

        if (!(G.decrypt ? dec_consume(s) : enc_consume(s))) break;

        pthread_mutex_lock(&P.mu);
        s->state = S_EMPTY;
        P.written++;
        pthread_cond_signal(&P.cv_free);
        pthread_mutex_unlock(&P.mu);
    }
    return NULL;
}

/* ------------------------------------------------------------- encryption */

static int enc_consume(slot_t *s) {
    if (fwrite(s->b, 1, s->blen, G.out) != s->blen) { fail("запись архива: %s", strerror(errno)); return 0; }
    G.outbytes += s->blen;
    return 1;
}

static size_t meta_head(uint8_t *a, int type, const struct stat *st) {
    a[0] = (uint8_t)type;
    put32(a + 1, st->st_mode);
    put64(a + 5, (uint64_t)st->st_mtim.tv_sec);
    put32(a + 13, (uint32_t)st->st_mtim.tv_nsec);
    return 17;
}

static size_t put_str(uint8_t *p, const char *str, size_t n) {
    put16(p, (uint16_t)n);
    memcpy(p + 2, str, n);
    return 2 + n;
}

static int emit_meta_dir(const char *rel, size_t rl, const struct stat *st) {
    slot_t *s = acquire();
    if (!s) return -1;
    size_t o = meta_head(s->a, R_DIR, st);
    o += put_str(s->a + o, rel, rl);
    s->alen = o;
    s->kind = K_META;
    submit(s);
    G.ndirs++;
    return 0;
}

static int emit_link(const char *fpath, const char *rel, size_t rl, const struct stat *sb) {
    char tgt[PATH_MAXLEN + 1];
    ssize_t tl = readlink(fpath, tgt, sizeof tgt);
    if (tl < 0) { fail("%s: %s", fpath, strerror(errno)); return -1; }
    if (tl == 0 || tl > PATH_MAXLEN) { fail("%s: слишком длинная цель ссылки", fpath); return -1; }
    slot_t *s = acquire();
    if (!s) return -1;
    size_t o = meta_head(s->a, R_LINK, sb);
    o += put_str(s->a + o, rel, rl);
    o += put_str(s->a + o, tgt, (size_t)tl);
    s->alen = o;
    s->kind = K_META;
    submit(s);
    G.nlinks++;
    return 0;
}

static int emit_file(const char *fpath, const char *rel, size_t rl) {
    int fd = open(fpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOATIME);
    if (fd < 0 && errno == EPERM) fd = open(fpath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { fail("%s: %s", fpath, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { fail("%s: %s", fpath, strerror(errno)); close(fd); return -1; }
    if (!S_ISREG(st.st_mode) || (st.st_dev == G.skip_dev && st.st_ino == G.skip_ino)) {
        close(fd);
        return 0;
    }
    slot_t *s = acquire();
    if (!s) { close(fd); return -1; }
    size_t o = meta_head(s->a, R_FILE, &st);
    put64(s->a + o, (uint64_t)st.st_size);
    o += 8;
    o += put_str(s->a + o, rel, rl);
    s->alen = o;
    s->kind = K_META;
    submit(s);
    G.nfiles++;
    G.nbytes += (uint64_t)st.st_size;

    uint64_t size = (uint64_t)st.st_size;
    if (size == 0) { close(fd); return 0; }
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    uint64_t nchunks = (size + G.chunk - 1) / G.chunk;
    fref_t *fr = malloc(sizeof *fr);
    if (!fr || !(fr->path = strdup(fpath))) { fail("нет памяти"); return -1; }
    fr->fd = fd;
    atomic_init(&fr->refs, (int)nchunks);
    for (uint64_t off = 0; off < size; off += G.chunk) {
        if (!(s = acquire())) return -1;
        s->kind = K_DATA;
        s->fr = fr;
        s->off = off;
        s->len = (uint32_t)(size - off < G.chunk ? size - off : G.chunk);
        submit(s);
    }
    return 0;
}

static int walk_cb(const char *fpath, const struct stat *sb, int tf, struct FTW *ftw) {
    if (P.err) return 1;
    if (ftw->level == 0) return 0;
    const char *rel = fpath + G.prefix;
    size_t rl = strlen(rel);
    if (rl > PATH_MAXLEN) { fail("%s: слишком длинный путь", fpath); return 1; }
    switch (tf) {
    case FTW_D:   if (emit_meta_dir(rel, rl, sb)) return 1; break;
    case FTW_SL:
    case FTW_SLN: if (emit_link(fpath, rel, rl, sb)) return 1; break;
    case FTW_F:
        if (S_ISREG(sb->st_mode)) { if (emit_file(fpath, rel, rl)) return 1; }
        else fprintf(stderr, "cryptor: пропускаю спецфайл %s\n", fpath);
        break;
    case FTW_DNR: fail("%s: нет доступа к директории", fpath); return 1;
    default:      fail("%s: не удалось получить stat", fpath); return 1;
    }
    return 0;
}

static int run_threads(int nthreads, void (*producer)(void *), void *parg) {
    pthread_t wt, *th = calloc((size_t)nthreads, sizeof *th);
    if (!th || pthread_create(&wt, NULL, writer, NULL)) { fprintf(stderr, "cryptor: pthread\n"); return -1; }
    int started = 0;
    for (; started < nthreads; started++)
        if (pthread_create(&th[started], NULL, worker, NULL)) { fail("pthread_create"); break; }
    producer(parg);
    finish_producing();
    for (int i = 0; i < started; i++) pthread_join(th[i], NULL);
    pthread_join(wt, NULL);
    free(th);
    return P.err ? -1 : 0;
}

static void enc_producer(void *arg) {
    const char *root = arg;
    if (nftw(root, walk_cb, 64, FTW_PHYS) < 0 && !P.err) { fail("%s: %s", root, strerror(errno)); return; }
    if (P.err) return;
    slot_t *s = acquire();
    if (!s) return;
    s->a[0] = R_END;
    put64(s->a + 1, G.nfiles);
    put64(s->a + 9, G.ndirs);
    put64(s->a + 17, G.nlinks);
    put64(s->a + 25, G.nbytes);
    s->alen = 33;
    s->kind = K_META;
    submit(s);
}

static int cmd_enc(const char *keyfile, int nthreads, char *root, const char *out) {
    uint8_t key[KEY_LEN], hdr[HDR_LEN];
    if (load_key(keyfile, key) < 0) return 1;

    size_t rlen = strlen(root);
    while (rlen > 1 && root[rlen - 1] == '/') root[--rlen] = 0;
    G.prefix = rlen + (root[rlen - 1] == '/' ? 0 : 1);
    struct stat st;
    if (stat(root, &st) < 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "cryptor: %s: не директория\n", root);
        return 1;
    }
    if (lstat(out, &st) == 0) { fprintf(stderr, "cryptor: %s уже существует\n", out); return 1; }

    char *part;
    if (asprintf(&part, "%s.part", out) < 0) return 1;
    int ofd = open(part, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (ofd < 0) { fprintf(stderr, "cryptor: %s: %s\n", part, strerror(errno)); return 1; }
    fstat(ofd, &st);
    G.skip_dev = st.st_dev;
    G.skip_ino = st.st_ino;
    G.out = fdopen(ofd, "wb");
    setvbuf(G.out, NULL, _IOFBF, 8u << 20);

    memcpy(hdr, MAGIC, 8);
    put32(hdr + 8, VERSION);
    put32(hdr + 12, G.chunk);
    if (random_bytes(hdr + 16, SALT_LEN) < 0 || derive_subkey(key, hdr) < 0) {
        fprintf(stderr, "cryptor: ошибка генерации ключа\n");
        goto err;
    }
    OPENSSL_cleanse(key, sizeof key);
    if (fwrite(hdr, 1, HDR_LEN, G.out) != HDR_LEN) goto err;
    G.outbytes = HDR_LEN;

    G.max_plain = 5 + (size_t)G.chunk > META_MAX ? 5 + (size_t)G.chunk : META_MAX;
    if (alloc_slots((unsigned)nthreads * 2 + 4) < 0) { fprintf(stderr, "cryptor: нет памяти\n"); goto err; }

    double t0 = now_sec();
    if (run_threads(nthreads, enc_producer, root) < 0) goto err;
    if (fflush(G.out) || fsync(fileno(G.out)) || fclose(G.out)) {
        G.out = NULL;
        fprintf(stderr, "cryptor: запись архива: %s\n", strerror(errno));
        goto err;
    }
    G.out = NULL;
    if (renameat2(AT_FDCWD, part, AT_FDCWD, out, RENAME_NOREPLACE) < 0) {
        fprintf(stderr, "cryptor: rename %s -> %s: %s\n", part, out, strerror(errno));
        goto err;
    }
    double dt = now_sec() - t0;
    fprintf(stderr, "готово: %llu файлов, %llu директорий, %llu ссылок; %.1f MiB -> %.1f MiB (%.1f%%) за %.2f c, %.0f MiB/s\n",
            (unsigned long long)G.nfiles, (unsigned long long)G.ndirs, (unsigned long long)G.nlinks,
            G.nbytes / 1048576.0, G.outbytes / 1048576.0,
            G.nbytes ? 100.0 * G.outbytes / G.nbytes : 0.0, dt, G.nbytes / 1048576.0 / (dt > 0 ? dt : 1e-9));
    OPENSSL_cleanse(G.subkey, sizeof G.subkey);
    free(part);
    return 0;
err:
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(G.subkey, sizeof G.subkey);
    if (G.out) fclose(G.out);
    unlink(part);
    free(part);
    return 1;
}

/* ------------------------------------------------------------- decryption */

typedef struct { char *path; uint32_t mode; struct timespec ts[2]; } ddir_t;
typedef struct { char *path, *target; struct timespec ts[2]; } dlink_t;

static struct {
    int root, cur, ended;
    uint64_t left;
    uint32_t cmode;
    struct timespec cts[2];
    char ppath[PATH_MAXLEN + 1];
    int pfd;
    ddir_t *dirs; size_t nd, cd;
    dlink_t *links; size_t nl, cl;
    uint64_t nfiles, ndirs, nlinks, nbytes;
} X = { .root = -1, .cur = -1, .pfd = -1 };

/* openat2 с запретом выхода за корень и любых симлинков в пути (защита от path traversal). */
static int open_beneath(int dfd, const char *path, int flags) {
    struct open_how how = { .flags = (uint64_t)flags,
                            .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS };
    return (int)syscall(SYS_openat2, dfd, path, &how, sizeof how);
}

static int path_ok(const char *p, size_t n) {
    if (n == 0 || n > PATH_MAXLEN || memchr(p, 0, n) || p[0] == '/') return 0;
    size_t i = 0;
    while (i <= n) {
        size_t j = i;
        while (j < n && p[j] != '/') j++;
        size_t cl = j - i;
        if (cl == 0 || (cl == 1 && p[i] == '.') || (cl == 2 && p[i] == '.' && p[i + 1] == '.')) return 0;
        i = j + 1;
    }
    return 1;
}

/* Возвращает fd родительской директории (кэшируется) и имя последнего компонента. */
static int parent_of(const char *path, const char **base) {
    const char *sl = strrchr(path, '/');
    if (!sl) { *base = path; return X.root; }
    *base = sl + 1;
    size_t pl = (size_t)(sl - path);
    if (X.pfd >= 0 && strlen(X.ppath) == pl && !memcmp(X.ppath, path, pl)) return X.pfd;
    if (X.pfd >= 0) close(X.pfd);
    memcpy(X.ppath, path, pl);
    X.ppath[pl] = 0;
    X.pfd = open_beneath(X.root, X.ppath, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (X.pfd < 0) X.ppath[0] = 0;
    return X.pfd;
}

typedef struct { const uint8_t *p; size_t n; int bad; } rd_t;

static uint64_t rd_int(rd_t *r, int bytes) {
    if (r->n < (size_t)bytes) { r->bad = 1; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < bytes; i++) v |= (uint64_t)r->p[i] << (8 * i);
    r->p += bytes; r->n -= (size_t)bytes;
    return v;
}

static int rd_str(rd_t *r, char out[PATH_MAXLEN + 1], size_t *len) {
    size_t l = (size_t)rd_int(r, 2);
    if (r->bad || l == 0 || l > PATH_MAXLEN || r->n < l || memchr(r->p, 0, l)) { r->bad = 1; return -1; }
    memcpy(out, r->p, l);
    out[l] = 0;
    *len = l;
    r->p += l; r->n -= l;
    return 0;
}

static int finish_cur(void) {
    int rc = 0;
    if (fchmod(X.cur, X.cmode & 07777) || futimens(X.cur, X.cts)) rc = -1;
    if (close(X.cur)) rc = -1;
    X.cur = -1;
    if (rc) fail("установка атрибутов файла: %s", strerror(errno));
    return rc;
}

static int dec_consume(slot_t *s) {
    char path[PATH_MAXLEN + 1], tgt[PATH_MAXLEN + 1];
    size_t pl, tl;
    const char *base;
    int pfd;

    if (X.ended) { fail("данные после маркера конца архива"); return 0; }
    if (X.cur >= 0) {
        if (s->kind != R_DATA_Z && s->kind != R_DATA_RAW) { fail("ожидались данные файла"); return 0; }
        if (s->dlen > X.left) { fail("данных больше, чем размер файла"); return 0; }
        if (write_full(X.cur, s->data, s->dlen) < 0) { fail("запись: %s", strerror(errno)); return 0; }
        X.left -= s->dlen;
        X.nbytes += s->dlen;
        if (!X.left && finish_cur() < 0) return 0;
        return 1;
    }

    rd_t r = { s->data + 1, s->dlen - 1, 0 };
    switch (s->kind) {
    case R_DIR:
    case R_FILE: {
        uint32_t mode = (uint32_t)rd_int(&r, 4);
        struct timespec ts[2] = { { 0, UTIME_OMIT } };
        ts[1].tv_sec = (time_t)rd_int(&r, 8);
        ts[1].tv_nsec = (long)rd_int(&r, 4);
        uint64_t size = s->kind == R_FILE ? rd_int(&r, 8) : 0;
        if (rd_str(&r, path, &pl) < 0 || r.n || !path_ok(path, pl) || ts[1].tv_nsec >= 1000000000L) break;
        if ((pfd = parent_of(path, &base)) < 0) { fail("%s: %s", path, strerror(errno)); return 0; }
        if (s->kind == R_DIR) {
            if (mkdirat(pfd, base, 0700) < 0) {
                struct stat st;
                if (errno != EEXIST || fstatat(pfd, base, &st, AT_SYMLINK_NOFOLLOW) || !S_ISDIR(st.st_mode)) {
                    fail("mkdir %s: %s", path, strerror(errno));
                    return 0;
                }
            }
            if (X.nd == X.cd) {
                X.cd = X.cd ? X.cd * 2 : 256;
                X.dirs = realloc(X.dirs, X.cd * sizeof *X.dirs);
                if (!X.dirs) { fail("нет памяти"); return 0; }
            }
            ddir_t *d = &X.dirs[X.nd++];
            d->path = strdup(path);
            d->mode = mode;
            memcpy(d->ts, ts, sizeof ts);
            X.ndirs++;
        } else {
            X.cur = openat(pfd, base, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (X.cur < 0) { fail("%s: %s", path, strerror(errno)); return 0; }
            X.cmode = mode;
            memcpy(X.cts, ts, sizeof ts);
            X.left = size;
            X.nfiles++;
            if (size == 0 && finish_cur() < 0) return 0;
        }
        return 1;
    }
    case R_LINK: {
        rd_int(&r, 4);
        struct timespec ts[2] = { { 0, UTIME_OMIT } };
        ts[1].tv_sec = (time_t)rd_int(&r, 8);
        ts[1].tv_nsec = (long)rd_int(&r, 4);
        if (rd_str(&r, path, &pl) < 0 || rd_str(&r, tgt, &tl) < 0 || r.n || !path_ok(path, pl) ||
            ts[1].tv_nsec >= 1000000000L)
            break;
        if (X.nl == X.cl) {
            X.cl = X.cl ? X.cl * 2 : 64;
            X.links = realloc(X.links, X.cl * sizeof *X.links);
            if (!X.links) { fail("нет памяти"); return 0; }
        }
        X.links[X.nl].path = strdup(path);
        X.links[X.nl].target = strdup(tgt);
        memcpy(X.links[X.nl].ts, ts, sizeof ts);
        X.nl++;
        X.nlinks++;
        return 1;
    }
    case R_END: {
        uint64_t nf = rd_int(&r, 8), nd = rd_int(&r, 8), nl = rd_int(&r, 8), nb = rd_int(&r, 8);
        if (r.bad || r.n) break;
        if (nf != X.nfiles || nd != X.ndirs || nl != X.nlinks || nb != X.nbytes) {
            fail("контрольные счётчики не совпали — архив повреждён");
            return 0;
        }
        X.ended = 1;
        return 1;
    }
    default:
        break;
    }
    fail("запись #%llu: некорректные метаданные", (unsigned long long)s->seq);
    return 0;
}

static void dec_producer(void *arg) {
    FILE *in = arg;
    for (;;) {
        uint8_t lb[4];
        size_t r = fread(lb, 1, 4, in);
        if (r == 0 && feof(in)) break;
        if (r != 4) { fail("архив обрезан"); return; }
        uint32_t plen = get32(lb);
        if (plen == 0 || plen > G.max_plain) { fail("архив повреждён (длина записи)"); return; }
        slot_t *s = acquire();
        if (!s) return;
        if (fread(s->b, 1, (size_t)plen + TAG_LEN, in) != (size_t)plen + TAG_LEN) { fail("архив обрезан"); return; }
        s->blen = plen;
        submit(s);
    }
    if (ferror(in)) fail("чтение архива: %s", strerror(errno));
}

static int finalize_extract(void) {
    if (!X.ended) { fprintf(stderr, "cryptor: архив обрезан (нет маркера конца)\n"); return -1; }
    const char *base;
    for (size_t i = 0; i < X.nl; i++) {
        int pfd = parent_of(X.links[i].path, &base);
        if (pfd < 0 || symlinkat(X.links[i].target, pfd, base) < 0 ||
            utimensat(pfd, base, X.links[i].ts, AT_SYMLINK_NOFOLLOW) < 0) {
            fprintf(stderr, "cryptor: symlink %s: %s\n", X.links[i].path, strerror(errno));
            return -1;
        }
    }
    for (size_t i = X.nd; i-- > 0;) {   /* сначала вложенные, потом родители */
        int fd = open_beneath(X.root, X.dirs[i].path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
        if (fd < 0 || fchmod(fd, X.dirs[i].mode & 07777) || futimens(fd, X.dirs[i].ts)) {
            fprintf(stderr, "cryptor: атрибуты %s: %s\n", X.dirs[i].path, strerror(errno));
            if (fd >= 0) close(fd);
            return -1;
        }
        close(fd);
    }
    return 0;
}

static int cmd_dec(const char *keyfile, int nthreads, const char *arch, const char *outdir) {
    uint8_t key[KEY_LEN], hdr[HDR_LEN];
    if (load_key(keyfile, key) < 0) return 1;
    FILE *in = fopen(arch, "rbe");
    if (!in) { fprintf(stderr, "cryptor: %s: %s\n", arch, strerror(errno)); return 1; }
    setvbuf(in, NULL, _IOFBF, 8u << 20);
    if (fread(hdr, 1, HDR_LEN, in) != HDR_LEN || memcmp(hdr, MAGIC, 8)) {
        fprintf(stderr, "cryptor: %s: не архив cryptor\n", arch);
        return 1;
    }
    G.chunk = get32(hdr + 12);
    if (get32(hdr + 8) != VERSION || G.chunk < MIN_CHUNK || G.chunk > MAX_CHUNK) {
        fprintf(stderr, "cryptor: %s: неподдерживаемая версия/параметры\n", arch);
        return 1;
    }
    int rc = derive_subkey(key, hdr);
    OPENSSL_cleanse(key, sizeof key);
    if (rc < 0) { fprintf(stderr, "cryptor: HKDF\n"); return 1; }

    if (mkdir(outdir, 0700) < 0 && errno != EEXIST) {
        fprintf(stderr, "cryptor: %s: %s\n", outdir, strerror(errno));
        return 1;
    }
    X.root = open(outdir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (X.root < 0) { fprintf(stderr, "cryptor: %s: %s\n", outdir, strerror(errno)); return 1; }

    G.max_plain = 5 + (size_t)G.chunk > META_MAX ? 5 + (size_t)G.chunk : META_MAX;
    if (alloc_slots((unsigned)nthreads * 2 + 4) < 0) { fprintf(stderr, "cryptor: нет памяти\n"); return 1; }

    double t0 = now_sec();
    rc = run_threads(nthreads, dec_producer, in);
    fclose(in);
    OPENSSL_cleanse(G.subkey, sizeof G.subkey);
    if (rc == 0) rc = finalize_extract();
    if (rc < 0) {
        fprintf(stderr, "cryptor: расшифровка прервана; в %s могут остаться частично извлечённые файлы\n", outdir);
        return 1;
    }
    double dt = now_sec() - t0;
    fprintf(stderr, "готово: %llu файлов, %llu директорий, %llu ссылок; %.1f MiB за %.2f c, %.0f MiB/s\n",
            (unsigned long long)X.nfiles, (unsigned long long)X.ndirs, (unsigned long long)X.nlinks,
            X.nbytes / 1048576.0, dt, X.nbytes / 1048576.0 / (dt > 0 ? dt : 1e-9));
    return 0;
}

/* ------------------------------------------------------------------ keygen */

static int cmd_keygen(const char *path) {
    uint8_t key[KEY_LEN];
    if (random_bytes(key, sizeof key) < 0) { perror("getrandom"); return 1; }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { fprintf(stderr, "cryptor: %s: %s\n", path, strerror(errno)); return 1; }
    int rc = write_full(fd, key, sizeof key) || fsync(fd) || close(fd);
    OPENSSL_cleanse(key, sizeof key);
    if (rc) { fprintf(stderr, "cryptor: %s: %s\n", path, strerror(errno)); unlink(path); return 1; }
    fprintf(stderr, "ключ (256 бит) записан в %s — храните его отдельно от архивов\n", path);
    return 0;
}

/* -------------------------------------------------------------------- main */

static void usage(void) {
    fputs("использование:\n"
          "  cryptor keygen <keyfile>\n"
          "  cryptor enc -k <keyfile> [-j потоки] [-l 0..9] [-c чанк_KiB] <директория> <архив>\n"
          "  cryptor dec -k <keyfile> [-j потоки] <архив> <выходная_директория>\n"
          "\n"
          "  -j  число потоков-воркеров (по умолчанию = число ядер)\n"
          "  -l  уровень deflate/gzip (по умолчанию 9 — максимум)\n"
          "  -c  размер чанка в KiB (по умолчанию 1024, 4..65536)\n",
          stderr);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 2; }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "keygen")) {
        if (argc != 3) { usage(); return 2; }
        return cmd_keygen(argv[2]);
    }
    int enc = !strcmp(cmd, "enc");
    if (!enc && strcmp(cmd, "dec")) { usage(); return 2; }

    const char *keyfile = NULL;
    long nthreads = sysconf(_SC_NPROCESSORS_ONLN);
    int opt;
    optind = 1;
    while ((opt = getopt(argc - 1, argv + 1, "k:j:l:c:")) != -1) {
        switch (opt) {
        case 'k': keyfile = optarg; break;
        case 'j': nthreads = atol(optarg); break;
        case 'l': G.level = atoi(optarg); break;
        case 'c': G.chunk = (uint32_t)(atol(optarg) * 1024); break;
        default: usage(); return 2;
        }
    }
    int rest = argc - 1 - optind;
    if (!keyfile || rest != 2 || nthreads < 1 || nthreads > 1024 || G.level < 0 || G.level > 9 ||
        G.chunk < MIN_CHUNK || G.chunk > MAX_CHUNK) {
        usage();
        return 2;
    }
    char *a1 = argv[1 + optind], *a2 = argv[2 + optind];
    G.decrypt = !enc;
    return enc ? cmd_enc(keyfile, (int)nthreads, a1, a2) : cmd_dec(keyfile, (int)nthreads, a1, a2);
}
